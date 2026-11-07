#!/usr/bin/env python3
"""Held, observed T5 anchors and scoped descriptor-relative owned I/O.

No module-level I/O. No private path is opened before both the exact public
anchor input and actual owned diskutil output have been checked. This module
does not run diskutil or claim a volume-wide atomic snapshot.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib, json, os, plistlib, stat, time
from pathlib import Path

MOUNT = Path('/Volumes/T5')
ROOT = MOUNT / 'hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r1'
UUID = 'FB804D1B-24CB-4D6E-AEA7-A9E180807758'
ANCHOR_PATHS = ('/', '/Volumes', '/Volumes/T5')

class VolumeRefused(RuntimeError): pass

def require(value, code):
    if not value: raise VolumeRefused(code)

def identity(info):
    return tuple(str(x) for x in (info.st_dev, info.st_ino, info.st_uid,
        info.st_gid, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns))

def inode_identity(info):
    return identity(info)[:5]

class HeldT5:
    def __init__(self, raw_public, expected_sha256, remaining, critical):
        require(isinstance(raw_public, bytes) and len(raw_public) <= 8192,
                'public_anchor_input_bound')
        require(hashlib.sha256(raw_public).hexdigest() == expected_sha256,
                'public_anchor_whole_sha')
        expected = json.loads(raw_public)
        require(set(expected) == {'schema', 'source_inventory_sha256', 'volumeUUID',
                  'expectedVolumeDevice', 'anchors'}
          and expected['schema'] == 'heptabao.mac-current-t5-public-anchor.r1'
          and expected['volumeUUID'] == UUID, 'public_anchor_schema')
        require([x.get('path') for x in expected['anchors']] == list(ANCHOR_PATHS),
                'exact_public_anchor_paths')
        require(all(set(x) == {'path','identity'} and len(x['identity']) == 9
                    and all(isinstance(v,str) and v.isdecimal() for v in x['identity'])
                    for x in expected['anchors']), 'public_anchor_identity_shape')
        require(isinstance(expected['expectedVolumeDevice'],str)
                and expected['expectedVolumeDevice'].isdecimal()
                and expected['expectedVolumeDevice'] == expected['anchors'][2]['identity'][0],
                'captured_volume_device')
        self.expected, self.remaining, self.critical = expected, remaining, critical
        self.rows, self.anchors = [], []
        self.uuid_verified = False
        self.closed = False
        self.close_errors = []
        self.last_anchor_check = False
        try:
            parent = None
            for index, item in enumerate(expected['anchors']):
                self.remaining()
                name = '/' if index == 0 else Path(item['path']).name
                named = os.lstat('/') if index == 0 else os.stat(
                    name, dir_fd=parent['fd'], follow_symlinks=False)
                require(stat.S_ISDIR(named.st_mode) and identity(named) == tuple(item['identity']),
                        'captured_anchor_named_identity')
                with self.critical():
                    fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                                 **({} if parent is None else {'dir_fd':parent['fd']}))
                    row = {'fd':fd,'name':name,'parent':parent,'expected':tuple(item['identity']),
                           'close_attempted':False,'closed':False,'anchor':True}
                    self.rows.append(row);self.anchors.append(row)
                require(identity(os.fstat(fd)) == row['expected'], 'captured_anchor_fd_identity')
                parent = row
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self, *, check_deadline=True):
        require(not self.closed, 'volume_guard_not_closed')
        if check_deadline: self.remaining()
        self.last_anchor_check = False
        for row in self.anchors:
            named = os.lstat('/') if row['parent'] is None else os.stat(
                row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
            require(identity(named) == identity(os.fstat(row['fd'])) == row['expected'],
                    'held_t5_anchor_changed')
        require(os.fstat(self.anchors[-1]['fd']).st_dev ==
                int(self.expected['expectedVolumeDevice']), 'held_t5_device_changed')
        self.last_anchor_check = True
        if check_deadline: self.remaining()

    def accept_diskutil(self, raw):
        self.check()
        require(isinstance(raw,bytes) and len(raw) <= 262144, 'bounded_actual_diskutil_bytes')
        info = plistlib.loads(raw)
        require(info.get('VolumeUUID') == UUID and info.get('MountPoint') == str(MOUNT),
                'actual_t5_uuid_mount')
        self.uuid_verified = True
        self.check()

    def _admit(self, path):
        self.check()
        require(self.uuid_verified, 'uuid_before_owned_private_io')
        path = Path(path)
        require(path.is_absolute() and path == Path(os.path.normpath(str(path)))
                and path.is_relative_to(ROOT), 'fixed_owned_t5_scope')
        return path

    def _close_row(self, row):
        if row['close_attempted']: return
        with self.critical():
            row['close_attempted'] = True
            try:
                os.close(row['fd']);row['closed'] = True
            except BaseException as error:
                self.close_errors.append(type(error).__name__)
                raise

    @contextmanager
    def parent(self, path):
        path = self._admit(path)
        parts = path.relative_to(MOUNT).parts
        require(parts and all(part not in ('','.', '..') for part in parts),
                'owned_component_shape')
        previous = self.anchors[-1]
        borrowed = []
        try:
            for component in parts[:-1]:
                self.remaining()
                named = os.stat(component,dir_fd=previous['fd'],follow_symlinks=False)
                require(stat.S_ISDIR(named.st_mode) and named.st_uid == 501
                        and named.st_dev == int(self.expected['expectedVolumeDevice'])
                        and stat.S_IMODE(named.st_mode)&0o022 == 0, 'owned_parent_custody')
                with self.critical():
                    fd = os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                                 dir_fd=previous['fd'])
                    row = {'fd':fd,'name':component,'parent':previous,
                           'expected_inode':inode_identity(named),
                           'close_attempted':False,'closed':False,'anchor':False}
                    self.rows.append(row);borrowed.append(row)
                require(inode_identity(os.fstat(fd)) == row['expected_inode'],
                        'owned_parent_fd_identity')
                previous = row
            self.check()
            yield previous['fd'], parts[-1]
            for row in borrowed:
                named = os.stat(row['name'],dir_fd=row['parent']['fd'],follow_symlinks=False)
                require(inode_identity(named) == inode_identity(os.fstat(row['fd']))
                        == row['expected_inode'], 'owned_parent_changed')
            self.check()
        finally:
            errors = []
            for row in reversed(borrowed):
                try:self._close_row(row)
                except BaseException as error:errors.append(type(error).__name__)
            if errors: raise VolumeRefused('owned_parent_close_failed')

    def read(self, path, maximum=2*1024*1024, *, private=True):
        require(type(maximum) is int and 0 < maximum <= 16*1024*1024, 'bounded_owned_read')
        with self.parent(path) as (parent, name):
            with self.critical():
                fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                row = {'fd':fd,'close_attempted':False,'closed':False,'anchor':False}
                self.rows.append(row)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501
                        and before.st_nlink == 1 and before.st_dev == int(self.expected['expectedVolumeDevice'])
                        and 0 <= before.st_size <= maximum
                        and (stat.S_IMODE(before.st_mode) == 0o600 if private else
                             stat.S_IMODE(before.st_mode)&0o022 == 0), 'owned_file_custody')
                raw = bytearray()
                while len(raw) <= maximum:
                    self.remaining()
                    block = os.read(fd,min(65536,maximum+1-len(raw)))
                    if not block:break
                    raw.extend(block)
                named = os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(len(raw) == before.st_size and identity(before) ==
                        identity(os.fstat(fd)) == identity(named), 'owned_file_stable_read')
                self.check()
                return bytes(raw)
            finally:self._close_row(row)

    def write_new(self, path, raw):
        require(isinstance(raw,bytes) and len(raw) <= 16*1024*1024, 'bounded_owned_write')
        with self.parent(path) as (parent, name):
            with self.critical():
                fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                             0o600,dir_fd=parent)
                row = {'fd':fd,'close_attempted':False,'closed':False,'anchor':False}
                self.rows.append(row)
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == 501
                        and before.st_nlink == 1 and before.st_dev == int(self.expected['expectedVolumeDevice']),
                        'new_owned_file_inode')
                offset=0
                while offset<len(raw):
                    self.remaining()
                    n=os.write(fd,raw[offset:offset+65536])
                    require(n>0,'new_owned_write_progress');offset+=n
                os.fchmod(fd,0o600);os.fsync(fd);os.fsync(parent)
                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(identity(after)==identity(named) and after.st_size==len(raw)
                        and inode_identity(before)==inode_identity(after), 'new_owned_file_name')
                self.check()
                return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                        'identity':list(identity(after))}
            finally:self._close_row(row)

    @contextmanager
    def capture_sink(self, path, maximum=2*1024*1024):
        require(type(maximum) is int and 0<maximum<=2*1024*1024,'bounded_capture_sink')
        with self.parent(path) as (parent,name):
            with self.critical():
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                           0o600,dir_fd=parent)
                row={'fd':fd,'close_attempted':False,'closed':False,'anchor':False}
                self.rows.append(row)
                stream=os.fdopen(fd,'wb',buffering=0,closefd=False)
            before=os.fstat(fd)
            try:
                require(stat.S_ISREG(before.st_mode) and before.st_uid==501
                        and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
                        and before.st_dev==int(self.expected['expectedVolumeDevice']),
                        'capture_sink_custody')
                yield stream
                os.fsync(fd);os.fsync(parent)
                after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                require(after.st_size<=maximum and identity(after)==identity(named)
                        and inode_identity(before)==inode_identity(after),'capture_sink_stable')
                self.check()
            finally:
                with self.critical():
                    try:stream.close()
                    finally:self._close_row(row)

    def mkdir_new(self, path):
        with self.parent(path) as (parent,name):
            self.remaining()
            os.mkdir(name,mode=0o700,dir_fd=parent)
            info=os.stat(name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==501
                    and stat.S_IMODE(info.st_mode)==0o700
                    and info.st_dev==int(self.expected['expectedVolumeDevice']),'new_owned_directory')
            os.fsync(parent);self.check()
            return list(identity(info))

    def public_state(self):
        return {'schema':'heptabao.held-t5-volume-state.r1',
                'volumeUUIDVerified':self.uuid_verified,
                'expectedVolumeDevice':self.expected['expectedVolumeDevice'],
                'anchors':self.expected['anchors'],'lastAnchorCheckPassed':self.last_anchor_check,
                'allDescriptorsClosed':all(x['closed'] for x in self.rows),
                'closeErrors':list(self.close_errors)}

    def close(self):
        if self.closed:return
        try:self.check(check_deadline=False)
        except BaseException:
            self.last_anchor_check=False
        for row in reversed(self.rows):
            try:self._close_row(row)
            except BaseException:pass
        self.closed=True
