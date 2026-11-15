def main():
    global CONTROL_SIGNALS
    os.umask(0o077)
    sys.dont_write_bytecode = True
    guard = operations = commands = signals = inspector = None
    try:
        need(sys.platform == 'darwin' and os.getuid() == 501 and os.getgid() == 20
             and Path(sys.executable).resolve(strict=True) == PYTHON, 'metadata_exact_mac_runtime')
        for name, source in PAYLOAD['sources'].items():
            raw = source.encode()
            need(len(raw) == PAYLOAD['pins'][name]['bytes'] and hashlib.sha256(raw).hexdigest()
                 == PAYLOAD['pins'][name]['sha256'], 'metadata_complete_source_pin')
            module = types.ModuleType(Path(name).stem); module.__file__ = str(OPERATIONS / name)
            sys.modules[module.__name__] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        from mac_owned_commands_r1 import Commands, Signals
        from mac_production_t5_guard_r1 import HeldT5
        from mac_public_code_pin_excerpt_r1 import public_code_pin
        from complete_cold_tree_backup_r1 import CompleteColdCopy
        import fcntl
        signals = Signals(); signals.install(); commands = Commands(signals); CONTROL_SIGNALS = signals
        pins = {}
        for path, expected in TOOL_PINS.items():
            pin = public_code_pin(path, remaining=remaining, critical=signals.critical)
            need((pin['bytes'], pin['sha256']) == expected, 'metadata_exact_native_tool')
            pins[path] = pin
        anchor = {'schema': 'heptabao.mac-current-t5-public-anchor.r1',
            'source_inventory_sha256': hashlib.sha256(encoded(PAYLOAD['pins'])).hexdigest(),
            'volumeUUID': 'FB804D1B-24CB-4D6E-AEA7-A9E180807758',
            'expectedVolumeDevice': str(Path('/Volumes/T5').lstat().st_dev),
            'anchors': [{'path': path, 'identity': list(full9(Path(path).lstat()))} for path in ('/', '/Volumes', '/Volumes/T5')]}
        raw = encoded(anchor); guard = HeldT5(raw, hashlib.sha256(raw).hexdigest(), remaining, signals.critical)
        row, out, err = commands.run('backup-metadata-t5-volume', ['/usr/sbin/diskutil', 'info', '-plist', '/Volumes/T5'],
            until=min(UNTIL, time.monotonic() + 10), maximum=262144)
        need(row['exitCode'] == 0 and not row['outcomeUnknown'] and not err, 'metadata_known_t5_volume')
        guard.accept_diskutil(out)
        operations = PrivateOperations()
        def check():
            remaining(); guard.check(); operations.check()
        # Destination is an unused constructor binding. This program never
        # invokes run/copy_file/create_directory or creates the backup path.
        future = CALLER_HOME / 'heptabao-authbus-production-backups' / 'uncreated-metadata-only'
        need(not future.exists() and not future.is_symlink(), 'unused_backup_destination_absent')
        inspector = CompleteColdCopy(ROOT / 'data', future, check=check, critical=signals.critical)
        inspector.used = True
        source = inspector.open_chain(ROOT / 'data')
        need(inspector.private_directory(os.fstat(source['fd'])), 'metadata_private_permanent_data_root')
        with signals.critical():
            fcntl.flock(source['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB)
            inspector.lock_fd = source
        inspector.scan('', source); inspector.source_unchanged()
        packet = {'schema': 'heptabao.permanent-encrypted-tree-metadata.private.r1',
            'directories': {path: stamp for path, (_, stamp) in inspector.source_dirs.items()},
            'files': inspector.entries, 'directoryChildren': inspector.children,
            'fileContentsRead': 0, 'sourceDirectoryLockHeld': True}
        operations.write('metadata.private.json', encoded(packet))
        inspector.source_unchanged()
        REPORT.update(ok=True, directories=len(inspector.source_dirs), files=len(inspector.entries),
            totalCipherFileBytes=inspector.total,
            largestCipherFileBytes=max((row['bytes'] for row in inspector.entries.values()), default=0),
            observedFileModes=sorted({format(row['mode'], '04o') for row in inspector.entries.values()}),
            directoryNonblockingLockAcquired=True, allSourceMetadataUnchanged=True,
            sourcePathsOrStateDigestsPublished=False, rustWriterLockInteroperabilityQualified=False,
            backupDestinationCreated=False)
        for path, expected in pins.items():
            need(public_code_pin(path, remaining=remaining, critical=signals.critical) == expected,
                 'metadata_native_tools_unchanged')
    except BaseException as error:
        REPORT['errorType'] = type(error).__name__
        REPORT['errorCode'] = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9._-]{1,120}', str(error)) else 'metadata_observation_refused'
    finally:
        inspector_errors = []
        if inspector is not None:
            for row in reversed(inspector.fds):
                try:
                    inspector.close(row)
                except BaseException:
                    inspector_errors.append('inspector_descriptor_close_failed')
            REPORT['inspectorDescriptors'] = len(inspector.fds)
            REPORT['allInspectorDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in inspector.fds)
            REPORT['originalDirectoryLockReleased'] = inspector.lock_fd is None or inspector.lock_fd['closed']
        else:
            REPORT.update(inspectorDescriptors=0, allInspectorDescriptorsClosedOnce=True, originalDirectoryLockReleased=True)
        if guard is not None:
            guard.close(); REPORT['volumeClosure'] = guard.public_state()
        errors = []
        for row in reversed(FDS):
            try:
                close(row)
            except BaseException:
                errors.append('outer_descriptor_close_failed')
        REPORT['descriptorCloseErrors'] = errors + inspector_errors
        REPORT['explicitDescriptors'] = len(FDS)
        REPORT['allExplicitDescriptorsClosedOnce'] = all(row['attempts'] == 1 and row['closed'] for row in FDS)
        REPORT['commands'] = commands.public() if commands is not None else {'allOwnedCommandsStopped': True, 'unknownCommandCount': 0, 'commands': []}
        REPORT['deadlineAfterClosure'] = time.monotonic() < UNTIL
        REPORT['cancellationObserved'] = CONTROL_SIGNALS is not None and CONTROL_SIGNALS.pending is not None
        REPORT['ok'] = bool(REPORT['ok'] and not errors and not inspector_errors
            and REPORT['allExplicitDescriptorsClosedOnce'] and REPORT['allInspectorDescriptorsClosedOnce']
            and REPORT['originalDirectoryLockReleased'] and REPORT['commands']['allOwnedCommandsStopped']
            and REPORT['commands']['unknownCommandCount'] == 0 and REPORT['deadlineAfterClosure']
            and not REPORT['cancellationObserved'] and REPORT.get('volumeClosure', {}).get('lastAnchorCheckPassed')
            and REPORT['volumeClosure']['allDescriptorsClosed'])
        REPORT['elapsedSeconds'] = time.monotonic() - START
        print(json.dumps(REPORT, sort_keys=True), flush=True)
    return 0 if REPORT['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
