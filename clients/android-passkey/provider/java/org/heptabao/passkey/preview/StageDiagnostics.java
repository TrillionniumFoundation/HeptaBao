package org.heptabao.passkey.preview;

import android.os.OperationCanceledException;
import android.system.ErrnoException;
import android.system.OsConstants;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.heptabao.passkey.core.Failure;

/**
 * Closed diagnostic codes for the ciphertext-staging boundary only.
 *
 * The table is tied to these exact source bytes. A missing line number, an
 * unknown method, or any unmapped first application frame yields UNKNOWN;
 * it never falls through to a less specific caller and guesses a location.
 * No message, URI, path, arbitrary class name, or stack trace is returned.
 * Existing Failure instances retain their identity and code.
 */
final class StageDiagnostics {
    static final String VAULT_SOURCE_SHA256 = "2b21338fe7086ac034f04441b521ddf11ed9d071e0c6aa4e64b34cd0dd7fcbc9";
    static final String DOCUMENT_SOURCE_SHA256 = "8a08b26986febb451a0416559ce43949e537e1649cd6d536754c45fddb49fa2f";
    private static final String PREFIX = "org.heptabao.passkey.";
    private static final String VAULT = PREFIX + "preview.VaultFiles";
    private static final String GUARD = VAULT + "$Guard";
    private static final String DOCUMENT = PREFIX + "preview.DocumentIO";

    private enum Site {
        UNKNOWN, SAF_PROVIDER_RESOLVE, SAF_OPEN, SAF_OPEN_CLEANUP,
        STORAGE_MKDIR, STORAGE_DIRECTORY_STAT,
        FILES_LSTAT, FILES_OPEN, FILES_FSTAT_BEFORE, FILES_CHMOD,
        FILES_FSTAT_AFTER, FILES_FSYNC, FILES_LSTAT_AFTER, FILES_CLOSE,
        LOCAL_READ_OPEN, LOCAL_READ_RESOURCE, LOCAL_READ_FSTAT_BEFORE,
        LOCAL_READ_BYTES, LOCAL_READ_FSTAT_AFTER,
        DIRECTORY_OPEN, DIRECTORY_FSTAT, DIRECTORY_FSYNC, DIRECTORY_CLOSE,
        PUBLISH_TEMP_OPEN, PUBLISH_TEMP_RESOURCE, PUBLISH_WRITE_SYNC,
        PUBLISH_LINK, PUBLISH_RENAME, PUBLISH_TEMP_CLEANUP,
        LOCK_OPEN, LOCK_STREAM_SETUP, LOCK_FSTAT, LOCK_TRY,
        LOCK_CONSTRUCTION_CLEANUP, LOCK_RELEASE_CLOSE,
        SAF_RESOURCE_SETUP_CLOSE, SAF_FSTAT, SAF_READ, SAF_RESOURCE_CLOSE_RELEASE
    }
    private enum Kind { ERRNO, FILE_NOT_FOUND, CANCELLED, IO, SECURITY, ARGUMENT, STATE, OTHER }
    private enum Errno { NONE, EPERM, EACCES, ENOENT, ENOSPC, EIO, EBADF, EINVAL, EMFILE,
                         ENFILE, EOPNOTSUPP, EROFS, EINTR, ECANCELED, OTHER }
    private static final class Binding {
        final String owner, method;
        final int line;
        final Site site;
        Binding(String owner, String method, int line, Site site) {
            this.owner = owner; this.method = method; this.line = line; this.site = site;
        }
    }
    private static Binding bind(String owner, String method, int line, Site site) {
        return new Binding(owner, method, line, site);
    }
    // Each trailing fragment is checked against the frozen source by the host
    // mapping audit. Multi-operation source lines deliberately use group names.
    private static final Binding[] SITES = {
        bind(DOCUMENT, "open", 54, Site.SAF_PROVIDER_RESOLVE), // resolveContentProvider
        bind(DOCUMENT, "open", 58, Site.SAF_OPEN), // openFileDescriptor
        bind(DOCUMENT, "open", 62, Site.SAF_OPEN_CLEANUP), // opened.close()
        bind(VAULT, "directory", 38, Site.STORAGE_MKDIR), // Os.mkdir
        bind(VAULT, "directory", 41, Site.STORAGE_DIRECTORY_STAT), // Os.lstat
        bind(VAULT, "privateFiles", 48, Site.FILES_LSTAT), // Os.lstat
        bind(VAULT, "privateFiles", 55, Site.FILES_OPEN), // Os.open
        bind(VAULT, "privateFiles", 56, Site.FILES_OPEN), // OsConstants.O_NOFOLLOW
        bind(VAULT, "privateFiles", 58, Site.FILES_FSTAT_BEFORE), // Os.fstat
        bind(VAULT, "privateFiles", 66, Site.FILES_CHMOD), // Os.fchmod
        bind(VAULT, "privateFiles", 67, Site.FILES_FSTAT_AFTER), // Os.fstat
        bind(VAULT, "privateFiles", 71, Site.FILES_FSYNC), // Os.fsync
        bind(VAULT, "privateFiles", 72, Site.FILES_LSTAT_AFTER), // Os.lstat
        bind(VAULT, "privateFiles", 77, Site.FILES_CLOSE), // Os.close
        bind(VAULT, "read", 85, Site.LOCAL_READ_OPEN), // Os.open
        bind(VAULT, "read", 86, Site.LOCAL_READ_RESOURCE), // new FileInputStream
        bind(VAULT, "read", 87, Site.LOCAL_READ_FSTAT_BEFORE), // Os.fstat
        bind(VAULT, "read", 90, Site.LOCAL_READ_BYTES), // stream.read
        bind(VAULT, "read", 93, Site.LOCAL_READ_FSTAT_AFTER), // Os.fstat
        bind(VAULT, "syncDirectory", 104, Site.DIRECTORY_OPEN), // Os.open
        bind(VAULT, "syncDirectory", 106, Site.DIRECTORY_FSTAT), // Os.fstat
        bind(VAULT, "syncDirectory", 108, Site.DIRECTORY_FSYNC), // Os.fsync
        bind(VAULT, "syncDirectory", 109, Site.DIRECTORY_CLOSE), // Os.close
        bind(VAULT, "publish", 119, Site.PUBLISH_TEMP_OPEN), // Os.open
        bind(VAULT, "publish", 120, Site.PUBLISH_TEMP_OPEN), // OsConstants.O_NOFOLLOW
        bind(VAULT, "publish", 121, Site.PUBLISH_TEMP_RESOURCE), // new FileOutputStream
        bind(VAULT, "publish", 122, Site.PUBLISH_WRITE_SYNC), // Os.fchmod(fd, 0600); regular(Os.fstat(fd), limit); output.write(value); output.flush(); Os.fsync(fd)
        bind(VAULT, "publish", 127, Site.PUBLISH_LINK), // Os.link
        bind(VAULT, "publish", 129, Site.PUBLISH_RENAME), // Os.rename
        bind(VAULT, "publish", 136, Site.PUBLISH_TEMP_CLEANUP), // Os.remove
        bind(GUARD, "<init>", 146, Site.LOCK_OPEN), // Os.open
        bind(GUARD, "<init>", 147, Site.LOCK_OPEN), // OsConstants.O_NOFOLLOW
        bind(GUARD, "<init>", 148, Site.LOCK_STREAM_SETUP), // new FileOutputStream
        bind(GUARD, "<init>", 150, Site.LOCK_FSTAT), // Os.fstat
        bind(GUARD, "<init>", 151, Site.LOCK_TRY), // opened.getChannel().tryLock()
        bind(GUARD, "<init>", 154, Site.LOCK_CONSTRUCTION_CLEANUP), // acquired.release(); opened.close()
        bind(GUARD, "close", 160, Site.LOCK_RELEASE_CLOSE), // lock.release(); } finally { stream.close()
        bind(VAULT, "readContent", 253, Site.SAF_RESOURCE_SETUP_CLOSE), // new ParcelFileDescriptor.AutoCloseInputStream
        bind(VAULT, "readContent", 254, Site.SAF_FSTAT), // Os.fstat
        bind(VAULT, "readContent", 258, Site.SAF_READ), // input.read(block)
        bind(VAULT, "readContent", 262, Site.SAF_RESOURCE_CLOSE_RELEASE), // operation.released(descriptor)
    };

    static Failure failure(Exception error) {
        if (error instanceof Failure) return (Failure)error;
        return new Failure("stage_failed:" + site(error).name() + ":" + kind(error).name() + ":" + errno(error).name());
    }
    private static Site site(Exception error) {
        if (error == null) return Site.UNKNOWN;
        StackTraceElement[] frames = error.getStackTrace();
        for (int i = 0; i < Math.min(frames.length, 16); i++) {
            StackTraceElement frame = frames[i];
            if (!frame.getClassName().startsWith(PREFIX)) continue;
            for (Binding binding : SITES) {
                if (frame.getClassName().equals(binding.owner) && frame.getMethodName().equals(binding.method)
                        && frame.getLineNumber() == binding.line) return binding.site;
            }
            return Site.UNKNOWN;
        }
        return Site.UNKNOWN;
    }
    private static Kind kind(Exception error) {
        if (error instanceof ErrnoException) return Kind.ERRNO;
        if (error instanceof FileNotFoundException) return Kind.FILE_NOT_FOUND;
        if (error instanceof OperationCanceledException) return Kind.CANCELLED;
        if (error instanceof IOException) return Kind.IO;
        if (error instanceof SecurityException) return Kind.SECURITY;
        if (error instanceof IllegalArgumentException) return Kind.ARGUMENT;
        if (error instanceof IllegalStateException) return Kind.STATE;
        return Kind.OTHER;
    }
    private static Errno errno(Exception error) {
        Throwable current = error;
        for (int depth = 0; depth < 3 && current != null; depth++) {
            if (current instanceof ErrnoException) return errnoCode(((ErrnoException)current).errno);
            Throwable next = current.getCause();
            if (next == current) break;
            current = next;
        }
        return Errno.NONE;
    }
    private static Errno errnoCode(int value) {
        if (value == OsConstants.EPERM) return Errno.EPERM;
        if (value == OsConstants.EACCES) return Errno.EACCES;
        if (value == OsConstants.ENOENT) return Errno.ENOENT;
        if (value == OsConstants.ENOSPC) return Errno.ENOSPC;
        if (value == OsConstants.EIO) return Errno.EIO;
        if (value == OsConstants.EBADF) return Errno.EBADF;
        if (value == OsConstants.EINVAL) return Errno.EINVAL;
        if (value == OsConstants.EMFILE) return Errno.EMFILE;
        if (value == OsConstants.ENFILE) return Errno.ENFILE;
        if (value == OsConstants.EOPNOTSUPP) return Errno.EOPNOTSUPP;
        if (value == OsConstants.EROFS) return Errno.EROFS;
        if (value == OsConstants.EINTR) return Errno.EINTR;
        if (value == OsConstants.ECANCELED) return Errno.ECANCELED;
        return Errno.OTHER;
    }
    private StageDiagnostics() {}
}
