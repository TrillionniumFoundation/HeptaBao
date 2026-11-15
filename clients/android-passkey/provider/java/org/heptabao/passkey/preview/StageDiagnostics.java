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
    static final String VAULT_SOURCE_SHA256 = "f19b24a8091bac11c92354922d5fe0db1d2d2d59d1afbc511387f2a9d19c2012";
    static final String DOCUMENT_SOURCE_SHA256 = "8a08b26986febb451a0416559ce43949e537e1649cd6d536754c45fddb49fa2f";
    private static final String PREFIX = "org.heptabao.passkey.";
    private static final String VAULT = PREFIX + "preview.VaultFiles";
    private static final String GUARD = VAULT + "$Guard";
    private static final String DESCRIPTOR = VAULT + "$Descriptor";
    private static final String DOCUMENT = PREFIX + "preview.DocumentIO";

    private enum Site {
        UNKNOWN, SAF_PROVIDER_RESOLVE, SAF_OPEN, SAF_OPEN_CLEANUP,
        RAW_CLOSE, RESOURCE_CLOSE, STORAGE_MKDIR, STORAGE_DIRECTORY_STAT,
        FILES_LSTAT, FILES_OPEN, FILES_FSTAT_BEFORE, FILES_CHMOD,
        FILES_FSTAT_AFTER, FILES_FSYNC, FILES_LSTAT_AFTER,
        LOCAL_READ_OPEN, LOCAL_READ_FSTAT_BEFORE, LOCAL_READ_BYTES, LOCAL_READ_FSTAT_AFTER,
        DIRECTORY_OPEN, DIRECTORY_FSTAT, DIRECTORY_FSYNC,
        PUBLISH_TEMP_OPEN, PUBLISH_CHMOD_STAT, PUBLISH_WRITE, PUBLISH_FSYNC,
        PUBLISH_RENAME, PUBLISH_TEMP_CLEANUP,
        LOCK_OPEN, LOCK_FSTAT, LOCK_DUP, LOCK_STREAM_SETUP, LOCK_TRY,
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
        bind(DESCRIPTOR, "close", 40, Site.RAW_CLOSE), // Os.close
        bind(VAULT, "closeKeeping", 46, Site.RESOURCE_CLOSE), // resource.close()
        bind(VAULT, "directory", 65, Site.STORAGE_MKDIR), // Os.mkdir
        bind(VAULT, "directory", 68, Site.STORAGE_DIRECTORY_STAT), // Os.lstat
        bind(VAULT, "privateFiles", 75, Site.FILES_LSTAT), // Os.lstat
        bind(VAULT, "privateFiles", 82, Site.FILES_OPEN), // Os.open
        bind(VAULT, "privateFiles", 83, Site.FILES_OPEN), // OsConstants.O_NOFOLLOW
        bind(VAULT, "privateFiles", 85, Site.FILES_FSTAT_BEFORE), // Os.fstat
        bind(VAULT, "privateFiles", 93, Site.FILES_CHMOD), // Os.fchmod
        bind(VAULT, "privateFiles", 94, Site.FILES_FSTAT_AFTER), // Os.fstat
        bind(VAULT, "privateFiles", 98, Site.FILES_FSYNC), // Os.fsync
        bind(VAULT, "privateFiles", 99, Site.FILES_LSTAT_AFTER), // Os.lstat
        bind(VAULT, "read", 112, Site.LOCAL_READ_OPEN), // Os.open
        bind(VAULT, "read", 114, Site.LOCAL_READ_FSTAT_BEFORE), // Os.fstat
        bind(VAULT, "read", 117, Site.LOCAL_READ_BYTES), // Os.read
        bind(VAULT, "read", 121, Site.LOCAL_READ_FSTAT_AFTER), // Os.fstat
        bind(VAULT, "syncDirectory", 132, Site.DIRECTORY_OPEN), // Os.open
        bind(VAULT, "syncDirectory", 134, Site.DIRECTORY_FSTAT), // Os.fstat
        bind(VAULT, "syncDirectory", 136, Site.DIRECTORY_FSYNC), // Os.fsync
        bind(VAULT, "publish", 150, Site.PUBLISH_TEMP_OPEN), // Os.open
        bind(VAULT, "publish", 151, Site.PUBLISH_TEMP_OPEN), // OsConstants.O_NOFOLLOW
        bind(VAULT, "publish", 154, Site.PUBLISH_CHMOD_STAT), // Os.fchmod(fd, 0600); regular(Os.fstat(fd), limit)
        bind(VAULT, "publish", 156, Site.PUBLISH_WRITE), // Os.write
        bind(VAULT, "publish", 160, Site.PUBLISH_FSYNC), // Os.fsync
        bind(VAULT, "publish", 169, Site.PUBLISH_RENAME), // Os.rename
        bind(VAULT, "publish", 178, Site.PUBLISH_TEMP_CLEANUP), // Os.remove
        bind(GUARD, "<init>", 207, Site.LOCK_OPEN), // Os.open
        bind(GUARD, "<init>", 208, Site.LOCK_OPEN), // OsConstants.O_NOFOLLOW
        bind(GUARD, "<init>", 210, Site.LOCK_FSTAT), // Os.fstat
        bind(GUARD, "<init>", 211, Site.LOCK_DUP), // ParcelFileDescriptor.dup
        bind(GUARD, "<init>", 213, Site.LOCK_STREAM_SETUP), // new ParcelFileDescriptor.AutoCloseOutputStream
        bind(GUARD, "<init>", 214, Site.LOCK_TRY), // opened.getChannel().tryLock()
        bind(VAULT, "readContent", 342, Site.SAF_RESOURCE_SETUP_CLOSE), // new ParcelFileDescriptor.AutoCloseInputStream
        bind(VAULT, "readContent", 343, Site.SAF_FSTAT), // Os.fstat
        bind(VAULT, "readContent", 347, Site.SAF_READ), // input.read(block)
        bind(VAULT, "readContent", 351, Site.SAF_RESOURCE_CLOSE_RELEASE), // operation.released(descriptor)
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
