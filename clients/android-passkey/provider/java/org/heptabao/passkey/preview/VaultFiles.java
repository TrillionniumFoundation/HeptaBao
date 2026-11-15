package org.heptabao.passkey.preview;

import android.content.Context;
import android.os.Process;
import android.os.ParcelFileDescriptor;
import android.net.Uri;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.heptabao.passkey.core.Codec;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Hbv;
import org.heptabao.passkey.core.Json;
import org.heptabao.passkey.core.Passkey;

/** Android sandbox storage. One cooperative process lock, descriptor checks and ciphertext CAS. */
final class VaultFiles {
    private static final AtomicReference<Object> ADMISSION = new AtomicReference<>();

    /** Sole owner of one Os.open descriptor; close is attempted once only. */
    private static final class Descriptor implements AutoCloseable {
        final FileDescriptor fd;
        private boolean closed;
        boolean closeFailed;
        Descriptor(FileDescriptor fd) { this.fd = fd; }
        @Override public void close() throws Exception {
            if (closed) return;
            closed = true;
            try { Os.close(fd); }
            catch (Exception error) { closeFailed = true; throw error; }
        }
    }
    private static Exception closeKeeping(Exception primary, AutoCloseable resource) {
        if (resource == null) return primary;
        try { resource.close(); }
        catch (Exception error) {
            if (primary == null) return error;
            if (primary != error) primary.addSuppressed(error);
        }
        return primary;
    }
    private static Failure unknown(Exception error) {
        Failure failure = new Failure("save_outcome_unknown");
        failure.addSuppressed(error);
        return failure;
    }
    static final class Loaded {
        final String store;
        final List<Session.Entry> labels;
        Loaded(String store, List<Session.Entry> labels) { this.store = store; this.labels = labels; }
    }
    private static void directory(File path, boolean create) throws Exception {
        if (create) {
            try { Os.mkdir(path.getPath(), 0700); }
            catch (ErrnoException error) { if (error.errno != OsConstants.EEXIST) throw error; }
        }
        StructStat stat = Os.lstat(path.getPath());
        Failure.require(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid()
            && (stat.st_mode & 0777) == 0700, "unsafe_directory");
    }
    private static File privateFiles(Context context) throws Exception {
        File files = context.getFilesDir();
        Failure.require(files.equals(new File(context.getDataDir(), "files")), "unsafe_directory");
        StructStat leaf = Os.lstat(files.getPath());
        int leafMode = leaf.st_mode & 07777;
        Failure.require(OsConstants.S_ISDIR(leaf.st_mode) && leaf.st_uid == Process.myUid()
            && (leafMode == 0700 || leafMode == 0771), "unsafe_directory");
        // O_DIRECTORY is not a public SDK 34 constant. Refuse symlinks, make
        // special-file opens nonblocking, and verify the opened inode is the
        // already-checked directory before any permission mutation.
        try (Descriptor owner = new Descriptor(Os.open(files.getPath(), OsConstants.O_RDONLY | OsConstants.O_NONBLOCK
                | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0))) {
            FileDescriptor fd = owner.fd;
            StructStat before = Os.fstat(fd);
            int mode = before.st_mode & 07777;
            // Android ContextImpl creates its own files directory with 0771.
            // Narrow only that fixed app-owned directory, through its verified
            // descriptor, before storing anything. All later checks stay 0700.
            Failure.require(OsConstants.S_ISDIR(before.st_mode) && before.st_uid == Process.myUid()
                && (mode == 0700 || mode == 0771) && before.st_dev == leaf.st_dev
                && before.st_ino == leaf.st_ino, "unsafe_directory");
            if (mode == 0771) Os.fchmod(fd, 0700);
            StructStat after = Os.fstat(fd);
            Failure.require(OsConstants.S_ISDIR(after.st_mode) && after.st_uid == Process.myUid()
                && (after.st_mode & 07777) == 0700 && before.st_dev == after.st_dev
                && before.st_ino == after.st_ino, "unsafe_directory");
            Os.fsync(fd);
            StructStat named = Os.lstat(files.getPath());
            Failure.require(OsConstants.S_ISDIR(named.st_mode) && named.st_uid == Process.myUid()
                && (named.st_mode & 07777) == 0700 && named.st_dev == after.st_dev
                && named.st_ino == after.st_ino, "unsafe_directory");
            return files;
        }
    }
    private static void regular(StructStat stat, int limit) throws Failure {
        Failure.require(OsConstants.S_ISREG(stat.st_mode) && stat.st_uid == Process.myUid()
            && (stat.st_mode & 0777) == 0600 && stat.st_nlink == 1
            && stat.st_size >= 0 && stat.st_size <= limit, "unsafe_file");
    }
    private static byte[] read(File path, int limit) throws Exception {
        try (Descriptor owner = new Descriptor(Os.open(path.getPath(), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0))) {
            FileDescriptor fd = owner.fd;
            StructStat before = Os.fstat(fd); regular(before, limit);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int)before.st_size);
            byte[] buffer = new byte[8192]; int count;
            while ((count = Os.read(fd, buffer, 0, buffer.length)) != 0) {
                Failure.require(count > 0 && count <= buffer.length, "read_incomplete");
                Failure.require(bytes.size() + count <= limit, "input_limit"); bytes.write(buffer, 0, count);
            }
            StructStat after = Os.fstat(fd); regular(after, limit);
            Failure.require(before.st_size == after.st_size && bytes.size() == before.st_size
                && before.st_mtime == after.st_mtime && before.st_ctime == after.st_ctime, "concurrent_change");
            return bytes.toByteArray();
        }
    }
    private static byte[] maybeRead(File path, int limit) throws Exception {
        try { return read(path, limit); }
        catch (ErrnoException error) { if (error.errno == OsConstants.ENOENT) return null; throw error; }
    }
    private static void syncDirectory(File path) throws Exception {
        try (Descriptor owner = new Descriptor(Os.open(path.getPath(), OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0))) {
            FileDescriptor fd = owner.fd;
            StructStat stat = Os.fstat(fd);
            Failure.require(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() && (stat.st_mode & 0777) == 0700, "unsafe_directory");
            Os.fsync(fd);
        }
    }
    private static void publish(Guard guard, File target, byte[] value, byte[] expectedHash, int limit) throws Exception {
        guard.requireHeld();
        Failure.require(value.length <= limit, "input_limit");
        File parent = target.getParentFile(); directory(parent, false);
        byte[] prior = maybeRead(target, limit);
        Failure.require(expectedHash == null ? prior == null : prior != null && MessageDigest.isEqual(expectedHash, Codec.sha(prior)), "conflict");
        File temporary = new File(parent, ".pending-" + Codec.hex(Codec.random(16)));
        boolean visible = false;
        boolean temporaryOwned = false;
        Exception failure = null;
        try {
            try (Descriptor owner = new Descriptor(Os.open(temporary.getPath(), OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL
                    | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0600))) {
                temporaryOwned = true;
                FileDescriptor fd = owner.fd;
                Os.fchmod(fd, 0600); regular(Os.fstat(fd), limit);
                for (int offset = 0; offset < value.length;) {
                    int count = Os.write(fd, value, offset, value.length - offset);
                    Failure.require(count > 0 && count <= value.length - offset, "write_incomplete");
                    offset += count;
                }
                Os.fsync(fd);
            }
            guard.requireHeld();
            byte[] current = maybeRead(target, limit);
            Failure.require(expectedHash == null ? current == null : current != null && MessageDigest.isEqual(expectedHash, Codec.sha(current)), "conflict");
            // The same Guard covers both CAS checks and rename. Android denies
            // app hard links. This is a cooperating-writer protocol, not a
            // kernel NOREPLACE guarantee against unrelated same-UID writers.
            guard.requireHeld();
            Os.rename(temporary.getPath(), target.getPath());
            visible = true; temporaryOwned = false; guard.published = true;
            syncDirectory(parent);
            Failure.require(MessageDigest.isEqual(Codec.sha(value), Codec.sha(read(target, limit))), "save_outcome_unknown");
        } catch (Exception error) {
            failure = visible ? unknown(error) : error;
            throw failure;
        } finally {
            if (temporaryOwned) {
                try { Os.remove(temporary.getPath()); }
                catch (ErrnoException error) {
                    if (error.errno != OsConstants.ENOENT) {
                        if (failure != null) { if (failure != error) failure.addSuppressed(error); }
                        else throw visible ? unknown(error) : error;
                    }
                }
            }
        }
    }
    private static final class Guard implements AutoCloseable {
        final File root;
        final ParcelFileDescriptor descriptor;
        final ParcelFileDescriptor.AutoCloseOutputStream stream;
        final FileLock lock;
        private final Object admission = new Object();
        private final AtomicBoolean closed = new AtomicBoolean();
        private volatile boolean published;
        Guard(Context context) throws Exception {
            // Closing any descriptor for this inode may release this process's
            // fcntl locks. Reject another local Guard before it opens the file.
            Failure.require(ADMISSION.compareAndSet(null, admission), "busy");
            Descriptor raw = null;
            ParcelFileDescriptor owned = null;
            ParcelFileDescriptor.AutoCloseOutputStream opened = null;
            FileLock acquired = null;
            try {
                File files = privateFiles(context);
                root = new File(files, "passkey-stores"); directory(root, true); syncDirectory(files);
                raw = new Descriptor(Os.open(new File(root, "store.lock").getPath(), OsConstants.O_RDWR | OsConstants.O_CREAT
                    | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0600));
                try (Descriptor closing = raw) {
                    regular(Os.fstat(raw.fd), 0);
                    owned = ParcelFileDescriptor.dup(raw.fd);
                } // Close the original before obtaining any lock on the duplicate.
                opened = new ParcelFileDescriptor.AutoCloseOutputStream(owned);
                try { acquired = opened.getChannel().tryLock(); }
                catch (OverlappingFileLockException error) { throw new Failure("busy"); }
                Failure.require(acquired != null, "busy");
                descriptor = owned; stream = opened; lock = acquired;
            } catch (Exception error) {
                Exception cleanup = closeKeeping(null, acquired);
                cleanup = closeKeeping(cleanup, opened);
                cleanup = closeKeeping(cleanup, owned);
                if (cleanup != null && cleanup != error) error.addSuppressed(cleanup);
                // An uncertain close fences this process. Do not open the
                // lockfile again until a fresh process can establish ownership.
                if (cleanup == null && (raw == null || !raw.closeFailed)) ADMISSION.compareAndSet(admission, null);
                throw error;
            }
        }
        void requireHeld() throws Failure {
            Failure.require(!closed.get() && ADMISSION.get() == admission && lock.isValid()
                && stream.getChannel().isOpen(), "storage_lock_lost");
        }
        String current() throws Exception {
            requireHeld();
            String name = new String(read(new File(root, "current"), 128), StandardCharsets.US_ASCII);
            Failure.require(name.matches("store-[0-9a-f]{32}"), "invalid_store_pointer"); directory(new File(root, name), false); return name;
        }
        @Override public void close() throws Exception {
            if (!closed.compareAndSet(false, true)) return;
            Exception error = closeKeeping(null, lock);
            error = closeKeeping(error, stream);
            error = closeKeeping(error, descriptor);
            if (error != null) throw published ? unknown(error) : error;
            if (!ADMISSION.compareAndSet(admission, null)) {
                Failure failure = new Failure("storage_lock_lost");
                throw published ? unknown(failure) : failure;
            }
        }
    }
    static final class Transaction implements AutoCloseable {
        private final Guard guard;
        final String store;
        final byte[] ciphertext;
        private boolean attempted;
        private Transaction(Guard guard, String store, byte[] ciphertext) { this.guard = guard; this.store = store; this.ciphertext = ciphertext; }
        void commit(Hbv.Unlocked vault) throws Exception {
            Failure.require(!attempted, "outcome_requires_reopen"); attempted = true;
            Failure.require(guard.current().equals(store) && MessageDigest.isEqual(Codec.sha(ciphertext), vault.expectedFileSha256), "conflict");
            publish(guard, new File(new File(guard.root, store), "vault.hbv"), vault.encryptNext(), vault.expectedFileSha256, Json.MAX_BYTES);
        }
        @Override public void close() throws Exception { guard.close(); }
    }
    static Transaction begin(Context context, String expectedStore) throws Exception {
        Guard guard = new Guard(context);
        try {
            String store = guard.current(); Failure.require(expectedStore == null || expectedStore.equals(store), "store_changed");
            byte[] ciphertext = read(new File(new File(guard.root, store), "vault.hbv"), Json.MAX_BYTES);
            return new Transaction(guard, store, ciphertext);
        } catch (Exception error) { throw closeKeeping(error, guard); }
    }
    static final class Prepared implements AutoCloseable {
        private final Guard guard;
        private final Context context;
        final String action;
        final String store;
        private final byte[] ciphertext;
        private final List<Session.Entry> labels;
        private final long revision;
        private boolean used;
        String backupName;
        Prepared(Guard guard, Context context, String action, String store, byte[] ciphertext,
                 List<Session.Entry> labels, long revision) {
            this.guard = guard; this.context = context; this.action = action; this.store = store;
            this.ciphertext = ciphertext; this.labels = labels; this.revision = revision;
        }
        // Worker checks logical revocation before and after this durable action.
        Loaded publish() throws Exception {
            guard.requireHeld();
            Failure.require(!used, "request_consumed"); used = true;
            if (action.equals("import")) {
                String freshName = "store-" + Codec.hex(Codec.random(16)); File fresh = new File(guard.root, freshName);
                directory(fresh, true); VaultFiles.publish(guard, new File(fresh, "vault.hbv"), ciphertext, null, Json.MAX_BYTES);
                syncDirectory(guard.root);
                File pointer = new File(guard.root, "current"); byte[] prior = maybeRead(pointer, 128);
                VaultFiles.publish(guard, pointer, freshName.getBytes(StandardCharsets.US_ASCII), prior == null ? null : Codec.sha(prior), 128);
                return new Loaded(freshName, labels);
            }
            Failure.require(guard.current().equals(store), "store_changed");
            Failure.require(MessageDigest.isEqual(Codec.sha(ciphertext), Codec.sha(read(new File(new File(guard.root, store), "vault.hbv"), Json.MAX_BYTES))), "conflict");
            if (action.equals("backup")) {
                File exports = new File(context.getFilesDir(), "encrypted-backups"); directory(exports, true); syncDirectory(context.getFilesDir());
                backupName = "backup-r" + revision + "-" + Codec.hex(Codec.random(8)) + ".hbv";
                VaultFiles.publish(guard, new File(exports, backupName), ciphertext, null, Json.MAX_BYTES);
            }
            return new Loaded(store, labels);
        }
        @Override public void close() throws Exception { guard.close(); }
    }
    static Prepared prepare(Context context, String action, String expectedStore, String expectedIncomingHash, byte[] password) throws Exception {
        Failure.require(action.equals("unlock") || action.equals("import") || action.equals("backup"), "invalid_operation");
        Guard guard = new Guard(context);
        try {
            String store = action.equals("import") ? null : guard.current();
            Failure.require(expectedStore == null || expectedStore.equals(store), "store_changed");
            byte[] encrypted = read(action.equals("import") ? new File(context.getFilesDir(), "incoming.hbv")
                : new File(new File(guard.root, store), "vault.hbv"), Json.MAX_BYTES);
            if (action.equals("import")) Failure.require(expectedIncomingHash != null
                && expectedIncomingHash.equals(Codec.hex(Codec.sha(encrypted))), "staged_document_changed");
            try (Hbv.Unlocked vault = Hbv.unlock(encrypted, password)) {
                List<Passkey.Record> records = Passkey.records(vault, BuildConfig.FIXTURE_CERT_SHA256);
                if (action.equals("import") && !records.isEmpty()) {
                    for (Passkey.Record record : records) { record.data.put("backup_state", true); record.save(); }
                    encrypted = vault.encryptNext();
                }
                return new Prepared(guard, context, action, store, encrypted, Session.labels(vault), vault.revision());
            }
        } catch (Exception error) { throw closeKeeping(error, guard); }
    }
    static String stage(Context context, Uri uri, DocumentIO operation) throws Exception {
        try {
            byte[] incoming = readContent(context, uri, operation); operation.check();
            try (Guard guard = new Guard(context)) {
                operation.check();
                File target = new File(context.getFilesDir(), "incoming.hbv"); byte[] old = maybeRead(target, Json.MAX_BYTES);
                publish(guard, target, incoming, old == null ? null : Codec.sha(old), Json.MAX_BYTES);
                operation.check(); return Codec.hex(Codec.sha(incoming));
            }
        } catch (Exception error) { throw StageDiagnostics.failure(error); }
    }
    private static byte[] readContent(Context context, Uri uri, DocumentIO operation) throws Exception {
        ParcelFileDescriptor descriptor = operation.open(context, uri, "r");
        try (ParcelFileDescriptor closing = descriptor; ParcelFileDescriptor.AutoCloseInputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) {
            StructStat stat = Os.fstat(descriptor.getFileDescriptor());
            Failure.require(OsConstants.S_ISREG(stat.st_mode) && stat.st_size >= 0 && stat.st_size <= Json.MAX_BYTES, "unsupported_document_source");
            ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] block = new byte[8192]; int count;
            while (true) {
                operation.check(); count = input.read(block); operation.check(); if (count == -1) break;
                Failure.require(output.size() + count <= Json.MAX_BYTES, "input_limit"); output.write(block, 0, count);
            }
            Failure.require(output.size() > 0, "empty_document"); return output.toByteArray();
        } finally { operation.released(descriptor); }
    }
    static void exportContent(Context context, String backupName, Uri uri, DocumentIO operation) throws Exception {
        Failure.require(backupName.matches("backup-r[0-9]+-[0-9a-f]{16}\\.hbv")
            && uri != null && "content".equals(uri.getScheme()), "invalid_document");
        byte[] encrypted = read(new File(new File(context.getFilesDir(), "encrypted-backups"), backupName), Json.MAX_BYTES);
        boolean writing = false;
        try {
            operation.check();
            // The restricted preview supports ordinary local SAF document files.
            // Streaming/remote providers that cannot provide a regular fsyncable
            // descriptor are explicitly refused rather than called durable.
            writing = true; // Opening a selected document for truncation may already change it.
            ParcelFileDescriptor descriptor = operation.open(context, uri, "rwt");
            try (ParcelFileDescriptor closing = descriptor) {
                Failure.require(descriptor != null && OsConstants.S_ISREG(Os.fstat(descriptor.getFileDescriptor()).st_mode), "unsupported_export_sink");
                try (ParcelFileDescriptor.AutoCloseOutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(descriptor)) {
                    for (int offset = 0; offset < encrypted.length; offset += 8192) {
                        operation.check(); output.write(encrypted, offset, Math.min(8192, encrypted.length - offset));
                    }
                    operation.check(); output.flush(); output.getFD().sync(); operation.check();
                }
            } finally { operation.released(descriptor); }
            Failure.require(MessageDigest.isEqual(Codec.sha(encrypted), Codec.sha(readContent(context, uri, operation))), "export_outcome_unknown");
        } catch (Exception error) { if (writing) throw new Failure("export_outcome_unknown"); throw error; }
    }
    private VaultFiles() {}
}
