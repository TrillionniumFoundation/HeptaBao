package org.heptabao.passkey.preview;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Hbv;
import org.heptabao.passkey.core.Passkey;

/** Caches only public credential labels. No password, DEK or private key is retained here. */
final class Session {
    static final long TTL_MILLIS = 300000;
    static final class Entry {
        final String id;
        final String username;
        Entry(String id, String username) { this.id = id; this.username = username; }
    }
    interface Authorized<T> { T run() throws Exception; }
    private static final class State {
        final long epoch;
        final long deadline;
        final String store;
        final List<Entry> entries;
        State(long epoch, long deadline, String store, List<Entry> entries) {
            this.epoch = epoch; this.deadline = deadline; this.store = store; this.entries = entries;
        }
        State locked() { return new State(epoch + 1, 0, null, Collections.emptyList()); }
    }
    private static final AtomicReference<State> CURRENT = new AtomicReference<>(new State(0, 0, null, Collections.emptyList()));
    private static final Handler TIMER = new Handler(Looper.getMainLooper());
    private static final Runnable EXPIRE = () -> current();
    private static State current() {
        while (true) {
            State state = CURRENT.get();
            if (state.deadline == 0 || SystemClock.elapsedRealtime() < state.deadline) return state;
            if (CURRENT.compareAndSet(state, state.locked())) return CURRENT.get();
        }
    }
    // Logical revocation never waits for filesystem, Binder, UI or crypto work.
    static long lockEpoch() {
        while (true) { State old = CURRENT.get(); State next = old.locked(); if (CURRENT.compareAndSet(old, next)) return next.epoch; }
    }
    static void lock() { lockEpoch(); }
    static boolean unlocked() { return current().deadline != 0; }
    static long epoch() throws Failure { State state = current(); Failure.require(state.deadline != 0, "locked"); return state.epoch; }
    static String store(long expected) throws Failure { State state = checked(expected, null); return state.store; }
    static List<Entry> entries() throws Failure { State state = current(); Failure.require(state.deadline != 0, "locked"); return new ArrayList<>(state.entries); }
    private static State checked(long expected, String store) throws Failure {
        State state = current(); Failure.require(state.deadline != 0 && expected == state.epoch
            && (store == null || store.equals(state.store)), "locked"); return state;
    }
    static void check(long expected, String store) throws Failure { checked(expected, store); }
    static void checkLocked(long expected) throws Failure { State state = current(); Failure.require(state.deadline == 0 && state.epoch == expected, "operation_interrupted"); }
    static List<Entry> labels(Hbv.Unlocked vault) throws Failure {
        List<Entry> result = new ArrayList<>();
        for (Passkey.Record record : Passkey.records(vault, BuildConfig.FIXTURE_CERT_SHA256)) result.add(new Entry(record.id(), record.username()));
        return result;
    }
    static void unlock(long lockedEpoch, String storeId, List<Entry> labels) throws Failure {
        State old = current(); Failure.require(old.deadline == 0 && old.epoch == lockedEpoch, "operation_interrupted");
        Failure.require(CURRENT.compareAndSet(old, new State(old.epoch + 1, SystemClock.elapsedRealtime() + TTL_MILLIS,
            storeId, Collections.unmodifiableList(new ArrayList<>(labels)))), "operation_interrupted");
        TIMER.postDelayed(EXPIRE, TTL_MILLIS + 1);
    }
    static <T> T authorized(long expected, String expectedStore, Authorized<T> operation) throws Exception {
        check(expected, expectedStore); return operation.run();
    }
    static long refreshAfterCommit(long expected, String store, List<Entry> labels) throws Failure {
        State old = checked(expected, store);
        State next = new State(old.epoch + 1, old.deadline, old.store, Collections.unmodifiableList(new ArrayList<>(labels)));
        Failure.require(CURRENT.compareAndSet(old, next), "locked"); return next.epoch;
    }
}
