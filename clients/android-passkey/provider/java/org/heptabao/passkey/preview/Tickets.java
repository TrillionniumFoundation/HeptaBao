package org.heptabao.passkey.preview;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.SystemClock;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.heptabao.passkey.core.Codec;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Passkey;

final class Tickets {
    static final class Ticket {
        final String id;
        final boolean create;
        final byte[] requestDigest;
        final String origin;
        final String selectedId;
        final long epoch;
        final String store;
        final long expires;
        volatile boolean cancelled;
        Ticket(String id, Passkey.Request request, String origin, String selectedId, long epoch, String store) {
            this.id = id; this.create = request.create; this.requestDigest = request.requestDigest.clone();
            this.origin = origin; this.selectedId = selectedId; this.epoch = epoch; this.store = store;
            this.expires = SystemClock.elapsedRealtime() + 180000;
        }
        boolean valid() { return !cancelled && SystemClock.elapsedRealtime() < expires; }
    }
    private static final Map<String,Ticket> PENDING = new HashMap<>();
    static synchronized Ticket issue(Passkey.Request request, String origin, String selectedId) throws Failure {
        Iterator<Ticket> iterator = PENDING.values().iterator();
        while (iterator.hasNext()) if (!iterator.next().valid()) iterator.remove();
        Failure.require(PENDING.size() < 32, "request_capacity");
        String id = Codec.url(Codec.random(24)); long epoch = Session.epoch();
        Ticket ticket = new Ticket(id, request, origin, selectedId, epoch, Session.store(epoch));
        PENDING.put(id, ticket); return ticket;
    }
    static PendingIntent pending(Context context, Ticket ticket) {
        Intent intent = new Intent(context, OperationActivity.class).setData(Uri.parse("heptabao-passkey://selection/" + ticket.id));
        int requestCode = ByteBuffer.wrap(Codec.random(4)).getInt() & 0x7fffffff;
        // The platform may launch this PendingIntent again when the user goes back.
        // Keep the framework token reusable; our consumed nonce rejects a second
        // execution and requires a new CredentialManager request.
        return PendingIntent.getActivity(context, requestCode, intent, PendingIntent.FLAG_MUTABLE);
    }
    static synchronized Ticket consume(Uri uri) throws Failure {
        Failure.require(uri != null && "heptabao-passkey".equals(uri.getScheme()) && "selection".equals(uri.getHost())
            && uri.getQuery() == null && uri.getFragment() == null, "invalid_selection");
        String id = uri.getLastPathSegment();
        Failure.require(id != null && uri.getPath().equals("/" + id), "invalid_selection");
        Ticket ticket = PENDING.remove(id);
        Failure.require(ticket != null && ticket.valid(), "selection_expired"); return ticket;
    }
    static void cancel(Ticket ticket) {
        ticket.cancelled = true;
        synchronized (Tickets.class) { PENDING.remove(ticket.id); }
    }
}
