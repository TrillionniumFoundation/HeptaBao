package org.heptabao.passkey.preview;

import android.credentials.ClearCredentialStateException;
import android.credentials.CreateCredentialException;
import android.credentials.GetCredentialException;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import android.service.credentials.BeginCreateCredentialRequest;
import android.service.credentials.BeginCreateCredentialResponse;
import android.service.credentials.BeginGetCredentialOption;
import android.service.credentials.BeginGetCredentialRequest;
import android.service.credentials.BeginGetCredentialResponse;
import android.service.credentials.ClearCredentialStateRequest;
import android.service.credentials.CredentialProviderService;
import java.util.ArrayList;
import java.util.List;
import org.heptabao.passkey.core.Failure;
import org.heptabao.passkey.core.Passkey;
import org.heptabao.passkey.core.Protocol;

/** Platform API 34 provider. This phase never reads or decrypts the private key store. */
public final class ProviderService extends CredentialProviderService {
    @Override public void onBeginCreateCredential(BeginCreateCredentialRequest request, CancellationSignal cancellation,
            OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException> callback) {
        Tickets.Ticket ticket = null;
        try {
            Failure.require(!cancellation.isCanceled(), "cancelled");
            Failure.require(Protocol.TYPE.equals(request.getType()), "unsupported_credential");
            String origin = Policy.caller(this, request.getCallingAppInfo());
            Passkey.Request parsed = Passkey.request(Policy.request(request.getData()), true);
            Failure.require(Session.entries().size() < Passkey.MAX_RECORDS, "credential_limit");
            ticket = Tickets.issue(parsed, origin, null); final Tickets.Ticket pending = ticket;
            cancellation.setOnCancelListener(() -> Tickets.cancel(pending));
            Failure.require(pending.valid() && !cancellation.isCanceled(), "cancelled");
            callback.onResult(new BeginCreateCredentialResponse.Builder()
                .addCreateEntry(Entries.create(this, Tickets.pending(this, pending))).build());
        } catch (Exception error) {
            if (ticket != null) Tickets.cancel(ticket);
            callback.onError(new CreateCredentialException(CreateCredentialException.TYPE_NO_CREATE_OPTIONS, safe(error)));
        }
    }
    @Override public void onBeginGetCredential(BeginGetCredentialRequest request, CancellationSignal cancellation,
            OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> callback) {
        List<Tickets.Ticket> tickets = new ArrayList<>();
        try {
            Failure.require(!cancellation.isCanceled(), "cancelled");
            String origin = Policy.caller(this, request.getCallingAppInfo());
            List<BeginGetCredentialOption> options = request.getBeginGetCredentialOptions();
            Failure.require(options.size() == 1, "unsupported_options");
            BeginGetCredentialOption option = options.get(0);
            Failure.require(Protocol.TYPE.equals(option.getType()), "unsupported_credential");
            Passkey.Request parsed = Passkey.request(Policy.request(option.getCandidateQueryData()), false);
            BeginGetCredentialResponse.Builder response = new BeginGetCredentialResponse.Builder();
            for (Session.Entry entry : Session.entries()) {
                if (!parsed.credentialIds.isEmpty() && !parsed.credentialIds.contains(entry.id)) continue;
                Tickets.Ticket ticket = Tickets.issue(parsed, origin, entry.id); tickets.add(ticket);
                response.addCredentialEntry(Entries.get(this, option, entry, Tickets.pending(this, ticket)));
            }
            Failure.require(!tickets.isEmpty(), "credential_unavailable");
            cancellation.setOnCancelListener(() -> { for (Tickets.Ticket ticket : tickets) Tickets.cancel(ticket); });
            Failure.require(!cancellation.isCanceled(), "cancelled"); callback.onResult(response.build());
        } catch (Exception error) {
            for (Tickets.Ticket ticket : tickets) Tickets.cancel(ticket);
            callback.onError(new GetCredentialException(GetCredentialException.TYPE_NO_CREDENTIAL, safe(error)));
        }
    }
    @Override public void onClearCredentialState(ClearCredentialStateRequest request, CancellationSignal cancellation,
            OutcomeReceiver<Void, ClearCredentialStateException> callback) {
        try {
            Policy.caller(this, request.getCallingAppInfo()); Session.lock(); callback.onResult(null);
        } catch (Exception error) {
            callback.onError(new ClearCredentialStateException(ClearCredentialStateException.TYPE_UNKNOWN, safe(error)));
        }
    }
    static String safe(Exception error) { return error instanceof Failure ? ((Failure)error).code : "operation_failed"; }
}
