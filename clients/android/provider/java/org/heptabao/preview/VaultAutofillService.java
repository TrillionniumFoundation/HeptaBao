package org.heptabao.preview;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.Uri;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillContext;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.Dataset;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;
import android.widget.RemoteViews;
import java.util.List;

public final class VaultAutofillService extends AutofillService {
    @SuppressWarnings("deprecation") @Override public void onFillRequest(FillRequest request, CancellationSignal cancellation, FillCallback callback) {
        VaultApplication app = (VaultApplication)getApplication();
        try {
            if (cancellation.isCanceled()) return;
            if ((request.getFlags() & FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST) != 0) throw new TargetPolicy.Rejected("browser_unsupported");
            List<FillContext> contexts = request.getFillContexts();
            if (contexts.isEmpty()) throw new TargetPolicy.Rejected("missing_structure");
            TargetPolicy.Target target = TargetPolicy.inspect(this, contexts.get(contexts.size() - 1).getStructure());
            if (app.isImporting()) throw new TargetPolicy.Rejected("import_in_progress");
            if (!VaultFiles.exists(this)) throw new TargetPolicy.Rejected("vault_not_imported");
            VaultApplication.Pending pending = app.begin(target);
            cancellation.setOnCancelListener(() -> app.cancel(pending.token));
            if (cancellation.isCanceled()) return;
            Intent intent = new Intent(this, AuthActivity.class)
                .setAction("org.heptabao.personal.preview.AUTHORIZE_FILL")
                .setData(Uri.parse("heptabao-auth://local/" + pending.token));
            // Autofill must add its arguments. The explicit component and unique data cannot be replaced by fill-in extras.
            PendingIntent launch = PendingIntent.getActivity(this, 0, intent,
                PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_MUTABLE);
            app.attachLaunch(pending.token, launch);
            RemoteViews menu = new RemoteViews(getPackageName(), R.layout.presentation);
            // Dataset auth returns an ephemeral dataset directly; no unlocked response is cached by the framework.
            Dataset locked = new Dataset.Builder(menu).setValue(target.username, null).setValue(target.password, null)
                .setAuthentication(launch.getIntentSender()).build();
            FillResponse response = new FillResponse.Builder().addDataset(locked).build();
            if (!cancellation.isCanceled()) callback.onSuccess(response);
            else app.cancel(pending.token);
        } catch (TargetPolicy.Rejected rejection) {
            app.lockAll(rejection.code); if (!cancellation.isCanceled()) callback.onSuccess(null);
        } catch (RuntimeException error) {
            app.lockAll("invalid_request"); if (!cancellation.isCanceled()) callback.onSuccess(null);
        }
    }
    @Override public void onSaveRequest(SaveRequest request, SaveCallback callback) { callback.onFailure("Read-only provider"); }
}
