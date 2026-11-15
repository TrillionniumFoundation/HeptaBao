/*
 * AndroidX Slice field names and layout adapted from androidx.credentials 1.6.0
 * CredentialEntry.kt, PublicKeyCredentialEntry.kt and CreateEntry.kt (AOSP).
 * Copyright 2022 The Android Open Source Project. Licensed under Apache-2.0.
 * See NOTICE and https://www.apache.org/licenses/LICENSE-2.0 .
 */
package org.heptabao.passkey.preview;

import android.app.PendingIntent;
import android.app.slice.Slice;
import android.app.slice.SliceSpec;
import android.content.Context;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.service.credentials.BeginGetCredentialOption;
import android.service.credentials.CredentialEntry;
import android.service.credentials.CreateEntry;
import java.util.Collections;
import org.heptabao.passkey.core.Protocol;

/** Only the documented platform callbacks are used; no simulated Credential Manager. */
@SuppressWarnings("deprecation")
final class Entries {
    private static final String CREATE = "androidx.credentials.provider.createEntry.SLICE_HINT_";
    private static final String GET = "androidx.credentials.provider.credentialEntry.SLICE_HINT_";
    private static void text(Slice.Builder builder, String value, String hint) { builder.addText(value, null, Collections.singletonList(hint)); }
    private static void action(Slice.Builder builder, PendingIntent pending, String hint) {
        builder.addAction(pending, new Slice.Builder(builder).addHints(Collections.singletonList(hint)).build(), null);
    }
    static CreateEntry create(Context context, PendingIntent pending) {
        Slice.Builder builder = new Slice.Builder(Uri.EMPTY, new SliceSpec("CreateEntry", 1));
        text(builder, "HeptaBao synthetic vault", CREATE + "USER_PROVIDER_ACCOUNT_NAME");
        text(builder, "Native passkey preview", CREATE + "NOTE");
        builder.addIcon(Icon.createWithResource(context, R.drawable.key_icon), null, Collections.singletonList(CREATE + "PROFILE_ICON"));
        text(builder, "false", CREATE + "AUTO_SELECT_ALLOWED");
        action(builder, pending, CREATE + "PENDING_INTENT"); return new CreateEntry(builder.build());
    }
    static CredentialEntry get(Context context, BeginGetCredentialOption option, Session.Entry entry, PendingIntent pending) {
        Slice.Builder builder = new Slice.Builder(Uri.EMPTY, new SliceSpec(Protocol.TYPE, 1));
        text(builder, option.getId(), GET + "OPTION_ID");
        text(builder, entry.id, GET + "DEDUPLICATION_ID");
        text(builder, "false", GET + "IS_DEFAULT_ICON_PREFERRED");
        text(builder, "Passkey", GET + "TYPE_DISPLAY_NAME");
        text(builder, entry.username, GET + "USER_NAME");
        text(builder, "HeptaBao synthetic RP", GET + "CREDENTIAL_TYPE_DISPLAY_NAME");
        text(builder, "false", GET + "AUTO_ALLOWED");
        builder.addIcon(Icon.createWithResource(context, R.drawable.key_icon), null, Collections.singletonList(GET + "PROFILE_ICON"));
        action(builder, pending, GET + "PENDING_INTENT"); return new CredentialEntry(option, builder.build());
    }
}
