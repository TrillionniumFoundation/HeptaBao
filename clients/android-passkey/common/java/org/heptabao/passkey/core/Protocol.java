package org.heptabao.passkey.core;

/** Deliberately one synthetic relying party and one native caller. No browser origin support. */
public final class Protocol {
    public static final String RP_ID = "passkeys.heptabao.test";
    public static final String FIXTURE_PACKAGE = "org.heptabao.passkey.fixture";
    public static final String PROVIDER_PACKAGE = "org.heptabao.passkey.preview";
    public static final String PROVIDER_SERVICE = PROVIDER_PACKAGE + ".ProviderService";
    public static final String TYPE = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL";
    public static final String REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON";
    public static final String CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH";
    public static final String REGISTRATION_JSON = "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON";
    public static final String AUTHENTICATION_JSON = "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON";
    public static final String SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE";
    public static final String RP_BASE = "http://127.0.0.1:38491";
    public static final int MAX_REQUEST = 65536;
}
