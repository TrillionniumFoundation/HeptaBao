package org.heptabao.passkey.core;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Limited WebAuthn ES256 authenticator implementation. JCA performs every EC operation. */
public final class Passkey {
    public static final String RECORD_SCHEMA = "heptabao-passkey-record-v1";
    public static final int MAX_RECORDS = 8;
    public static final class Request {
        public final boolean create;
        public final String challenge;
        public final String userHandle;
        public final String username;
        public final String displayName;
        public final List<String> credentialIds;
        public final byte[] requestDigest;
        private Request(boolean create, String challenge, String userHandle, String username,
                        String displayName, List<String> ids, byte[] digest) {
            this.create = create; this.challenge = challenge; this.userHandle = userHandle;
            this.username = username; this.displayName = displayName; this.credentialIds = ids;
            this.requestDigest = digest;
        }
    }
    public static Request request(String text, boolean create) throws Failure {
        Map<String,Object> value = Json.parseObject(text, Protocol.MAX_REQUEST);
        Json.allowed(value, create ? new String[]{"challenge","rp","user","pubKeyCredParams","timeout","excludeCredentials","authenticatorSelection","attestation","extensions"}
                                  : new String[]{"challenge","rpId","allowCredentials","userVerification","timeout","extensions"});
        String challenge = Json.string(value.get("challenge")); Codec.decodeUrl(challenge, 32, 64);
        if (value.containsKey("timeout")) {
            long timeout = Json.integer(value.get("timeout")); Failure.require(timeout >= 1000 && timeout <= 300000, "unsupported_timeout");
        }
        if (value.containsKey("extensions")) Failure.require(Json.object(value.get("extensions")).isEmpty(), "unsupported_extensions");
        String handle = null, username = null, displayName = null;
        if (create) {
            Map<String,Object> rp = Json.object(value.get("rp")); Json.keys(rp, "id", "name");
            Failure.require(Json.string(rp.get("id")).equals(Protocol.RP_ID), "wrong_rp");
            bounded(Json.string(rp.get("name")), 1, 128);
            Map<String,Object> user = Json.object(value.get("user")); Json.keys(user, "id", "name", "displayName");
            handle = Json.string(user.get("id")); Codec.decodeUrl(handle, 16, 64);
            username = Json.string(user.get("name")); displayName = Json.string(user.get("displayName"));
            bounded(username, 1, 128); bounded(displayName, 1, 128);
            List<Object> algorithms = Json.list(value.get("pubKeyCredParams"));
            Failure.require(!algorithms.isEmpty() && algorithms.size() <= 8, "unsupported_algorithm");
            boolean supported = false;
            for (Object raw : algorithms) {
                Map<String,Object> algorithm = Json.object(raw); Json.keys(algorithm, "type", "alg");
                Failure.require(Json.string(algorithm.get("type")).equals("public-key"), "unsupported_algorithm");
                if (Json.integer(algorithm.get("alg")) == -7) supported = true;
            }
            Failure.require(supported, "unsupported_algorithm");
            Map<String,Object> selection = Json.object(value.get("authenticatorSelection"));
            Json.allowed(selection, "authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification");
            Failure.require("required".equals(selection.get("userVerification")) && "required".equals(selection.get("residentKey")), "verification_required");
            if (selection.containsKey("requireResidentKey")) Failure.require(Json.bool(selection.get("requireResidentKey")), "resident_key_required");
            if (selection.containsKey("authenticatorAttachment")) Failure.require("platform".equals(selection.get("authenticatorAttachment")), "unsupported_attachment");
            Failure.require("none".equals(value.get("attestation")), "unsupported_attestation");
        } else {
            Failure.require(Protocol.RP_ID.equals(value.get("rpId")), "wrong_rp");
            Failure.require("required".equals(value.get("userVerification")), "verification_required");
        }
        List<String> ids = new ArrayList<>(); HashSet<String> unique = new HashSet<>();
        String idsKey = create ? "excludeCredentials" : "allowCredentials";
        if (value.containsKey(idsKey)) {
            List<Object> descriptors = Json.list(value.get(idsKey));
            Failure.require(descriptors.size() <= MAX_RECORDS, "credential_limit");
            for (Object raw : descriptors) {
                Map<String,Object> descriptor = Json.object(raw); Json.allowed(descriptor, "type", "id", "transports");
                Failure.require("public-key".equals(descriptor.get("type")), "unsupported_credential");
                String id = Json.string(descriptor.get("id")); Codec.decodeUrl(id, 32, 32);
                Failure.require(unique.add(id), "duplicate_credential"); ids.add(id);
                if (descriptor.containsKey("transports")) {
                    List<Object> transports = Json.list(descriptor.get("transports"));
                    Failure.require(transports.size() == 1 && "internal".equals(transports.get(0)), "unsupported_transport");
                }
            }
        }
        return new Request(create, challenge, handle, username, displayName, ids,
                           Codec.sha(text.getBytes(StandardCharsets.UTF_8)));
    }
    private static void bounded(String value, int minimum, int maximum) throws Failure {
        int size = value.getBytes(StandardCharsets.UTF_8).length;
        Failure.require(size >= minimum && size <= maximum, "input_limit");
    }
    public static final class Record {
        public final Map<String,Object> item;
        public final Map<String,Object> data;
        private Record(Map<String,Object> item, Map<String,Object> data) { this.item = item; this.data = data; }
        public String id() throws Failure { return Json.string(data.get("credential_id")); }
        public String username() throws Failure { return Json.string(data.get("user_name")); }
        public long count() throws Failure { return Json.integer(data.get("sign_count")); }
        public boolean backedUp() throws Failure { return Json.bool(data.get("backup_state")); }
        public void save() throws Failure { item.put("secret", Json.write(data)); }
    }
    public static List<Record> records(Hbv.Unlocked vault, String certificate) throws Failure {
        List<Record> records = new ArrayList<>(); HashSet<String> ids = new HashSet<>();
        for (Object raw : vault.items()) {
            Map<String,Object> item = Json.object(raw); String itemId = Json.string(item.get("id"));
            if (!itemId.startsWith("passkey-")) continue;
            Failure.require("api".equals(item.get("kind")) && ("https://" + Protocol.RP_ID).equals(item.get("origin")), "invalid_passkey_record");
            Map<String,Object> data = Json.parseObject(Json.string(item.get("secret")), 65536);
            Json.keys(data, "schema", "rp_id", "credential_id", "user_handle", "user_name", "display_name", "private_pkcs8", "public_spki", "sign_count", "backup_eligible", "backup_state", "caller_package", "caller_certificate_sha256");
            Failure.require(RECORD_SCHEMA.equals(data.get("schema")) && Protocol.RP_ID.equals(data.get("rp_id"))
                && Protocol.FIXTURE_PACKAGE.equals(data.get("caller_package")) && certificate.equals(data.get("caller_certificate_sha256")), "wrong_target");
            String id = Json.string(data.get("credential_id")); Codec.decodeUrl(id, 32, 32);
            Failure.require(itemId.equals("passkey-" + id) && ids.add(id), "invalid_passkey_record");
            Codec.decodeUrl(Json.string(data.get("user_handle")), 16, 64);
            bounded(Json.string(data.get("user_name")), 1, 128); bounded(Json.string(data.get("display_name")), 1, 128);
            byte[] privateEncoding = Codec.decodeStd(Json.string(data.get("private_pkcs8")), 32, 512);
            Arrays.fill(privateEncoding, (byte)0);
            Codec.decodeStd(Json.string(data.get("public_spki")), 32, 512);
            long count = Json.integer(data.get("sign_count"));
            Failure.require(count >= 0 && count <= 0xffffffffL && Json.bool(data.get("backup_eligible")), "invalid_passkey_record");
            Json.bool(data.get("backup_state")); records.add(new Record(item, data));
            Failure.require(records.size() <= MAX_RECORDS, "credential_limit");
        }
        return records;
    }
    public static Record create(Hbv.Unlocked vault, Request request, String certificate) throws Failure {
        Failure.require(request.create, "wrong_operation");
        List<Record> current = records(vault, certificate);
        Failure.require(current.size() < MAX_RECORDS, "credential_limit");
        for (Record record : current) Failure.require(!request.credentialIds.contains(record.id()), "credential_excluded");
        byte[] privateBytes = null; PrivateKey privateKey = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1")); KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate(); privateBytes = privateKey.getEncoded();
            String credentialId = Codec.url(Codec.random(32));
            Map<String,Object> data = Json.map("schema", RECORD_SCHEMA, "rp_id", Protocol.RP_ID,
                "credential_id", credentialId, "user_handle", request.userHandle, "user_name", request.username,
                "display_name", request.displayName, "private_pkcs8", Codec.std(privateBytes),
                "public_spki", Codec.std(pair.getPublic().getEncoded()), "sign_count", 0L,
                "backup_eligible", true, "backup_state", false, "caller_package", Protocol.FIXTURE_PACKAGE,
                "caller_certificate_sha256", certificate);
            Map<String,Object> item = Json.map("id", "passkey-" + credentialId, "kind", "api",
                "title", "Synthetic passkey", "username", request.username, "origin", "https://" + Protocol.RP_ID,
                "secret", Json.write(data), "notes", "Restricted native passkey preview", "totp", null);
            vault.items().add(item); return new Record(item, data);
        } catch (GeneralSecurityException error) { throw new Failure("key_generation_failed"); }
        finally {
            if (privateBytes != null) Arrays.fill(privateBytes, (byte)0);
            destroy(privateKey);
        }
    }
    private static void destroy(PrivateKey key) {
        if (key == null) return;
        try { key.destroy(); } catch (Exception ignored) { /* JCA providers may retain internal copies. */ }
    }
    private static ECPublicKey publicKey(Record record) throws Failure {
        try {
            ECPublicKey key = (ECPublicKey)KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Codec.decodeStd(Json.string(record.data.get("public_spki")), 32, 512)));
            requireP256(key.getParams()); return key;
        } catch (GeneralSecurityException | ClassCastException error) { throw new Failure("invalid_passkey_key"); }
    }
    private static void requireP256(ECParameterSpec parameters) throws GeneralSecurityException, Failure {
        AlgorithmParameters algorithm = AlgorithmParameters.getInstance("EC"); algorithm.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = algorithm.getParameterSpec(ECParameterSpec.class);
        Failure.require(parameters.getCurve().equals(expected.getCurve()) && parameters.getGenerator().equals(expected.getGenerator())
            && parameters.getOrder().equals(expected.getOrder()) && parameters.getCofactor() == expected.getCofactor(), "unsupported_curve");
    }
    private static byte[] fixed(BigInteger value) throws Failure {
        byte[] bytes = value.toByteArray();
        Failure.require(value.signum() >= 0 && value.bitLength() <= 256, "invalid_passkey_key");
        byte[] result = new byte[32]; int start = bytes.length == 33 ? 1 : 0;
        System.arraycopy(bytes, start, result, 32 - (bytes.length - start), bytes.length - start); return result;
    }
    private static byte[] clientData(Request request, String origin) throws Failure {
        return Json.bytes(Json.map("type", request.create ? "webauthn.create" : "webauthn.get",
                                  "challenge", request.challenge, "origin", origin, "crossOrigin", false));
    }
    private static byte[] authenticatorData(Record record, boolean create) throws Failure {
        int flags = 1 | 4 | 8 | (record.backedUp() ? 16 : 0) | (create ? 64 : 0);
        byte[] base = ByteBuffer.allocate(37).put(Codec.sha(Protocol.RP_ID.getBytes(StandardCharsets.UTF_8)))
            .put((byte)flags).putInt((int)record.count()).array();
        if (!create) return base;
        ECPublicKey key = publicKey(record);
        Map<Object,Object> cose = new LinkedHashMap<>();
        cose.put(1, 2); cose.put(3, -7); cose.put(-1, 1); cose.put(-2, fixed(key.getW().getAffineX())); cose.put(-3, fixed(key.getW().getAffineY()));
        byte[] id = Codec.decodeUrl(record.id(), 32, 32);
        return Codec.concat(base, new byte[16], new byte[]{0, 32}, id, Codec.cbor(cose));
    }
    private static Map<String,Object> credential(Record record, Map<String,Object> response) throws Failure {
        return Json.map("id", record.id(), "rawId", record.id(), "type", "public-key", "authenticatorAttachment", "platform",
                        "response", response, "clientExtensionResults", Json.map());
    }
    /** Caller must have completed fresh password verification and explicit approval. */
    public static String attestation(Record record, Request request, String origin) throws Failure {
        Failure.require(request.create, "wrong_operation");
        byte[] attestation = Codec.cbor(Json.map("fmt", "none", "authData", authenticatorData(record, true), "attStmt", Json.map()));
        return Json.write(credential(record, Json.map("clientDataJSON", Codec.url(clientData(request, origin)),
            "attestationObject", Codec.url(attestation), "transports", Arrays.asList("internal"))));
    }
    public static Assertion advance(Hbv.Unlocked vault, Request request, String selectedId, String certificate, String origin) throws Failure {
        Failure.require(!request.create, "wrong_operation"); Record selected = null;
        for (Record record : records(vault, certificate)) if (record.id().equals(selectedId)) selected = record;
        Failure.require(selected != null && (request.credentialIds.isEmpty() || request.credentialIds.contains(selectedId)), "credential_unavailable");
        long count = selected.count(); Failure.require(count < 0xffffffffL, "counter_exhausted");
        selected.data.put("sign_count", count + 1); selected.save();
        return new Assertion(selected, authenticatorData(selected, false), clientData(request, origin));
    }
    /** Counter mutation must be durably committed before calling sign(). */
    public static final class Assertion {
        private final Record record;
        private final byte[] authData;
        private final byte[] clientData;
        private boolean signed;
        private Assertion(Record record, byte[] authData, byte[] clientData) { this.record = record; this.authData = authData; this.clientData = clientData; }
        public String sign() throws Failure {
            Failure.require(!signed, "request_consumed"); signed = true;
            byte[] encoding = Codec.decodeStd(Json.string(record.data.get("private_pkcs8")), 32, 512); PrivateKey privateKey = null;
            try {
                privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoding));
                Failure.require(privateKey instanceof ECPrivateKey, "unsupported_curve"); requireP256(((ECPrivateKey)privateKey).getParams());
                byte[] message = Codec.concat(authData, Codec.sha(clientData));
                Signature signature = Signature.getInstance("SHA256withECDSA"); signature.initSign(privateKey); signature.update(message);
                byte[] result = signature.sign();
                Signature check = Signature.getInstance("SHA256withECDSA"); check.initVerify(publicKey(record)); check.update(message);
                Failure.require(check.verify(result), "key_pair_mismatch");
                return Json.write(credential(record, Json.map("clientDataJSON", Codec.url(clientData), "authenticatorData", Codec.url(authData),
                    "signature", Codec.url(result), "userHandle", record.data.get("user_handle"))));
            } catch (GeneralSecurityException error) { throw new Failure("signature_failed"); }
            finally { Arrays.fill(encoding, (byte)0); destroy(privateKey); }
        }
    }
}
