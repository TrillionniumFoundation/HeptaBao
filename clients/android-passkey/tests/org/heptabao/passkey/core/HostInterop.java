package org.heptabao.passkey.core;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Host-only format/crypto check. This class is never included in an APK. */
public final class HostInterop {
    interface Negative { void run() throws Exception; }
    private static void reject(List<Object> checks, String name, Negative action) throws Exception {
        boolean refused = false;
        try { action.run(); } catch (Failure error) { refused = true; }
        Failure.require(refused, "negative_check_failed"); checks.add(name);
    }
    private static byte[] read(Path path, int bound) throws Exception {
        Failure.require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= bound, "unsafe_test_file");
        Failure.require((Integer)Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) % 512 == 0600, "unsafe_test_file");
        return Files.readAllBytes(path);
    }
    private static void output(Path path, byte[] bytes) throws Exception {
        try (FileChannel channel = FileChannel.open(path, java.util.EnumSet.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true);
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 7) throw new Failure("invalid_test_arguments");
        String mode = args[0], certificate = args[4]; Codec.unhex(certificate);
        byte[] encrypted = read(Paths.get(args[1]), Json.MAX_BYTES);
        byte[] password = read(Paths.get(args[2]), 1024);
        byte[] recoveryDoc = read(Paths.get(args[3]), 2048);
        Map<String,Object> recovery = Json.object(Json.parse(recoveryDoc));
        byte[] recoveryKey = Codec.decodeStd(Json.string(recovery.get("recovery_key")), 32, 32);
        String rawRequest = new String(read(Paths.get(args[5]), Protocol.MAX_REQUEST), StandardCharsets.UTF_8);
        Path prefix = Paths.get(args[6]);
        try {
            if (mode.equals("negative")) {
                List<Object> checks = new ArrayList<>();
                reject(checks, "wrong_password", () -> { try (Hbv.Unlocked ignored = Hbv.unlock(encrypted, Codec.random(32))) { } });
                reject(checks, "wrong_recovery_key", () -> { try (Hbv.Unlocked ignored = Hbv.unlockRecovery(encrypted, Codec.random(32))) { } });
                Map<String,Object> envelope = Json.object(Json.parse(encrypted));
                Map<String,Object> changed = Json.object(Json.parse(encrypted)); changed.put("revision", Json.integer(changed.get("revision")) + 1);
                byte[] badRevision = Json.bytes(changed);
                reject(checks, "authenticated_revision", () -> { try (Hbv.Unlocked ignored = Hbv.unlockRecovery(badRevision, recoveryKey)) { } });
                changed = Json.object(Json.parse(encrypted)); changed.put("vault_id", Codec.std(Codec.random(16))); byte[] badId = Json.bytes(changed);
                reject(checks, "authenticated_vault_id", () -> { try (Hbv.Unlocked ignored = Hbv.unlockRecovery(badId, recoveryKey)) { } });
                changed = Json.object(Json.parse(encrypted)); Json.object(changed.get("kdf")).put("memory_kib", 1024L); byte[] weakKdf = Json.bytes(changed);
                reject(checks, "fixed_kdf_parameters", () -> { try (Hbv.Unlocked ignored = Hbv.unlockRecovery(weakKdf, recoveryKey)) { } });
                changed = Json.object(Json.parse(encrypted)); Map<String,Object> body = Json.object(changed.get("body"));
                byte[] cipher = Codec.decodeStd(Json.string(body.get("ciphertext")), 16, Json.MAX_BYTES); cipher[0] ^= 1; body.put("ciphertext", Codec.std(cipher)); byte[] tampered = Json.bytes(changed);
                reject(checks, "body_authentication", () -> { try (Hbv.Unlocked ignored = Hbv.unlockRecovery(tampered, recoveryKey)) { } });
                reject(checks, "duplicate_json_fields", () -> Json.parseObject("{\"challenge\":1,\"challenge\":2}", 1024));
                reject(checks, "unpaired_java_surrogate", () -> Json.parseObject("{\"text\":\"" + '\ud800' + "\"}", 1024));
                reject(checks, "padded_base64", () -> Codec.decodeUrl(Codec.url(new byte[32]) + "=", 32, 32));
                reject(checks, "noncanonical_base64", () -> Codec.decodeUrl("AB", 1, 1));
                Map<String,Object> request = Json.parseObject(rawRequest, Protocol.MAX_REQUEST);
                boolean create = request.containsKey("rp");
                Passkey.request(rawRequest, create); checks.add("valid_request");
                changed = Json.parseObject(rawRequest, Protocol.MAX_REQUEST);
                if (create) Json.object(changed.get("rp")).put("id", "wrong-target.heptabao.test"); else changed.put("rpId", "wrong-target.heptabao.test");
                String wrongRp = Json.write(changed); reject(checks, "wrong_rp", () -> Passkey.request(wrongRp, create));
                changed = Json.parseObject(rawRequest, Protocol.MAX_REQUEST);
                if (create) Json.object(changed.get("authenticatorSelection")).put("userVerification", "preferred"); else changed.put("userVerification", "preferred");
                String noUv = Json.write(changed); reject(checks, "uv_required", () -> Passkey.request(noUv, create));
                changed = Json.parseObject(rawRequest, Protocol.MAX_REQUEST); changed.put("extensions", Json.map("unsupported", true));
                String extension = Json.write(changed); reject(checks, "unsupported_extension", () -> Passkey.request(extension, create));
                try (Hbv.Unlocked vault = Hbv.unlock(encrypted, password)) {
                    Failure.require(vault.vaultId().equals(recovery.get("vault_id")), "recovery_binding");
                    checks.add("password_unlock"); vault.close(); reject(checks, "closed_vault", () -> vault.items());
                }
                try (Hbv.Unlocked vault = Hbv.unlockRecovery(encrypted, recoveryKey)) {
                    checks.add("recovery_unlock");
                    if (!Passkey.records(vault, certificate).isEmpty()) {
                        reject(checks, "wrong_fixture_certificate", () -> Passkey.records(vault, Codec.hex(Codec.random(32))));
                    }
                }
                System.out.println(Json.write(Json.map("ok", true, "scope", "host_core_only", "checks", checks, "count", checks.size()))); return;
            }
            boolean create = mode.equals("create"), restore = mode.equals("recover-get");
            Failure.require(create || restore || mode.equals("get"), "invalid_test_mode");
            Passkey.Request request = Passkey.request(rawRequest, create);
            String origin = "android:apk-key-hash:" + Codec.url(Codec.unhex(certificate));
            String response; String credentialId; long count; boolean backupState;
            try (Hbv.Unlocked vault = restore ? Hbv.unlockRecovery(encrypted, recoveryKey) : Hbv.unlock(encrypted, password)) {
                Failure.require(vault.vaultId().equals(recovery.get("vault_id")), "recovery_binding");
                if (restore) for (Passkey.Record record : Passkey.records(vault, certificate)) { record.data.put("backup_state", true); record.save(); }
                if (create) {
                    Passkey.Record record = Passkey.create(vault, request, certificate); response = Passkey.attestation(record, request, origin);
                    credentialId = record.id(); count = record.count(); backupState = record.backedUp();
                    output(Paths.get(prefix + ".vault.hbv"), vault.encryptNext());
                } else {
                    Failure.require(request.credentialIds.size() == 1, "test_requires_one_credential"); credentialId = request.credentialIds.get(0);
                    Passkey.Assertion assertion = Passkey.advance(vault, request, credentialId, certificate, origin);
                    // Required ordering: encrypted counter state is forced before signature generation.
                    output(Paths.get(prefix + ".vault.hbv"), vault.encryptNext()); response = assertion.sign();
                    Passkey.Record record = Passkey.records(vault, certificate).get(0); count = record.count(); backupState = record.backedUp();
                    Map<String,Object> responseObject = Json.object(Json.parseObject(response, Protocol.MAX_REQUEST).get("response"));
                    Signature verify = Signature.getInstance("SHA256withECDSA");
                    verify.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Codec.decodeStd(Json.string(record.data.get("public_spki")), 32, 512))));
                    verify.update(Codec.concat(Codec.decodeUrl(Json.string(responseObject.get("authenticatorData")), 37, 37), Codec.sha(Codec.decodeUrl(Json.string(responseObject.get("clientDataJSON")), 1, 4096))));
                    Failure.require(verify.verify(Codec.decodeUrl(Json.string(responseObject.get("signature")), 8, 80)), "signature_verification_failed");
                    reject(new ArrayList<>(), "one_use_signature", () -> assertion.sign());
                }
            }
            output(Paths.get(prefix + ".response.json"), response.getBytes(StandardCharsets.UTF_8));
            System.out.println(Json.write(Json.map("ok", true, "scope", "host_core_only", "operation", mode, "credential_id", credentialId,
                "sign_count", count, "backup_state", backupState, "ciphertext_sha256", Codec.hex(Codec.sha(read(Paths.get(prefix + ".vault.hbv"), Json.MAX_BYTES))))));
        } finally { Arrays.fill(password, (byte)0); Arrays.fill(recoveryKey, (byte)0); Arrays.fill(recoveryDoc, (byte)0); recovery.clear(); }
    }
}
