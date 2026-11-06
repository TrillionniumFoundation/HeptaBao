#!/usr/bin/env python3
"""Build the read-only Android Autofill preview with a pinned, explicit SDK/JDK.

No Gradle daemon, network resolution, device operation, or production signing key.
The dependency jar is supplied by the operator and must match the pinned digest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import time
import zipfile

BC_SHA256 = "fc50334d4d87b4272e72fa95ca748ead05bdef02ef760a5b13f64ffee317cd81"
GOOD_PACKAGE = "org.heptabao.synthetic.fixture"
DECOY_PACKAGE = "org.heptabao.synthetic.decoy"
PROVIDER_PACKAGE = "org.heptabao.personal.preview"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--bc-jar", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    source, fixture, sdk, jdk, bc, output = (path.resolve() for path in (args.source, args.fixture, args.sdk, args.java_home, args.bc_jar, args.output))
    if digest(bc) != BC_SHA256:
        raise RuntimeError("dependency_digest_mismatch")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = output / "private"; private.mkdir(mode=0o700)
    logs = output / "logs"; logs.mkdir(mode=0o700)
    apks = output / "apks"; apks.mkdir(mode=0o700)
    android = sdk / "platforms/android-34/android.jar"
    bt = sdk / "build-tools/34.0.0"
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin")
    expected = json.loads((fixture / "expected.json").read_text())
    if expected.get("schema") != 1 or expected.get("entry_id") != "android-fixture" or expected.get("origin") != "https://native-fixture.heptabao.invalid" or expected["ciphertext_sha256"] != digest(fixture / "vault.hbv"):
        raise RuntimeError("fixture_binding_mismatch")
    for name in ("username_sha256", "password_sha256"):
        if len(expected[name]) != 64 or any(c not in "0123456789abcdef" for c in expected[name]):
            raise RuntimeError("fixture_digest_invalid")
    receipt = {"schema": 1, "purpose": "synthetic_android_autofill_build", "started_unix_ns": time.time_ns(), "source_files_before": inventory(source), "build_script_sha256": digest(Path(__file__).resolve()), "dependency": {"name": "bcprov-jdk15to18-1.86.jar", "sha256": BC_SHA256, "source": "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15to18/1.86/bcprov-jdk15to18-1.86.jar"}, "platform": platform.platform(), "commands": [], "fixture_public": expected, "artifacts": {}}
    def run(argv, label, cwd=None):
        start = time.time_ns()
        result = subprocess.run([str(value) for value in argv], cwd=cwd, env=env, capture_output=True, check=False)
        stdout, stderr = logs / (label + ".stdout"), logs / (label + ".stderr")
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        receipt["commands"].append({"label": label, "argv": [str(value) for value in argv], "started_unix_ns": start, "finished_unix_ns": time.time_ns(), "exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
        if result.returncode:
            (output / "receipt.failed.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
            raise RuntimeError("build_failed_" + label)
        return result.stdout
    run([jdk / "bin/java", "-version"], "java-version")
    run([jdk / "bin/javac", "-version"], "javac-version")
    run([bt / "aapt2", "version"], "aapt2-version")
    run([bt / "d8", "--version"], "d8-version")
    run([bt / "apksigner", "version"], "apksigner-version")
    license_text = run([jdk / "bin/java", "-cp", bc, "org.bouncycastle.LICENSE"], "bc-license")
    receipt["tool_files"] = {str(path): digest(path) for path in (android, bt / "aapt2", bt / "lib/d8.jar", bt / "lib/apksigner.jar", bt / "zipalign", jdk / "bin/java", jdk / "bin/javac")}
    interop = output / "interop-classes"; interop.mkdir()
    crypto = source / "provider/java/org/heptabao/preview"
    run([jdk / "bin/javac", "--release", "17", "-cp", bc, "-d", interop, crypto / "StrictJson.java", crypto / "VaultCrypto.java", source / "tests/org/heptabao/preview/CryptoInterop.java"], "compile-interop")
    raw = run([jdk / "bin/java", "-cp", str(interop) + os.pathsep + str(bc), "org.heptabao.preview.CryptoInterop", fixture], "rust-java-interop")
    receipt["crypto_interop"] = json.loads(raw)
    if receipt["crypto_interop"].get("ok") is not True:
        raise RuntimeError("interop_failed")
    password = private / "keystore.pass"; key_password = private / "key.pass"
    synthetic_password = secrets.token_urlsafe(32) + "\n"
    password.write_text(synthetic_password); key_password.write_text(synthetic_password)
    key_paths = {}
    certificates = {}
    for label in ("provider", "fixture-good", "fixture-wrong"):
        keystore = private / (label + ".p12"); cert = private / (label + ".der")
        run([jdk / "bin/keytool", "-genkeypair", "-alias", "synthetic", "-keyalg", "RSA", "-keysize", "3072", "-validity", "30", "-dname", "CN=HeptaBao synthetic " + label, "-keystore", keystore, "-storetype", "PKCS12", "-storepass:file", password, "-keypass:file", key_password, "-noprompt"], "keygen-" + label)
        run([jdk / "bin/keytool", "-exportcert", "-alias", "synthetic", "-keystore", keystore, "-storepass:file", password, "-file", cert], "certificate-" + label)
        key_paths[label] = keystore; certificates[label] = digest(cert)
    receipt["synthetic_certificates_sha256"] = certificates
    def build(kind, variant, package, key_label):
        directory = output / variant; directory.mkdir()
        manifest = (source / kind / "AndroidManifest.xml").read_text().replace("@@PACKAGE@@", package).replace("@@LABEL@@", "HeptaBao " + variant)
        (directory / "AndroidManifest.xml").write_text(manifest)
        generated = directory / "generated"; generated.mkdir()
        classes = directory / "classes"; classes.mkdir()
        dex = directory / "dex"; dex.mkdir()
        resources = directory / "resources.zip"
        run([bt / "aapt2", "compile", "--dir", source / kind / "res", "-o", resources], variant + "-resources")
        namespace = "org.heptabao.preview" if kind == "provider" else "org.heptabao.fixture"
        linked = directory / "linked.apk"
        link = [bt / "aapt2", "link", "-I", android, "--manifest", directory / "AndroidManifest.xml", "--java", generated, "--custom-package", namespace, "--min-sdk-version", "34", "--target-sdk-version", "34", "-o", linked, resources]
        assets = directory / "assets"; assets.mkdir()
        if kind == "fixture": shutil.copyfile(fixture / "vault.hbv", assets / "vault.hbv")
        else: (assets / "bouncycastle-LICENSE.txt").write_bytes(license_text)
        link.extend(["-A", assets])
        run(link, variant + "-link")
        config = generated / Path(namespace.replace(".", "/")) / "BuildConfig.java"
        config.parent.mkdir(parents=True, exist_ok=True)
        if kind == "provider":
            constants = {"TARGET_PACKAGE": GOOD_PACKAGE, "TARGET_CERT_SHA256": certificates["fixture-good"], "ENTRY_ID": expected["entry_id"], "ENTRY_ORIGIN": expected["origin"]}
        else:
            constants = {"USER_SHA256": expected["username_sha256"], "PASSWORD_SHA256": expected["password_sha256"]}
        config.write_text("package " + namespace + ";\nfinal class BuildConfig {\n" + "".join("  static final String " + name + " = " + json.dumps(value) + ";\n" for name, value in constants.items()) + "}\n")
        sources = sorted((source / kind / "java").rglob("*.java")) + sorted(generated.rglob("*.java"))
        classpath = str(android) + (os.pathsep + str(bc) if kind == "provider" else "")
        run([jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp", classpath, "-d", classes] + sources, variant + "-javac")
        d8 = [bt / "d8", "--min-api", "34", "--lib", android, "--output", dex] + sorted(classes.rglob("*.class"))
        if kind == "provider": d8.append(bc)
        run(d8, variant + "-d8")
        unsigned = directory / "unsigned.apk"; shutil.copyfile(linked, unsigned)
        with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_STORED) as archive:
            for dexfile in sorted(dex.glob("classes*.dex")): archive.write(dexfile, dexfile.name)
        aligned = directory / "aligned.apk"
        run([bt / "zipalign", "-f", "4", unsigned, aligned], variant + "-zipalign")
        target = apks / (variant + ".apk")
        run([bt / "apksigner", "sign", "--ks", key_paths[key_label], "--ks-key-alias", "synthetic", "--ks-pass", "file:" + str(password), "--key-pass", "file:" + str(key_password), "--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--out", target, aligned], variant + "-sign")
        verified = run([bt / "apksigner", "verify", "--verbose", "--print-certs", target], variant + "-verify").decode()
        if certificates[key_label] not in verified:
            raise RuntimeError("apk_signer_mismatch")
        run([bt / "aapt2", "dump", "badging", target], variant + "-manifest-badging")
        run([bt / "aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", target], variant + "-manifest-tree")
        master = (fixture / "master.private").read_bytes()
        with zipfile.ZipFile(target) as archive:
            for member in archive.namelist():
                if "private" in member or master in archive.read(member):
                    raise RuntimeError("private_fixture_material_in_apk")
            if kind == "fixture" and hashlib.sha256(archive.read("assets/vault.hbv")).hexdigest() != expected["ciphertext_sha256"]:
                raise RuntimeError("apk_ciphertext_mismatch")
        receipt["artifacts"][variant] = {"path": str(target), "sha256": digest(target), "bytes": target.stat().st_size, "package": package, "signer_sha256": certificates[key_label], "generated_config_sha256": digest(config)}
    build("fixture", "fixture-good", GOOD_PACKAGE, "fixture-good")
    build("fixture", "fixture-wrong-certificate", GOOD_PACKAGE, "fixture-wrong")
    build("fixture", "fixture-wrong-package", DECOY_PACKAGE, "fixture-good")
    build("provider", "provider", PROVIDER_PACKAGE, "provider")
    receipt["source_files_after"] = inventory(source)
    if receipt["source_files_before"] != receipt["source_files_after"]:
        raise RuntimeError("source_changed_during_build")
    receipt["finished_unix_ns"] = time.time_ns()
    receipt["result"] = "build_and_host_interop_passed_device_not_run"
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"ok": True, "receipt": str(output / "receipt.json"), "receipt_sha256": digest(output / "receipt.json"), "crypto_interop": receipt["crypto_interop"], "artifacts": receipt["artifacts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
