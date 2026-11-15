#!/usr/bin/env python3
"""Offline APK builder for the isolated native Android Passkey preview.

No device operations, production signing key, Gradle daemon or dependency fetch.
Supply the explicitly pinned SDK/JDK and BC jar. Build output must be a new root.
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
PROVIDER = "org.heptabao.passkey.preview"
FIXTURE = "org.heptabao.passkey.fixture"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "sdk", "java-home", "bc-jar", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, sdk, jdk, bc, output = [p.resolve() for p in (args.source, args.sdk, args.java_home, args.bc_jar, args.output)]
    if digest(bc) != BC_SHA256:
        raise RuntimeError("dependency_digest_mismatch")
    os.umask(0o077)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private = output / "private"; private.mkdir(mode=0o700)
    logs = output / "logs"; logs.mkdir(mode=0o700)
    apks = output / "apks"; apks.mkdir(mode=0o700)
    android = sdk / "platforms/android-34/android.jar"
    bt = sdk / "build-tools/34.0.0"
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin")
    receipt = {"schema": 1, "purpose": "synthetic_native_passkey_apk_build", "source_files_before": inventory(source),
               "build_script_sha256": digest(Path(__file__).resolve()), "platform": platform.platform(),
               "started_unix_ns": time.time_ns(), "dependency_sha256": BC_SHA256, "commands": [], "artifacts": {}}

    def run(argv, label, cwd=None):
        start = time.time_ns()
        result = subprocess.run([str(v) for v in argv], cwd=cwd, env=env, capture_output=True, check=False)
        stdout, stderr = logs / (label + ".stdout"), logs / (label + ".stderr")
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        receipt["commands"].append({"label": label, "argv": [str(v) for v in argv], "started_unix_ns": start,
            "finished_unix_ns": time.time_ns(), "exit_code": result.returncode, "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
        if result.returncode:
            (output / "receipt.failed.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
            raise RuntimeError("build_failed_" + label)
        return result.stdout

    for binary, arguments, label in ((jdk / "bin/java", ["-version"], "java"), (jdk / "bin/javac", ["-version"], "javac"),
            (bt / "aapt2", ["version"], "aapt2"), (bt / "d8", ["--version"], "d8"), (bt / "apksigner", ["version"], "apksigner")):
        run([binary] + arguments, label + "-version")
    receipt["tool_files"] = {str(path): digest(path) for path in (android, jdk / "bin/java", jdk / "bin/javac", bt / "aapt2", bt / "lib/d8.jar", bt / "lib/apksigner.jar", bt / "zipalign")}
    license_text = run([jdk / "bin/java", "-cp", bc, "org.bouncycastle.LICENSE"], "bc-license")
    password = private / "signing.pass"; key_password = private / "key.pass"
    password.write_text(secrets.token_urlsafe(32) + "\n"); key_password.write_bytes(password.read_bytes())
    keys = {}; certs = {}
    for label in ("provider", "fixture", "wrong-cert"):
        key, cert = private / (label + ".p12"), private / (label + ".der")
        run([jdk / "bin/keytool", "-genkeypair", "-alias", "synthetic", "-keyalg", "RSA", "-keysize", "3072", "-validity", "30",
             "-dname", "CN=HeptaBao Passkey synthetic " + label, "-keystore", key, "-storetype", "PKCS12", "-storepass:file", password,
             "-keypass:file", key_password, "-noprompt"], "keygen-" + label)
        run([jdk / "bin/keytool", "-exportcert", "-alias", "synthetic", "-keystore", key, "-storepass:file", password, "-file", cert], "cert-" + label)
        keys[label] = key; certs[label] = digest(cert)
    receipt["fixture_certificate_sha256"] = certs["fixture"]
    receipt["native_origin"] = "android:apk-key-hash:" + __import__("base64").urlsafe_b64encode(bytes.fromhex(certs["fixture"])).decode().rstrip("=")
    (output / "fixture.public.json").write_text(json.dumps({"schema": 1, "fixture_package": FIXTURE, "certificate_sha256": certs["fixture"], "native_origin": receipt["native_origin"], "rp_id": "passkeys.heptabao.test"}, sort_keys=True, indent=2) + "\n")

    def build(kind, variant, package, key_label):
        directory = output / variant; directory.mkdir()
        generated = directory / "generated"; generated.mkdir()
        classes = directory / "classes"; classes.mkdir()
        dex = directory / "dex"; dex.mkdir()
        manifest = (source / kind / "AndroidManifest.xml").read_text().replace("@@PACKAGE@@", package).replace("@@LABEL@@", "HeptaBao " + variant)
        (directory / "AndroidManifest.xml").write_text(manifest)
        namespace = PROVIDER if kind == "provider" else FIXTURE
        resources = directory / "resources.zip"
        run([bt / "aapt2", "compile", "--dir", source / kind / "res", "-o", resources], variant + "-resources")
        assets = directory / "assets"; assets.mkdir()
        shutil.copyfile(source / "NOTICE", assets / "NOTICE")
        shutil.copyfile(source / "LICENSE-APACHE-2.0.txt", assets / "LICENSE-APACHE-2.0.txt")
        if kind == "provider": (assets / "bouncycastle-LICENSE.txt").write_bytes(license_text)
        linked = directory / "linked.apk"
        run([bt / "aapt2", "link", "-I", android, "--manifest", directory / "AndroidManifest.xml", "--java", generated,
             "--custom-package", namespace, "--min-sdk-version", "34", "--target-sdk-version", "34", "-A", assets, "-o", linked, resources], variant + "-link")
        if kind == "provider":
            config = generated / "org/heptabao/passkey/preview/BuildConfig.java"; config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text("package " + PROVIDER + ";\nfinal class BuildConfig { static final String FIXTURE_CERT_SHA256 = " + json.dumps(certs["fixture"]) + "; }\n")
        common = sorted((source / "common/java").rglob("*.java"))
        if kind != "provider": common = [path for path in common if path.name not in ("Hbv.java", "Passkey.java")]
        sources = common + sorted((source / kind / "java").rglob("*.java")) + sorted(generated.rglob("*.java"))
        classpath = str(android) + (os.pathsep + str(bc) if kind == "provider" else "")
        run([jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp", classpath, "-d", classes] + sources, variant + "-javac")
        dex_args = [bt / "d8", "--min-api", "34", "--lib", android, "--output", dex] + sorted(classes.rglob("*.class"))
        if kind == "provider": dex_args.append(bc)
        run(dex_args, variant + "-d8")
        unsigned = directory / "unsigned.apk"; shutil.copyfile(linked, unsigned)
        with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(dex.glob("classes*.dex")): archive.write(path, path.name)
        aligned = directory / "aligned.apk"; run([bt / "zipalign", "-f", "4", unsigned, aligned], variant + "-align")
        target = apks / (variant + ".apk")
        run([bt / "apksigner", "sign", "--ks", keys[key_label], "--ks-key-alias", "synthetic", "--ks-pass", "file:" + str(password), "--key-pass", "file:" + str(key_password),
             "--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--out", target, aligned], variant + "-sign")
        verification = run([bt / "apksigner", "verify", "--verbose", "--print-certs", target], variant + "-verify").decode()
        if certs[key_label] not in verification: raise RuntimeError("signer_mismatch")
        run([bt / "aapt2", "dump", "badging", target], variant + "-badging")
        run([bt / "aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", target], variant + "-manifest")
        with zipfile.ZipFile(target) as archive:
            for name in archive.namelist():
                if name.endswith((".p12", ".private", ".pass", ".hbv")):
                    raise RuntimeError("private_material_in_apk")
        receipt["artifacts"][variant] = {"path": str(target), "package": package, "sha256": digest(target), "bytes": target.stat().st_size, "certificate_sha256": certs[key_label]}

    build("provider", "provider", PROVIDER, "provider")
    build("fixture", "fixture-good", FIXTURE, "fixture")
    build("fixture", "fixture-wrong-cert", FIXTURE, "wrong-cert")
    build("fixture", "fixture-wrong-package", "org.heptabao.passkey.decoy", "fixture")
    receipt["source_files_after"] = inventory(source)
    if receipt["source_files_before"] != receipt["source_files_after"]: raise RuntimeError("source_changed")
    receipt["finished_unix_ns"] = time.time_ns(); receipt["result"] = "apk_build_only_no_device_qualification"
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"ok": True, "receipt": str(output / "receipt.json"), "sha256": digest(output / "receipt.json"), "artifacts": receipt["artifacts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
