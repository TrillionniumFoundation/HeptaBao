#!/usr/bin/env python3
"""Build the permission-only fixture revision while reusing exact r7 provider bytes.

This offline QA builder does not install APKs, grant permissions, create new signing
identities, or qualify Credential Manager. Its signing inputs are existing private
synthetic r7 test files, passed to SDK tools by file path rather than by value.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import time
import zipfile

BASE_RECEIPT_SHA = "e12bd68de3c606e03ce22a7a688ebb90c7b6ec4a951d15e5be233339e698042b"
PROVIDER_SHA = "b16e82916330fac6909f82696089798c3ec76d7b4058fe9290e7e841b9e00459"
FIXTURE_CERT = "cb684e07720b0233e9aa87bc74e87cf40956476770dabc2a426bee30dcba6135"
MANIFEST_SHA = "280f1318abd1e2cf14bc83fda266dc75bf9058bce53e65c37d77a7041b524673"
PERMISSION = "android.permission.CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS"
PERMISSION_LINE = b'    <uses-permission android:name="' + PERMISSION.encode() + b'"/>\n'
PROVIDER = "org.heptabao.passkey.preview"
FIXTURE = "org.heptabao.passkey.fixture"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, private=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
            or (private and stat.S_IMODE(info.st_mode) != 0o600)):
        raise RuntimeError("unsafe_regular_input")


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError("symlink_source")
        if stat.S_ISREG(info.st_mode):
            regular(path)
            result[str(path.relative_to(root))] = digest(path)
        elif not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("special_source")
    return result


def durable_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "sdk", "java-home", "base-build", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    source, sdk, jdk, base, output = [p.absolute() for p in
        (args.source, args.sdk, args.java_home, args.base_build, args.output)]
    os.umask(0o077)
    base_receipt = base / "receipt.json"
    regular(base_receipt)
    if digest(base_receipt) != BASE_RECEIPT_SHA:
        raise RuntimeError("base_receipt_mismatch")
    prior = json.loads(base_receipt.read_bytes())
    before = inventory(source)
    expected = dict(prior["source_files_after"])
    expected["fixture/AndroidManifest.xml"] = MANIFEST_SHA
    if before != expected or prior["source_files_before"] != prior["source_files_after"]:
        raise RuntimeError("source_not_exact_permission_only_revision")
    manifest_path = source / "fixture/AndroidManifest.xml"
    manifest_bytes = manifest_path.read_bytes()
    if (manifest_bytes.count(PERMISSION_LINE) != 1 or
            hashlib.sha256(manifest_bytes.replace(PERMISSION_LINE, b"", 1)).hexdigest()
            != prior["source_files_after"]["fixture/AndroidManifest.xml"]):
        raise RuntimeError("manifest_diff_mismatch")
    private = base / "private"
    info = private.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("unsafe_signing_directory")
    password, key_password = private / "signing.pass", private / "key.pass"
    keys = {label: private / (label + ".p12") for label in ("fixture", "wrong-cert")}
    for path in (password, key_password, *keys.values()):
        regular(path, private=True)
    certs = {label: digest(private / (label + ".der")) for label in ("fixture", "wrong-cert")}
    if certs["fixture"] != FIXTURE_CERT or certs["wrong-cert"] != prior["artifacts"]["fixture-wrong-cert"]["certificate_sha256"]:
        raise RuntimeError("base_certificate_mismatch")
    provider = base / "apks/provider.apk"
    regular(provider)
    if digest(provider) != PROVIDER_SHA or prior["artifacts"]["provider"]["sha256"] != PROVIDER_SHA:
        raise RuntimeError("base_provider_mismatch")
    output.mkdir(mode=0o700, exist_ok=False)
    fd = os.open(output.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    logs, apks = output / "logs", output / "apks"
    logs.mkdir(mode=0o700)
    apks.mkdir(mode=0o700)
    android, bt = sdk / "platforms/android-34/android.jar", sdk / "build-tools/34.0.0"
    env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin")
    receipt = {"schema": 1, "purpose": "synthetic_permission_only_fixture_rebuild", "source_files_before": before,
        "build_script_sha256": digest(Path(__file__).absolute()), "platform": platform.platform(),
        "started_unix_ns": time.time_ns(), "commands": [], "artifacts": {},
        "base_provider_build": {"receipt_path": str(base_receipt), "receipt_sha256": BASE_RECEIPT_SHA,
            "provider_sha256": PROVIDER_SHA, "provider_recompiled": False},
        "fixture_certificate_sha256": FIXTURE_CERT,
        "native_origin": "android:apk-key-hash:" + base64.urlsafe_b64encode(bytes.fromhex(FIXTURE_CERT)).decode().rstrip("="),
        "no_adb": True, "device_qualification": False, "credential_manager_exercised": False}

    def run(argv, label):
        start = time.time_ns()
        result = subprocess.run([str(v) for v in argv], env=env, capture_output=True, check=False)
        stdout, stderr = logs / (label + ".stdout"), logs / (label + ".stderr")
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        receipt["commands"].append({"label": label, "argv": [str(v) for v in argv], "started_unix_ns": start,
            "finished_unix_ns": time.time_ns(), "exit_code": result.returncode,
            "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})
        if result.returncode:
            durable_json(output / "receipt.failed.json", receipt)
            raise RuntimeError("build_failed_" + label)
        return result.stdout

    for binary, arguments, label in ((jdk / "bin/java", ["-version"], "java"),
            (jdk / "bin/javac", ["-version"], "javac"), (bt / "aapt2", ["version"], "aapt2"),
            (bt / "d8", ["--version"], "d8"), (bt / "apksigner", ["version"], "apksigner")):
        run([binary] + arguments, label + "-version")
    receipt["tool_files"] = {str(path): digest(path) for path in
        (android, jdk / "bin/java", jdk / "bin/javac", bt / "aapt2", bt / "lib/d8.jar", bt / "lib/apksigner.jar", bt / "zipalign")}
    if receipt["tool_files"] != prior["tool_files"]:
        raise RuntimeError("toolchain_changed")
    target = apks / "provider.apk"
    shutil.copyfile(provider, target)
    verification = run([bt / "apksigner", "verify", "--verbose", "--print-certs", target], "reused-provider-verify").decode()
    if digest(target) != PROVIDER_SHA or prior["artifacts"]["provider"]["certificate_sha256"] not in verification:
        raise RuntimeError("reused_provider_changed")
    receipt["artifacts"]["provider"] = dict(prior["artifacts"]["provider"], path=str(target), reused_exact_bytes=True)
    durable_json(output / "fixture.public.json", {"schema": 1, "fixture_package": FIXTURE,
        "certificate_sha256": FIXTURE_CERT, "native_origin": receipt["native_origin"], "rp_id": "passkeys.heptabao.test"})

    def build(variant, package, key_label):
        directory = output / variant
        directory.mkdir()
        generated, classes, dex = directory / "generated", directory / "classes", directory / "dex"
        for path in (generated, classes, dex):
            path.mkdir()
        manifest = manifest_bytes.decode().replace("@@PACKAGE@@", package).replace("@@LABEL@@", "HeptaBao " + variant)
        (directory / "AndroidManifest.xml").write_text(manifest)
        resources, assets = directory / "resources.zip", directory / "assets"
        run([bt / "aapt2", "compile", "--dir", source / "fixture/res", "-o", resources], variant + "-resources")
        assets.mkdir()
        for name in ("NOTICE", "LICENSE-APACHE-2.0.txt"):
            shutil.copyfile(source / name, assets / name)
        linked = directory / "linked.apk"
        run([bt / "aapt2", "link", "-I", android, "--manifest", directory / "AndroidManifest.xml", "--java", generated,
            "--custom-package", FIXTURE, "--min-sdk-version", "34", "--target-sdk-version", "34", "-A", assets,
            "-o", linked, resources], variant + "-link")
        common = [path for path in sorted((source / "common/java").rglob("*.java")) if path.name not in ("Hbv.java", "Passkey.java")]
        sources = common + sorted((source / "fixture/java").rglob("*.java")) + sorted(generated.rglob("*.java"))
        run([jdk / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-cp", android, "-d", classes] + sources, variant + "-javac")
        run([bt / "d8", "--min-api", "34", "--lib", android, "--output", dex] + sorted(classes.rglob("*.class")), variant + "-d8")
        unsigned, aligned = directory / "unsigned.apk", directory / "aligned.apk"
        shutil.copyfile(linked, unsigned)
        with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(dex.glob("classes*.dex")):
                archive.write(path, path.name)
        run([bt / "zipalign", "-f", "4", unsigned, aligned], variant + "-align")
        target = apks / (variant + ".apk")
        run([bt / "apksigner", "sign", "--ks", keys[key_label], "--ks-key-alias", "synthetic",
            "--ks-pass", "file:" + str(password), "--key-pass", "file:" + str(key_password),
            "--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
            "--v4-signing-enabled", "false", "--out", target, aligned], variant + "-sign")
        verification = run([bt / "apksigner", "verify", "--verbose", "--print-certs", target], variant + "-verify").decode()
        if certs[key_label] not in verification:
            raise RuntimeError("signer_mismatch")
        badging = run([bt / "aapt2", "dump", "badging", target], variant + "-badging").decode()
        xmltree = run([bt / "aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", target], variant + "-manifest").decode()
        if "uses-permission: name='" + PERMISSION + "'" not in badging or PERMISSION not in xmltree:
            raise RuntimeError("compiled_permission_missing")
        with zipfile.ZipFile(target) as archive:
            if any(name.endswith((".p12", ".private", ".pass", ".hbv")) for name in archive.namelist()):
                raise RuntimeError("private_material_in_apk")
        receipt["artifacts"][variant] = {"path": str(target), "package": package, "sha256": digest(target),
            "bytes": target.stat().st_size, "certificate_sha256": certs[key_label],
            "compiled_allowed_provider_permission_verified": True}

    build("fixture-good", FIXTURE, "fixture")
    build("fixture-wrong-cert", FIXTURE, "wrong-cert")
    build("fixture-wrong-package", "org.heptabao.passkey.decoy", "fixture")
    receipt["source_files_after"] = inventory(source)
    if receipt["source_files_before"] != receipt["source_files_after"] or digest(provider) != PROVIDER_SHA or digest(base_receipt) != BASE_RECEIPT_SHA:
        raise RuntimeError("source_or_base_changed")
    receipt["finished_unix_ns"] = time.time_ns()
    receipt["result"] = "fixture_apk_build_only_no_device_qualification"
    durable_json(output / "receipt.json", receipt)
    print(json.dumps({"ok": True, "receipt": str(output / "receipt.json"), "sha256": digest(output / "receipt.json"),
        "artifacts": receipt["artifacts"], "credential_manager_exercised": False}, sort_keys=True))


if __name__ == "__main__":
    main()
