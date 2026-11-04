#!/usr/bin/env python3
"""Build the EasyVpn APK using the Android SDK and JDK, without Gradle."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "android" / "build"
APP = ROOT / "android" / "app" / "src" / "main"
CORES = ROOT / "android" / "cores"


def version_key(path):
    return tuple(int(part) for part in re.findall(r"\d+", path.name))


def newest(directory, predicate):
    candidates = [
        path for path in directory.iterdir()
        if path.is_dir() and predicate(path)
    ] if directory.is_dir() else []
    if not candidates:
        raise RuntimeError("No suitable version found in " + str(directory))
    return max(candidates, key=version_key)


def tool(directory, name):
    suffixes = [".exe", ".bat", ".cmd", ""] if os.name == "nt" else [""]
    for suffix in suffixes:
        path = directory / (name + suffix)
        if path.is_file():
            return path
    raise RuntimeError("Missing tool: " + str(directory / name))


def command_text(command):
    return subprocess.list2cmdline([str(arg) for arg in command])


def run(command, env):
    command = [str(arg) for arg in command]
    print("+ " + command_text(command), flush=True)
    actual = command
    if os.name == "nt" and Path(command[0]).suffix.lower() in (".bat", ".cmd"):
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        # Pass the complete cmd invocation as a string: passing a list would
        # make subprocess re-quote the /c payload with incompatible escaping.
        # Dollar signs in Java class names are literal in cmd, not expansions.
        actual = f'"{comspec}" /d /s /c "{command_text(command)}"'
    try:
        result = subprocess.run(
            actual, cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", check=False,
        )
    except OSError as error:
        raise RuntimeError(
            "Failed command: " + command_text(command) + "\n" + str(error)
        ) from error
    if result.stdout:
        # Signing tools must not leak credentials through diagnostic output.
        output = result.stdout
        secrets = [
            env.get("EASYVPN_KS_PASS", ""),
            env.get("EASYVPN_KEY_PASS", ""),
        ]
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                output = output.replace(secret, "[REDACTED]")
        print(output, end="" if output.endswith("\n") else "\n")
    if result.returncode != 0:
        raise RuntimeError(
            "Command exited with code {}: {}".format(
                result.returncode, command_text(command)
            )
        )


def clean_directory(path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def locate_environment():
    sdk = Path(os.environ.get(
        "ANDROID_HOME", r"E:\2-Sources\AndroidSdk"
    )).expanduser().resolve()
    if not sdk.is_dir():
        raise RuntimeError("Android SDK not found: " + str(sdk))

    build_tools = newest(sdk / "build-tools", lambda path: True)
    platform = sdk / "platforms" / "android-35"
    if not (platform / "android.jar").is_file():
        platform = newest(
            sdk / "platforms",
            lambda path: (path / "android.jar").is_file()
            and path.name.startswith("android-"),
        )

    ndk_value = os.environ.get("ANDROID_NDK_HOME")
    if ndk_value:
        ndk = Path(ndk_value).expanduser().resolve()
    else:
        ndk = newest(sdk / "ndk", lambda path: path.name.startswith("28."))
    if not ndk.is_dir():
        raise RuntimeError("Android NDK not found: " + str(ndk))

    java_home = Path(os.environ.get(
        "JAVA_HOME", r"C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot"
    )).expanduser().resolve()
    java_bin = java_home / "bin"
    javac = tool(java_bin, "javac")
    keytool = tool(java_bin, "keytool")

    env = os.environ.copy()
    env["ANDROID_HOME"] = str(sdk)
    env["ANDROID_SDK_ROOT"] = str(sdk)
    env["ANDROID_NDK_HOME"] = str(ndk)
    env["ANDROID_NDK_ROOT"] = str(ndk)
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = os.pathsep.join([
        str(java_bin),
        str(Path.home() / ".cargo" / "bin"),
        str(build_tools),
        str(sdk / "platform-tools"),
        env.get("PATH", ""),
    ])
    cargo = shutil.which("cargo", path=env["PATH"])
    if cargo is None:
        raise RuntimeError("cargo not found; install Rust and cargo-ndk")
    return sdk, build_tools, platform / "android.jar", javac, keytool, cargo, env


def signing_config(args, env):
    """Return the keystore, alias and a private subprocess environment."""
    signing_env = env.copy()
    properties_path = ROOT / "android" / "keystore" / "keystore.properties"
    if args.keystore_props:
        properties_path = Path(args.keystore_props).expanduser().resolve()

    if not args.debug and (args.keystore_props or properties_path.exists()):
        if not properties_path.is_file():
            raise RuntimeError(
                "Keystore properties not found: " + str(properties_path)
            )
        properties = {}
        for line in properties_path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "!")):
                continue
            key, separator, value = line.partition("=")
            if separator:
                properties[key.strip()] = value.strip()

        required = ("storeFile", "keyAlias", "storePassword", "keyPassword")
        for key in required:
            if not properties.get(key):
                raise RuntimeError(
                    "Missing or empty property '{}' in {}".format(
                        key, properties_path
                    )
                )

        keystore = Path(properties["storeFile"]).expanduser()
        if not keystore.is_absolute():
            keystore = properties_path.parent / keystore
        keystore = keystore.resolve()
        if not keystore.is_file():
            raise RuntimeError("Keystore not found: " + str(keystore))

        signing_env["EASYVPN_KS_PASS"] = properties["storePassword"]
        signing_env["EASYVPN_KEY_PASS"] = properties["keyPassword"]
        return keystore, properties["keyAlias"], signing_env

    signing_env["EASYVPN_KS_PASS"] = "android"
    signing_env["EASYVPN_KEY_PASS"] = "android"
    return (
        Path.home() / ".android" / "debug.keystore",
        "androiddebugkey",
        signing_env,
    )


def build(args):
    sdk, build_tools, android_jar, javac, keytool, cargo, env = locate_environment()
    abis = ["arm64-v8a", "x86_64"] if args.abi == "all" else [args.abi]
    output = Path(args.release_name).expanduser()
    if not output.is_absolute():
        output = ROOT / output
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    # Clean intermediates to avoid including classes or ABIs from an earlier build.
    jni_libs = BUILD / "jniLibs"
    classes = BUILD / "classes"
    dex = BUILD / "dex"
    for directory in (jni_libs, classes, dex):
        clean_directory(directory)

    for abi in abis:
        for name in ("libxray.so", "libsingbox.so", "libmihomo.so"):
            path = CORES / abi / name
            if not path.is_file():
                raise RuntimeError("Missing bundled core: " + str(path))
    for name in ("geoip.dat", "geosite.dat"):
        path = CORES / "assets" / name
        if not path.is_file():
            raise RuntimeError("Missing core asset: " + str(path))

    cargo_command = [cargo, "ndk"]
    for abi in abis:
        cargo_command.extend(["-t", abi])
    cargo_command.extend([
        "-P", "26", "-o", jni_libs,
        "build", "--release", "-p", "easyvpn-android",
    ])
    run(cargo_command, env)

    for abi in abis:
        destination = jni_libs / abi
        destination.mkdir(parents=True, exist_ok=True)
        for source in sorted((CORES / abi).glob("*.so")):
            if source.name == "libeasyvpn.so":
                raise RuntimeError("Bundled cores must not overwrite libeasyvpn.so")
            shutil.copy2(source, destination / source.name)
        if not (destination / "libeasyvpn.so").is_file():
            raise RuntimeError("cargo-ndk did not produce libeasyvpn.so for " + abi)

    # Generate R.java as part of resource linking, then compile it with the shim.
    resource_zip = BUILD / "res.zip"
    base_apk = BUILD / "base.apk"
    generated = BUILD / "generated"
    clean_directory(generated)
    for path in (resource_zip, base_apk):
        if path.exists():
            path.unlink()
    aapt2 = tool(build_tools, "aapt2")
    run([aapt2, "compile", "--dir", APP / "res", "-o", resource_zip], env)
    run([
        aapt2, "link", "-I", android_jar,
        "--manifest", APP / "AndroidManifest.xml",
        "-A", CORES / "assets",
        "--min-sdk-version", "26", "--target-sdk-version", "35",
        "--java", generated, "-o", base_apk, resource_zip,
    ], env)

    sources = sorted((APP / "java").rglob("*.java"))
    sources.extend(sorted(generated.rglob("*.java")))
    if not sources:
        raise RuntimeError("No Java sources found")
    run([
        javac, "--release", "8", "-encoding", "UTF-8",
        "-classpath", android_jar, "-d", classes,
    ] + sources, env)

    class_files = sorted(classes.rglob("*.class"))
    if not class_files:
        raise RuntimeError("javac produced no classes")
    run([
        tool(build_tools, "d8"), "--release", "--lib", android_jar,
        "--min-api", "26", "--output", dex,
    ] + class_files, env)

    dex_files = sorted(dex.glob("classes*.dex"))
    if not dex_files:
        raise RuntimeError("d8 produced no dex files")
    with zipfile.ZipFile(base_apk, "a", compression=zipfile.ZIP_DEFLATED) as apk:
        for path in dex_files:
            apk.write(path, path.name)
        for abi in abis:
            for path in sorted((jni_libs / abi).glob("*.so")):
                apk.write(path, "lib/{}/{}".format(abi, path.name))

    aligned = BUILD / "aligned.apk"
    run([
        tool(build_tools, "zipalign"), "-P", "16", "-f", "4",
        base_apk, aligned,
    ], env)

    keystore, alias, signing_env = signing_config(args, env)
    keystore.parent.mkdir(parents=True, exist_ok=True)
    if not keystore.is_file():
        run([
            keytool, "-genkeypair", "-keystore", keystore,
            "-storepass:env", "EASYVPN_KS_PASS",
            "-keypass:env", "EASYVPN_KEY_PASS",
            "-alias", alias, "-dname", "CN=Android Debug",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-noprompt",
        ], signing_env)

    print("Signing keystore: {} (alias: {})".format(keystore, alias))
    apksigner = tool(build_tools, "apksigner")
    run([
        apksigner, "sign", "--ks", keystore,
        "--ks-key-alias", alias,
        "--ks-pass", "env:EASYVPN_KS_PASS",
        "--key-pass", "env:EASYVPN_KEY_PASS",
        "--out", output, aligned,
    ], signing_env)
    run([apksigner, "verify", "--verbose", output], env)
    print("APK written to " + str(output))

    if args.install:
        run([tool(sdk / "platform-tools", "adb"), "install", "-r", output], env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--abi", choices=["arm64-v8a", "x86_64", "all"], default="all"
    )
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--release-name", default="dist/EasyVpn.apk")
    parser.add_argument(
        "--keystore-props",
        help="Signing properties file (default: android/keystore/keystore.properties)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Force signing with the debug keystore",
    )
    args = parser.parse_args()
    try:
        build(args)
    except (RuntimeError, OSError, UnicodeError, zipfile.BadZipFile) as error:
        print("error: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
