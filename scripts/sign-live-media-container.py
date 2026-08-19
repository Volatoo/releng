#!/usr/bin/env python3

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


DIGEST = re.compile(r"^[0-9a-f]{64}$")
BUILD_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MANIFEST_FIELDS = {
    "schema", "channel", "init_system", "iso_file", "iso_size",
    "iso_sha256", "rootfs_sha256", "release_index_sha256",
    "installer_sha256", "release_key_sha256",
}
LIVE_INPUT_FIELDS = {
    "schema", "architecture", "channel", "build_id", "release_index",
    "installer", "keyring",
}
INDEX_BINDING_FIELDS = {"file", "size", "sha256", "format"}


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        fail(f"missing {name}")
    return value


def safe_file(path: Path, description: str, maximum: int) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} is not a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        fail(f"{description} size is outside the accepted range")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact(value: object, fields: set[str], description: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{description} fields are invalid")
    return value


def canonical_json(path: Path, description: str) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode(), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{description} is invalid JSON: {error}")
    if raw != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode():
        fail(f"{description} is not canonical JSON")
    return value, raw


def parse_manifest(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or "=" not in line:
            fail("live ISO manifest contains an invalid record")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            fail("live ISO manifest contains an invalid or duplicate field")
        values[key] = value
    if set(values) != MANIFEST_FIELDS:
        fail("live ISO manifest fields are invalid")
    return values


def artifact(path: Path, name: str, artifact_format: str) -> dict:
    return {
        "file": name,
        "format": artifact_format,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def main() -> None:
    channel = environment("CHANNEL")
    build_id = environment("BUILD_ID")
    init_system = environment("INIT_SYSTEM")
    iso_name = environment("ISO_NAME")
    host_uid = int(environment("HOST_UID"))
    host_gid = int(environment("HOST_GID"))
    if (
        not IDENTITY.fullmatch(channel)
        or not BUILD_ID.fullmatch(build_id)
        or init_system not in ("openrc", "systemd")
        or not IDENTITY.fullmatch(iso_name)
        or not iso_name.endswith(".iso")
    ):
        fail("live-media release identity is invalid")

    iso = Path("/input/live.iso")
    manifest_path = Path("/input/live.iso.manifest")
    public_key = Path("/signing/release.pub")
    secret_key = Path("/signing/release.sec")
    channel_root = Path(f"/input/publication/releases/amd64/channels/{channel}")
    index_path = channel_root / "index.json"
    index_signature = channel_root / "index.json.sig"
    live_inputs_path = channel_root / "live-media-inputs.json"
    live_inputs_signature = channel_root / "live-media-inputs.json.sig"
    for path, description, maximum in (
        (iso, "live ISO", 16 * 1024 * 1024 * 1024),
        (manifest_path, "live ISO manifest", 1024 * 1024),
        (public_key, "release public key", 1024 * 1024),
        (secret_key, "release secret key", 1024 * 1024),
        (index_path, "release index", 16 * 1024 * 1024),
        (index_signature, "release index signature", 1024 * 1024),
        (live_inputs_path, "live-media inputs", 1024 * 1024),
        (live_inputs_signature, "live-media inputs signature", 1024 * 1024),
    ):
        safe_file(path, description, maximum)

    for document, signature in (
        (index_path, index_signature),
        (live_inputs_path, live_inputs_signature),
    ):
        subprocess.run(
            ["signify", "-V", "-p", str(public_key), "-m", str(document),
             "-x", str(signature)],
            check=True,
        )

    live_inputs, _ = canonical_json(live_inputs_path, "live-media inputs")
    top = exact(live_inputs, LIVE_INPUT_FIELDS, "live-media inputs")
    binding = exact(top["release_index"], INDEX_BINDING_FIELDS, "release index binding")
    if (
        top["schema"] != "org.volatoo.live-media-inputs/v1"
        or top["architecture"] != "amd64"
        or top["channel"] != channel
        or top["build_id"] != build_id
        or binding.get("file") != "index.json"
        or binding.get("format") != "release-index-v1"
        or binding.get("size") != index_path.stat().st_size
        or binding.get("sha256") != sha256_file(index_path)
    ):
        fail("live-media inputs do not bind the selected release index")

    manifest = parse_manifest(manifest_path)
    try:
        manifest_size = int(manifest["iso_size"])
    except ValueError:
        fail("live ISO manifest size is invalid")
    keyring = top["keyring"]
    if not isinstance(keyring, list) or len(keyring) != 1 or not isinstance(keyring[0], dict):
        fail("live-media keyring is invalid")
    installer = top["installer"]
    if not isinstance(installer, dict):
        fail("live-media installer is invalid")
    if (
        manifest["schema"] != "org.volatoo.live-media/v1"
        or manifest["channel"] != channel
        or manifest["init_system"] != init_system
        or manifest["iso_file"] != iso_name
        or manifest_size != iso.stat().st_size
        or manifest["iso_sha256"] != sha256_file(iso)
        or manifest["release_index_sha256"] != binding["sha256"]
        or manifest["installer_sha256"] != installer.get("sha256")
        or manifest["release_key_sha256"] != keyring[0].get("sha256")
        or manifest["release_key_sha256"] != sha256_file(public_key)
        or any(not DIGEST.fullmatch(manifest[name]) for name in (
            "iso_sha256", "rootfs_sha256", "release_index_sha256",
            "installer_sha256", "release_key_sha256",
        ))
    ):
        fail("live ISO differs from its authenticated build inputs")

    document = {
        "schema": "org.volatoo.live-media-release/v1",
        "architecture": "amd64",
        "channel": channel,
        "build_id": build_id,
        "init_system": init_system,
        "iso": artifact(iso, iso_name, "iso9660-hybrid"),
        "build_manifest": artifact(
            manifest_path, iso_name + ".manifest", "live-media-manifest-v1"
        ),
        "release_index": artifact(index_path, "index.json", "release-index-v1"),
        "live_media_inputs": artifact(
            live_inputs_path, "live-media-inputs.json", "live-media-inputs-v1"
        ),
    }
    output = Path("/output/live-media.json")
    output.write_bytes(
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    signature = output.with_name("live-media.json.sig")
    subprocess.run(
        ["signify", "-S", "-s", str(secret_key), "-m", str(output),
         "-x", str(signature)],
        check=True,
    )
    subprocess.run(
        ["signify", "-V", "-p", str(public_key), "-m", str(output),
         "-x", str(signature)],
        check=True,
    )
    os.chmod(output, 0o644)
    os.chmod(signature, 0o644)
    os.chown(output, host_uid, host_gid)
    os.chown(signature, host_uid, host_gid)
    print("signed authenticated live-media release descriptor")


if __name__ == "__main__":
    main()
