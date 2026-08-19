#!/usr/bin/env python3

import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile


MANIFEST_FIELDS = {
    "schema", "channel", "init_system", "disk_file", "disk_size",
    "disk_sha256", "kernel_sha256", "initramfs_sha256", "rootfs_sha256",
    "state_sha256", "secure_boot", "secure_boot_cert_sha256", "uki_sha256",
}
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
BUILD_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
INSTALLER_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
MAX_INSTALLER_SIZE = 64 * 1024 * 1024


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        fail(f"missing {name}")
    return value


def timestamp(name: str) -> datetime.datetime:
    value = environment(name)
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        fail(f"{name} is not canonical UTC RFC3339")
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def safe_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{description} is not a regular non-symlink file")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_installer(path: Path) -> None:
    safe_file(path, "installer")
    size = path.stat().st_size
    if size < 64 or size > MAX_INSTALLER_SIZE:
        fail("installer size is outside the accepted range")
    with path.open("rb") as executable:
        header = executable.read(64)
        if (
            header[:4] != b"\x7fELF"
            or header[4] != 2
            or header[5] != 1
            or header[6] != 1
        ):
            fail("installer is not a little-endian ELF64 executable")
        if struct.unpack_from("<H", header, 16)[0] not in (2, 3):
            fail("installer ELF type is not executable")
        if struct.unpack_from("<H", header, 18)[0] != 62:
            fail("installer is not an amd64 executable")
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        program_entry_size = struct.unpack_from("<H", header, 54)[0]
        program_count = struct.unpack_from("<H", header, 56)[0]
        if (
            program_entry_size < 56
            or program_count == 0
            or program_count > 128
            or program_offset > size
            or program_count > (size - program_offset) // program_entry_size
        ):
            fail("installer has an invalid ELF program-header table")
        executable.seek(program_offset)
        for _ in range(program_count):
            program_header = executable.read(program_entry_size)
            if len(program_header) != program_entry_size:
                fail("installer ELF program-header table is truncated")
            if struct.unpack_from("<I", program_header, 0)[0] == 3:
                fail("installer is dynamically linked")


def write_json(path: Path, document: dict) -> None:
    path.write_bytes(
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    os.chmod(path, 0o644)


def sign_and_verify(path: Path, secret_key: Path, public_key: Path) -> Path:
    signature_path = path.with_name(path.name + ".sig")
    subprocess.run(
        [
            "signify", "-S", "-s", str(secret_key), "-m", str(path),
            "-x", str(signature_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            "signify", "-V", "-p", str(public_key), "-m", str(path),
            "-x", str(signature_path),
        ],
        check=True,
    )
    os.chmod(signature_path, 0o644)
    return signature_path


def parse_manifest(path: Path, expected_init: str, channel: str) -> dict[str, str]:
    safe_file(path, f"{expected_init} manifest")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or "=" not in line:
            fail(f"{expected_init} manifest contains an invalid record")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            fail(f"{expected_init} manifest contains an invalid or duplicate field")
        values[key] = value
    if set(values) != MANIFEST_FIELDS:
        fail(f"{expected_init} manifest fields differ from release-media v2")
    if (
        values["schema"] != "org.volatoo.release-media/v2"
        or values["channel"] != channel
    ):
        fail(f"{expected_init} manifest schema or channel differs")
    if (
        values["init_system"] != expected_init
        or not IDENTITY.fullmatch(values["disk_file"])
        or not values["disk_file"].endswith(".img")
    ):
        fail(f"{expected_init} manifest target identity is invalid")
    try:
        disk_size = int(values["disk_size"])
    except ValueError:
        fail(f"{expected_init} manifest disk size is invalid")
    if disk_size <= 0:
        fail(f"{expected_init} manifest disk size is invalid")
    for name in (
        "disk_sha256", "kernel_sha256", "initramfs_sha256", "rootfs_sha256",
        "state_sha256",
    ):
        if not DIGEST.fullmatch(values[name]):
            fail(f"{expected_init} manifest {name} is invalid")
    if values["secure_boot"] == "yes":
        if not DIGEST.fullmatch(
            values["secure_boot_cert_sha256"]
        ) or not DIGEST.fullmatch(values["uki_sha256"]):
            fail(f"{expected_init} Secure Boot provenance is invalid")
    elif values["secure_boot"] == "no":
        if (
            values["secure_boot_cert_sha256"] != "none"
            or values["uki_sha256"] != "none"
        ):
            fail(f"{expected_init} unsigned manifest claims Secure Boot provenance")
    else:
        fail(f"{expected_init} secure_boot is invalid")
    return values


def verify_archive(archive: Path, manifest: dict[str, str], expected_init: str) -> None:
    safe_file(archive, f"{expected_init} archive")
    with tempfile.TemporaryFile() as stderr_file:
        command = subprocess.Popen(
            ["zstd", "--decompress", "--stdout", "--no-progress", "--", str(archive)],
            stdout=subprocess.PIPE,
            stderr=stderr_file,
        )
        assert command.stdout is not None
        digest = hashlib.sha256()
        size = 0
        while chunk := command.stdout.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if size > int(manifest["disk_size"]):
                command.kill()
                command.wait()
                fail(f"{expected_init} archive expands beyond its manifest size")
        command.wait()
        if command.returncode != 0:
            stderr_file.seek(0)
            stderr = stderr_file.read().decode(errors="replace").strip()
            fail(f"{expected_init} archive decompression failed: {stderr}")
    if (
        size != int(manifest["disk_size"])
        or digest.hexdigest() != manifest["disk_sha256"]
    ):
        fail(f"{expected_init} archive does not reproduce its manifest disk")


def copy_object(source: Path, output: Path, digest: str) -> str:
    destination = output / "objects" / "sha256" / digest[:2] / digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256_file(destination) != digest:
            fail(f"content-addressed object collision for {digest}")
    else:
        temporary = destination.with_name(destination.name + ".new")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o644)
        if sha256_file(temporary) != digest:
            fail(f"object changed while copying {source.name}")
        os.replace(temporary, destination)
    return f"../../../../objects/sha256/{digest[:2]}/{digest}"


def target(output: Path, channel: str, build_id: str, init_system: str) -> dict:
    archive = Path(f"/input/{init_system}.img.zst")
    manifest_path = Path(f"/input/{init_system}.img.manifest")
    manifest = parse_manifest(manifest_path, init_system, channel)
    verify_archive(archive, manifest, init_system)
    archive_digest = sha256_file(archive)
    manifest_digest = sha256_file(manifest_path)
    return {
        "id": f"{build_id}-{init_system}-amd64",
        "architecture": "amd64",
        "init_system": init_system,
        "archive": {
            "url": copy_object(archive, output, archive_digest),
            "size": archive.stat().st_size,
            "sha256": archive_digest,
            "format": "zstd",
        },
        "manifest": {
            "url": copy_object(manifest_path, output, manifest_digest),
            "size": manifest_path.stat().st_size,
            "sha256": manifest_digest,
            "format": "release-media-v2",
        },
        "disk": {
            "file": manifest["disk_file"],
            "size": int(manifest["disk_size"]),
            "sha256": manifest["disk_sha256"],
            "format": "raw-gpt",
        },
    }


def live_media_inputs(
    output: Path,
    installer: Path,
    installer_version: str,
    public_key: Path,
    index_path: Path,
    channel: str,
    build_id: str,
) -> dict:
    validate_installer(installer)
    installer_digest = sha256_file(installer)
    public_key_digest = sha256_file(public_key)
    return {
        "schema": "org.volatoo.live-media-inputs/v1",
        "architecture": "amd64",
        "channel": channel,
        "build_id": build_id,
        "release_index": {
            "file": "index.json",
            "size": index_path.stat().st_size,
            "sha256": sha256_file(index_path),
            "format": "release-index-v1",
        },
        "installer": {
            "version": installer_version,
            "url": copy_object(installer, output, installer_digest),
            "size": installer.stat().st_size,
            "sha256": installer_digest,
            "format": "elf64-static",
        },
        "keyring": [
            {
                "url": copy_object(public_key, output, public_key_digest),
                "size": public_key.stat().st_size,
                "sha256": public_key_digest,
                "format": "signify-public-key",
            }
        ],
    }


def main() -> None:
    output = Path("/output")
    if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
        fail("output directory must be an empty non-symlink directory")
    build_id = environment("BUILD_ID")
    channel = environment("CHANNEL")
    if not BUILD_ID.fullmatch(build_id) or not IDENTITY.fullmatch(channel):
        fail("release identity is invalid")
    try:
        sequence = int(environment("SEQUENCE"))
    except ValueError:
        fail("sequence is invalid")
    if sequence <= 0:
        fail("sequence must be positive")
    published_at = timestamp("PUBLISHED_AT")
    expires_at = timestamp("EXPIRES_AT")
    if published_at >= expires_at:
        fail("release-index validity window is invalid")
    secret_key = Path("/signing/release.sec")
    public_key = Path("/signing/release.pub")
    safe_file(secret_key, "signing key")
    safe_file(public_key, "public key")
    installer = Path("/input/volatoo-installer")
    installer_version = environment("INSTALLER_VERSION")
    if not INSTALLER_VERSION.fullmatch(installer_version):
        fail("installer version is invalid")

    index = {
        "schema": "org.volatoo.release-index/v1",
        "channel": channel,
        "sequence": sequence,
        "published_at": published_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "releases": [
            target(output, channel, build_id, name) for name in ("openrc", "systemd")
        ],
    }
    index_directory = output / "releases" / "amd64" / "autobuilds" / build_id
    index_directory.mkdir(parents=True)
    index_path = index_directory / "index.json"
    write_json(index_path, index)
    signature_path = sign_and_verify(index_path, secret_key, public_key)

    live_inputs_path = index_directory / "live-media-inputs.json"
    write_json(
        live_inputs_path,
        live_media_inputs(
            output,
            installer,
            installer_version,
            public_key,
            index_path,
            channel,
            build_id,
        ),
    )
    live_inputs_signature = sign_and_verify(
        live_inputs_path, secret_key, public_key
    )

    channel_directory = output / "releases" / "amd64" / "channels" / channel
    channel_directory.mkdir(parents=True)
    shutil.copyfile(index_path, channel_directory / "index.json")
    shutil.copyfile(signature_path, channel_directory / "index.json.sig")
    shutil.copyfile(live_inputs_path, channel_directory / live_inputs_path.name)
    shutil.copyfile(
        live_inputs_signature, channel_directory / live_inputs_signature.name
    )
    checksums = output / "SHA256SUMS"
    records = []
    for path in sorted(path for path in output.rglob("*") if path.is_file()):
        if path == checksums:
            continue
        records.append(f"{sha256_file(path)}  {path.relative_to(output).as_posix()}\n")
    checksums.write_text("".join(records), encoding="utf-8")
    os.chmod(checksums, 0o644)
    subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=output, check=True)

    uid = int(environment("HOST_UID"))
    gid = int(environment("HOST_GID"))
    for path in [output, *output.rglob("*")]:
        os.chown(path, uid, gid)
    print(f"packaged release index {build_id} for {channel}")


if __name__ == "__main__":
    main()
