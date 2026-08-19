#!/usr/bin/env bash

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
Usage: scripts/package-index-docker.sh \
  --build-id ID --channel CHANNEL --sequence NUMBER \
  --published-at RFC3339 --expires-at RFC3339 \
  --openrc-archive FILE --openrc-manifest FILE \
  --systemd-archive FILE --systemd-manifest FILE \
  --installer FILE --installer-version VERSION \
  --signing-key FILE --public-key FILE OUTPUT_DIRECTORY
EOF
}

build_id=
channel=
sequence=
published_at=
expires_at=
openrc_archive=
openrc_manifest=
systemd_archive=
systemd_manifest=
installer=
installer_version=
signing_key=
public_key=
output=
while (( $# > 0 )); do
	case $1 in
		--build-id|--channel|--sequence|--published-at|--expires-at|--openrc-archive|--openrc-manifest|--systemd-archive|--systemd-manifest|--installer|--installer-version|--signing-key|--public-key)
			(( $# >= 2 )) || { echo "error: $1 requires a value" >&2; exit 2; }
			case $1 in
				--build-id) build_id=$2 ;;
				--channel) channel=$2 ;;
				--sequence) sequence=$2 ;;
				--published-at) published_at=$2 ;;
				--expires-at) expires_at=$2 ;;
				--openrc-archive) openrc_archive=$2 ;;
				--openrc-manifest) openrc_manifest=$2 ;;
				--systemd-archive) systemd_archive=$2 ;;
				--systemd-manifest) systemd_manifest=$2 ;;
				--installer) installer=$2 ;;
				--installer-version) installer_version=$2 ;;
				--signing-key) signing_key=$2 ;;
				--public-key) public_key=$2 ;;
			esac
			shift 2
			;;
		-h|--help) usage; exit 0 ;;
		-*) echo "error: unknown option: $1" >&2; usage; exit 2 ;;
		*) [[ -z $output ]] || { echo "error: only one output is allowed" >&2; exit 2; }; output=$1; shift ;;
	esac
done

[[ -n $build_id && -n $channel && -n $sequence && -n $published_at && -n $expires_at && -n $installer_version && -n $output ]] || {
	usage
	exit 2
}
[[ $build_id =~ ^[0-9]{8}T[0-9]{6}Z$ && $channel =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && $sequence =~ ^[1-9][0-9]*$ && $installer_version =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ ]] || {
	echo "error: invalid release identity" >&2
	exit 2
}
for input in "$openrc_archive" "$openrc_manifest" "$systemd_archive" "$systemd_manifest" "$installer" "$signing_key" "$public_key"; do
	[[ -f $input && ! -L $input ]] || {
		echo "error: release input must be a regular non-symlink file: $input" >&2
		exit 1
	}
done
[[ ! -e $output && ! -L $output ]] || {
	echo "error: output already exists: $output" >&2
	exit 1
}
[[ $(docker context show) == orbstack ]] || {
	echo "error: Docker context must be orbstack" >&2
	exit 1
}

absolute_file()
{
	local path=$1
	printf '%s/%s\n' "$(cd -- "$(dirname -- "$path")" && pwd)" "$(basename -- "$path")"
}
openrc_archive=$(absolute_file "$openrc_archive")
openrc_manifest=$(absolute_file "$openrc_manifest")
systemd_archive=$(absolute_file "$systemd_archive")
systemd_manifest=$(absolute_file "$systemd_manifest")
installer=$(absolute_file "$installer")
signing_key=$(absolute_file "$signing_key")
public_key=$(absolute_file "$public_key")
output_name=$(basename -- "$output")
output_parent=$(cd -- "$(dirname -- "$output")" && pwd)
[[ $output_name != . && $output_name != .. ]] || {
	echo "error: unsafe output directory name" >&2
	exit 1
}
staging=$(mktemp -d "$output_parent/.volatoo-index.XXXXXX")
cleanup()
{
	if [[ -d $staging ]]; then
		find "$staging" -depth -type f -delete
		find "$staging" -depth -type d -empty -delete
	fi
}
trap cleanup EXIT

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=volatoo-releng-index:1
docker build --file "$repo_root/Dockerfile.index" --tag "$image" "$repo_root"
docker run --rm --network none \
	--env "BUILD_ID=$build_id" \
	--env "CHANNEL=$channel" \
	--env "SEQUENCE=$sequence" \
	--env "PUBLISHED_AT=$published_at" \
	--env "EXPIRES_AT=$expires_at" \
	--env "INSTALLER_VERSION=$installer_version" \
	--env "HOST_UID=$(id -u)" \
	--env "HOST_GID=$(id -g)" \
	--mount "type=bind,src=$openrc_archive,dst=/input/openrc.img.zst,readonly" \
	--mount "type=bind,src=$openrc_manifest,dst=/input/openrc.img.manifest,readonly" \
	--mount "type=bind,src=$systemd_archive,dst=/input/systemd.img.zst,readonly" \
	--mount "type=bind,src=$systemd_manifest,dst=/input/systemd.img.manifest,readonly" \
	--mount "type=bind,src=$installer,dst=/input/volatoo-installer,readonly" \
	--mount "type=bind,src=$signing_key,dst=/signing/release.sec,readonly" \
	--mount "type=bind,src=$public_key,dst=/signing/release.pub,readonly" \
	--mount "type=bind,src=$staging,dst=/output" \
	"$image"

[[ -f $staging/releases/amd64/autobuilds/$build_id/index.json && \
	-f $staging/releases/amd64/autobuilds/$build_id/index.json.sig && \
	-f $staging/releases/amd64/autobuilds/$build_id/live-media-inputs.json && \
	-f $staging/releases/amd64/autobuilds/$build_id/live-media-inputs.json.sig ]] || {
	echo "error: release index packager did not publish all signed documents" >&2
	exit 1
}
mv "$staging" "$output_parent/$output_name"
trap - EXIT
echo "packaged signed release index: $output_parent/$output_name"
