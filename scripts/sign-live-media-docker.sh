#!/usr/bin/env bash

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
Usage: scripts/sign-live-media-docker.sh \
  --build-id ID --channel CHANNEL --init-system openrc|systemd \
  --iso FILE --manifest FILE --publication DIRECTORY \
  --signing-key FILE --public-key FILE OUTPUT_DIRECTORY
EOF
}

build_id=
channel=
init_system=
iso=
manifest=
publication=
signing_key=
public_key=
output=
while (( $# > 0 )); do
	case $1 in
		--build-id|--channel|--init-system|--iso|--manifest|--publication|--signing-key|--public-key)
			(( $# >= 2 )) || { echo "error: $1 requires a value" >&2; exit 2; }
			case $1 in
				--build-id) build_id=$2 ;;
				--channel) channel=$2 ;;
				--init-system) init_system=$2 ;;
				--iso) iso=$2 ;;
				--manifest) manifest=$2 ;;
				--publication) publication=$2 ;;
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
[[ $build_id =~ ^[0-9]{8}T[0-9]{6}Z$ && \
	$channel =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ && \
	$init_system =~ ^(openrc|systemd)$ && -n $output && \
	-d $publication && ! -L $publication ]] || { usage; exit 2; }
for input in "$iso" "$manifest" "$signing_key" "$public_key"; do
	[[ -f $input && ! -L $input ]] || {
		echo "error: live-media signing input is missing or unsafe: $input" >&2
		exit 1
	}
done
[[ ! -e $output && ! -L $output ]] || {
	echo "error: output already exists or is unsafe: $output" >&2
	exit 1
}
[[ $(docker context show) == orbstack ]] || {
	echo "error: Docker context must be orbstack" >&2
	exit 1
}

absolute_file()
{
	printf '%s/%s\n' "$(cd -- "$(dirname -- "$1")" && pwd)" "$(basename -- "$1")"
}
iso=$(absolute_file "$iso")
manifest=$(absolute_file "$manifest")
signing_key=$(absolute_file "$signing_key")
public_key=$(absolute_file "$public_key")
publication=$(cd -- "$publication" && pwd)
output_name=$(basename -- "$output")
output_parent=$(cd -- "$(dirname -- "$output")" && pwd)
[[ $output_name != . && $output_name != .. ]] || { echo "error: unsafe output name" >&2; exit 1; }
staging=$(mktemp -d "$output_parent/.volatoo-live-media.XXXXXX")
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
	--entrypoint /usr/local/sbin/sign-volatoo-live-media \
	--env "BUILD_ID=$build_id" --env "CHANNEL=$channel" \
	--env "INIT_SYSTEM=$init_system" --env "ISO_NAME=$(basename -- "$iso")" \
	--env "HOST_UID=$(id -u)" --env "HOST_GID=$(id -g)" \
	--mount "type=bind,src=$iso,dst=/input/live.iso,readonly" \
	--mount "type=bind,src=$manifest,dst=/input/live.iso.manifest,readonly" \
	--mount "type=bind,src=$publication,dst=/input/publication,readonly" \
	--mount "type=bind,src=$signing_key,dst=/signing/release.sec,readonly" \
	--mount "type=bind,src=$public_key,dst=/signing/release.pub,readonly" \
	--mount "type=bind,src=$staging,dst=/output" \
	"$image"
[[ -f $staging/live-media.json && ! -L $staging/live-media.json && \
	-f $staging/live-media.json.sig && ! -L $staging/live-media.json.sig ]] || {
	echo "error: signer did not publish safe live-media descriptors" >&2
	exit 1
}
mv "$staging" "$output_parent/$output_name"
trap - EXIT
echo "published signed live-media descriptor: $output_parent/$output_name"
