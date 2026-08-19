#!/bin/sh
set -eu

script_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
case $script_root in
	*/tests) guard=$script_root/../require-docker-context.sh ;;
	*) guard=$script_root/require-docker-context.sh ;;
esac
test_root=$(mktemp -d "${TMPDIR:-/tmp}/volatoo-context-policy.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cat >"$test_root/docker" <<'EOF'
#!/bin/sh
printf '%s\n' "$VOLATOO_TEST_DOCKER_CONTEXT"
EOF
chmod 0755 "$test_root/docker"

run_guard()
{
	VOLATOO_TEST_DOCKER_CONTEXT=$1 \
		GITHUB_ACTIONS=$2 \
		RUNNER_OS=$3 \
		PATH="$test_root:$PATH" \
		sh -c '. "$1"; volatoo_require_docker_context' sh "$guard"
}

run_guard orbstack '' ''
run_guard default true Linux
if run_guard default '' '' >/dev/null 2>&1; then
	printf '%s\n' 'error: local default context was accepted' >&2
	exit 1
fi
if run_guard desktop-linux true Linux >/dev/null 2>&1; then
	printf '%s\n' 'error: unsupported GitHub Actions context was accepted' >&2
	exit 1
fi

printf '%s\n' 'Docker context policy tests passed'
