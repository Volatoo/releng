#!/bin/sh

volatoo_require_docker_context()
{
	context=$(docker context show)
	if [ "$context" = orbstack ]; then
		return 0
	fi
	if [ "$context" = default ] \
		&& [ "${GITHUB_ACTIONS:-}" = true ] \
		&& [ "${RUNNER_OS:-}" = Linux ]; then
		return 0
	fi
	printf '%s\n' \
		'error: Docker context must be orbstack locally or default on GitHub Actions Linux' >&2
	return 1
}
