#!/bin/sh
# Update dsh-mcp-oauth with the Node bundled inside DeepSeek Harness.
# Usage: dsh-mcp-oauth-update [--check] [--ref vX.Y.Z]
set -eu

BUNDLED="/Applications/DeepSeek Harness.app/Contents/Resources/runtime/primary-runtime/dependencies/node/bin/node"
REPO="${DSH_MCP_OAUTH_REPO:-/Users/eli/Work/harness/ai-engineering/scratch/mcp-oauth}"

if [ -x "$BUNDLED" ]; then
	NODE="$BUNDLED"
elif command -v node >/dev/null 2>&1; then
	NODE="$(command -v node)"
else
	echo "no Node runtime found: neither the bundled one nor PATH" >&2
	exit 2
fi

if [ ! -d "$REPO/.git" ]; then
	echo "update source is not a git repository: $REPO" >&2
	echo "set DSH_MCP_OAUTH_REPO to the checkout that holds the plugin" >&2
	exit 2
fi

exec "$NODE" "$REPO/tools/update.mjs" --repo "$REPO" --node "$NODE" "$@"
