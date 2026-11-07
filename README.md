# dsh-mcp-oauth

OAuth for MCP servers in **DeepSeek Harness**, with native tools (`mcp__<server>__<tool>`) and
**zero dependencies** — no npm packages, no lockfile, no build step.

DeepSeek Harness ships an MCP client that only sends static headers, so OAuth-only servers
(ClickUp, Canva, Clerk, Wispr Flow…) cannot be connected. The bundled SDK already implements the
whole authorization protocol; the client simply never passes an `authProvider`. This plugin is a
copy of `@deepseek-ai/dsh-mcp-client` with that one gap closed.

## What it uses

- the MCP SDK bundled inside DeepSeek Harness (`@modelcontextprotocol/client`) — a runtime peer,
  not a dependency;
- Node builtins;
- the macOS Keychain through `security(1)`, with a `0600` file fallback.

`package.json` declares no dependencies of any kind, and a test fails the build if one appears.

## Install

1. Clone this repository somewhere stable.
2. Copy the package into the profile you use:

```sh
cp -R dsh-mcp-plugin ~/.dsh/profiles/desktop/node_modules/dsh-mcp-oauth
rm -rf ~/.dsh/profiles/desktop/node_modules/dsh-mcp-oauth/.git
```

3. Add an entry to `~/.dsh/profiles/desktop/cordis.patch.yml`:

```yaml
- insert:
    - id: mcp-clickup-oauth
      name: dsh-mcp-oauth
      config:
        serverName: clickup
        transport: streamable-http
        url: https://mcp.clickup.com/mcp
        oauth:
          enabled: true
```

The profile reloads on save. The first connection opens one browser window; approve it and the
token lands in the Keychain. Later starts reuse it without any prompt.

## Update

```sh
./tools/update.sh --check      # installed vs latest tag
./tools/update.sh              # install the latest tag
./tools/update.sh --ref v0.6.0 # pin a version
```

The updater exports the tag, runs the test suite, backs up the installed copy, swaps it in, and
restores the backup on any failure. It needs `git` and Node; it does not need npm or pnpm.

## Tests

```sh
node --test
```

Covers credential-store merging, the callback listener (state, denial, unknown server, method,
listener shutdown), client metadata, and the dependency-free guarantee.

## Security notes

- The callback listener binds `127.0.0.1` only, exists only while an authorization is pending, and
  closes as soon as the browser returns.
- CSRF protection is the one-shot `state` value, compared in constant time.
- The port is reserved before the browser opens, so a busy port fails fast instead of after consent.
- At most two browser windows per server per 30 minutes, then a five-minute cooldown after a failure.
- Tokens never enter logs or the model context; the Keychain is the primary store.

## Limitations

- The plugin is a fork of `dsh-mcp-client`; a DeepSeek Harness update may require re-applying the
  transport patch.
- The code exchange is verified against ClickUp; it has no automated integration test yet.
