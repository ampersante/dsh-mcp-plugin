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

## Authorize from the terminal

```sh
node tools/authorize.mjs notion=https://mcp.notion.com/mcp
node tools/authorize.mjs --port 8770 --parallel ticktick=https://… wispr=https://…
```

The listener runs in this terminal, so the redirect target is live before the link is printed and
every failure is reported here instead of inside the application. The token goes to the same store
the plugin reads, so the next connection reuses it without a browser. `--parallel` keeps several
links valid at once.

Open the link in a real browser window. A link opened inside the host application's own window
arrives as a cross-site navigation and providers reject it, usually with a bare error page that
names no cause.

Pass the same number as `oauth.callbackPort` in the server config. The stored client registration
names the redirect URI, so the two must agree or the plugin registers again and the refresh token
belongs to a client it no longer uses.

## Update

```sh
./tools/update.sh --check      # installed vs latest tag
./tools/update.sh              # install the latest tag
./tools/update.sh --ref v0.6.0 # pin a version
```

The updater exports the tag, runs the test suite, backs up the installed copy, swaps it in, and
restores the backup on any failure. It needs `git` and Node; it does not need npm or pnpm.
Running `node tools/update.mjs` directly requires Node 22.15+ (the tests need `registerHooks`); the
documented path is `./tools/update.sh`, which uses the Node bundled with DeepSeek Harness.

## Tests

```sh
node --test --test-concurrency=1 "test/**/*.test.mjs"
```

Covers credential-store merging, the callback listener (state, denial, unknown server, method,
listener shutdown), client metadata, the terminal authorization flow against a local authorization
server (PKCE challenge, exchange, stored token, reuse), and the dependency-free guarantee.

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
- The exchange test needs a copy of `@modelcontextprotocol/client`, taken from `DSH_MCP_OAUTH_SDK`
  or `~/.dsh/mcp-oauth-sdk`. It never reads the application bundle; without a copy it is skipped
  with a reason, and a copy that exists but is incomplete fails instead of silently skipping.
- An authorization endpoint that answers with JSON rather than a redirect (alphaXiv does) shows a
  JSON body in the browser; open the `url` field of that answer instead.

## License

MIT — see [LICENSE](LICENSE).
