# Плагин dsh-mcp-oauth — нативный OAuth для MCP в DSH

## Корень проблемы

`dsh-mcp-client` создаёт transport без `authProvider`:

```js
new StreamableHTTPClientTransport(new URL(config.url), { requestInit: { headers: config.headers } })
```

При этом в бандле лежит `@modelcontextprotocol/client@2.3.1`, где есть `OAuthClientProvider`,
`auth()`, `registerClient`, `startAuthorization`, `exchangeAuthorization`, обработка `UnauthorizedError`
и step-up по `403`. Пропущен только аргумент.

## Что делаем

Локальный плагин `dsh-mcp-oauth` — копия `@deepseek-ai/dsh-mcp-client` с патчем транспорта и
провайдером учётных данных. Никаких сторонних npm-пакетов: всё, что нужно, уже в рантайме DSH.

Проверено на живом профиле (`/tmp/dshtest`): локальный пакет ставится через
`dsh plugin --profile <p> add file:<dir>` встроенным pnpm (376 мс, без npm) и **импортирует
`@modelcontextprotocol/client` из рантайма** (`MODTEST_OK function`).

## Состав

| Файл | Что |
|---|---|
| `package.json` | имя, версия, `type: module`, `main` |
| `index.js` | вендоренный `dsh-mcp-client/lib/index.js` (35 КБ) + патчи |
| `oauth.js` | провайдер: DCR, PKCE, callback-сервер, хранение токенов |
| `cordis.patch.yml` | записи-серверы для профиля (генерируется отдельно) |

### Патчи в index.js

1. Фабрика транспорта: при `config.oauth` передавать `authProvider`.
2. Схема конфига: блок `oauth` — `{ scopes?, clientId?, clientSecret?, callbackPort? }`.
3. Ничего больше не менять: нейминг `mcp__<server>__<tool>`, реконнект, canonical-результаты остаются.

### Провайдер (oauth.js)

Реализует `OAuthClientProvider`: `redirectUrl`, `clientMetadata`, `clientInformation/save`,
`tokens/saveTokens`, `saveCodeVerifier/codeVerifier`, `redirectToAuthorization`, `invalidateCredentials`.

- Токены: macOS Keychain через `security add-generic-password` / `find-generic-password`
  (сервис `dsh-mcp-oauth`, аккаунт = имя сервера). Файл `0600` как fallback для серверов без Keychain.
- `redirectToAuthorization`: `open <url>` и ожидание callback на `127.0.0.1:<port>` (по умолчанию 8765),
  печать URL в stderr, если браузер не открылся.
- Регистрация клиента: DCR через `auth()`; если сервер DCR не поддерживает — `clientId/clientSecret` из конфига.

## Шаги

1. Собрать пакет в `~/.dsh/plugins/dsh-mcp-oauth/` (исходник), вендорить index.js.
2. Проверить на ClickUp (`https://mcp.clickup.com/mcp`) в тестовом профиле `web` с `DSH_HOME=/tmp/dshtest`:
   дойти до выдачи authorization URL, подтвердить, что инструменты появляются в `tools/list`.
3. Установить в рабочий профиль `desktop`: копия пакета в `~/.dsh/profiles/desktop/node_modules/dsh-mcp-oauth`
   (или `pnpm add file:` через встроенный pnpm), запись в `cordis.patch.yml`.
4. Добавить Canva и Wispr теми же записями.

## Приёмка

- `mcp__clickup__*` появляются в списке инструментов без ручных токенов.
- Токен лежит в Keychain (`security find-generic-password -s dsh-mcp-oauth -a clickup`), в YAML его нет.
- После перезапуска приложения инструменты работают без повторной авторизации.
- Отзыв: удалить запись из патча и элемент из Keychain.

## Риски

1. **Нет `.d.ts`** — интерфейс провайдера только по JSDoc в `dist/index.mjs`. Проверяется на первом прогоне.
2. **DCR.** Если ClickUp/Canva не поддерживают динамическую регистрацию, нужен `clientId` из их кабинета —
   ручная регистрация приложения неизбежна, это ограничение любого моста.
3. **Форк.** После обновления DSH патч переносится на новую версию `dsh-mcp-client` (полчаса).
4. **Установка в desktop-профиль.** CLI блокирует `--profile desktop`; ставим файлами напрямую, приложение
   подхватывает на лету. Проверить на первом шаге.
5. **Keychain из процесса приложения.** `security` пишет в связку от имени пользователя; при первом запросе
   macOS может спросить разрешение на доступ — подтверждается один раз.

## Откат

Удалить запись из `cordis.patch.yml` и каталог пакета. Профиль возвращается к штатному `dsh-mcp-client`.
