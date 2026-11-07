# dsh-mcp-oauth

OAuth-провайдер для MCP-серверов в DeepSeek Harness: нативные инструменты
`mcp__<server>__<tool>` без моста и без сторонних пакетов.

## Как устроено

- Копия `@deepseek-ai/dsh-mcp-client` с патчем фабрики транспорта: в
  `StreamableHTTPClientTransport` передаётся `authProvider`.
- `oauth.js` хранит учётные данные (Keychain, при недоступности — файл `0600`)
  и поднимает один callback-сервер на процесс с маршрутом `/callback/<server>`.
- Протокол (discovery, DCR, PKCE, обмен, refresh, step-up) выполняет
  `@modelcontextprotocol/client` из рантайма DSH.

## Установка

Скопировать каталог в `<profile>/node_modules/dsh-mcp-oauth` и добавить запись
в `cordis.patch.yml` профиля:

```yaml
- insert:
    - id: mcp-<name>-oauth
      name: dsh-mcp-oauth
      config:
        serverName: <name>
        transport: streamable-http
        url: <mcp-endpoint>
        oauth:
          enabled: true
```

## Обновление

```sh
node tools/update.mjs --repo ~/path/to/repo --ref v0.5.0
```

Скрипт выгружает тег, прогоняет тесты встроенным Node, ставит версию с
резервной копией, трогает патч профиля для перезагрузки и откатывается при
любой ошибке. npm и pnpm не нужны.

## Тесты

```sh
node --test
```

Покрывают слияние хранилищ (Keychain и файл) и callback-сервер: состояние,
отказ, неизвестный сервер, метод, закрытие слушателя после последней сессии.

## Ограничения

- Форк `dsh-mcp-client`: после обновления DSH патч переносится вручную.
- Обмен кода на токен проверен вручную на ClickUp; автотестом не покрыт.
