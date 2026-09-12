# Kiro Plugin

[中文](./README.md) | English

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin that connects Kiro OAuth accounts to CLIProxyAPI as an upstream and exposes a standard Claude Messages interface. The upstream speaks AWS CodeWhisperer's private protocol; the plugin handles the Claude ↔ CodeWhisperer translation in both directions, supporting tool calls, image input, and streaming output.

## Build

```bash
gofmt -w .
go test ./...
go vet ./...

# macOS (native arch, e.g. arm64)
CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dylib .

# Linux (build on a machine of the same GOOS/GOARCH)
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.so .

# Windows
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dll .
```

## Install into CLIProxyAPI

> Note: do not use the official release archives with a `no-plugin` suffix (the musl/OpenWrt portable build, FreeBSD arm64) — they cannot load dynamic library plugins. The mainstream macOS / Windows / default Linux / Docker builds all load them fine.

Place the shared library in the plugin directory, in per-platform subdirectories:

```
plugins/darwin/arm64/kiro.dylib
plugins/linux/amd64/kiro.so
plugins/windows/amd64/kiro.dll
```

Enable it in the host's `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    kiro:
      enabled: true
      # Leave idc_start_url empty to log in with AWS Builder ID; set it to use organization IDC. See the table below.
      # idc_start_url: "https://d-xxxx.awsapps.com/start"
      # idc_region: "us-east-1"
      # account_label: "team-a"
```

## Configuration fields

`plugins.configs.kiro.*` provides the defaults. If the host sends OAuth flow config at login time (top level or under `oauth_flow_config`), the flow config wins.

| Field | Type | Description |
|---|---|---|
| `idc_start_url` | string | Organization IAM Identity Center portal start URL, e.g. `https://d-xxxx.awsapps.com/start`. **When set, login goes through organization IDC; when empty/missing, login uses AWS Builder ID (a personal account) with the default start URL.** |
| `idc_region` | string | AWS Region that hosts your Identity Center instance. Used only for IDC login; defaults to `us-east-1` when empty. |
| `account_label` | string | Optional label written into auth metadata and label text so multiple Kiro accounts are easier to distinguish. |

## Login methods

The login method is **inferred** from the effective `idc_start_url`:

- **AWS Builder ID (default, personal free account)**: leave `idc_start_url` empty. After saving, start the device-code login from the "Kiro OAuth" page in the panel and authorize in the browser — no other fields needed.
- **Organization IDC (IAM Identity Center)**: fill in `idc_start_url` (the organization portal URL), and `idc_region` if needed (defaults to `us-east-1` when empty). Start the device-code login from the "Kiro OAuth" page after saving.
- **Google / GitHub**: no interactive login (limited by the upstream Cognito callback allowlist). Sign in with the Kiro desktop app, then export the credential JSON into `auth-dir`. The JSON must contain `accessToken`, `refreshToken`, `profileArn`, `authMethod` (value `social`), and `region` (usually `us-east-1`); it refreshes automatically after import.

Verify after login:

```bash
curl -s http://127.0.0.1:8317/v1/models | grep -i claude
```

## License

[MIT](./LICENSE)
