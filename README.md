# Kiro Plugin

中文 | [English](./README.en.md)

一个 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 插件：把 Kiro OAuth 账号接入 CLIProxyAPI 作为上游，对外提供标准的 Claude Messages 接口。上游走 AWS CodeWhisperer 私有协议，插件内部完成 Claude ↔ CodeWhisperer 的双向转换，支持工具调用、图片输入、流式输出。

## 构建

```bash
gofmt -w .
go test ./...
go vet ./...

# macOS（本机架构，如 arm64）
CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dylib .

# Linux（在相同 GOOS/GOARCH 的机器上编）
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.so .

# Windows
# CGO_ENABLED=1 go build -buildmode=c-shared -o kiro.dll .
```

## 安装到 CLIProxyAPI

> 注意：请勿使用官方 release 里带 `no-plugin` 后缀的包（musl/OpenWrt 便携版、FreeBSD arm64），它们不支持动态库插件。主流的 macOS / Windows / 默认 Linux 包 / Docker 均可正常加载。

把动态库放到插件目录，按平台分子目录：

```
plugins/darwin/arm64/kiro.dylib
plugins/linux/amd64/kiro.so
plugins/windows/amd64/kiro.dll
```

在宿主 `config.yaml` 启用：

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    kiro:
      enabled: true
      # 不填 idc_start_url 即用 AWS Builder ID 登录；填了则走组织 IDC，见下表
      # idc_start_url: "https://d-xxxx.awsapps.com/start"
      # idc_region: "us-east-1"
      # account_label: "team-a"
```

## 配置字段

`plugins.configs.kiro.*` 提供默认值；若宿主在登录时下发 OAuth 流程配置（顶层或 `oauth_flow_config` 子对象），则流程配置优先。

| 字段 | 类型 | 说明 |
|---|---|---|
| `idc_start_url` | 字符串 | 组织 IAM Identity Center 门户 start URL，如 `https://d-xxxx.awsapps.com/start`。**填了就走组织 IDC 登录；留空/缺失则走 AWS Builder ID（个人账号）登录，并使用默认 start URL** |
| `idc_region` | 字符串 | 承载你的 Identity Center 实例的 AWS 区域，仅 IDC 登录时使用，留空回退 `us-east-1` |
| `account_label` | 字符串 | 可选标签，会写入认证元数据与显示名称，便于区分多个 Kiro 账号 |

## 登录方式

登录方式由生效的 `idc_start_url` 是否配置**隐式决定**：

- **AWS Builder ID（默认，个人免费账号）**：`idc_start_url` 留空即可。保存配置后到面板「Kiro OAuth」页发起设备码登录，浏览器授权即可，无需其它字段。
- **组织 IDC（IAM Identity Center）**：填写 `idc_start_url`（组织门户 URL），需要时再填 `idc_region`（留空默认 `us-east-1`）。保存后同样在「Kiro OAuth」页发起设备码登录。
- **Google / GitHub**：没有交互登录（受上游 Cognito 回调白名单限制）。请在 Kiro 桌面应用登录后导出凭据 JSON 放进 `auth-dir`，JSON 要有 `accessToken`、`refreshToken`、`profileArn`、`authMethod`（值为 `social`）、`region`（一般 `us-east-1`），导入后会自动刷新。

登录后验证：

```bash
curl -s http://127.0.0.1:8317/v1/models | grep -i claude
```

## 许可证

[MIT](./LICENSE)
