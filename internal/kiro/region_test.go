package kiro

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/xiaokui-dev/cliproxyapi-kiro-plugin/internal/hostapi"
)

// maliciousRegions 汇总所有会破坏 URL authority 的输入形态。任何一条被放行,
// 都意味着携带 refreshToken / clientSecret / accessToken 的请求可能被发往第三方主机。
var maliciousRegions = []struct {
	name   string
	region string
}{
	{"userinfo 分隔符改写主机", "us-east-1@attacker.example/"},
	{"仅 userinfo 无斜杠", "us-east-1@attacker.example"},
	{"路径分隔符提前结束主机", "us-east-1/../../evil.test"},
	{"反斜杠(部分解析器等价于斜杠)", `us-east-1\@evil.test`},
	{"查询串截断", "us-east-1?x="},
	{"片段截断", "us-east-1#frag"},
	{"显式端口", "us-east-1:8443"},
	{"scheme 注入", "us-east-1.amazonaws.com/x@evil.test"},
	{"协议相对地址", "//evil.test"},
	{"点号扩展主机", "us-east-1.evil.test"},
	{"前导空白后接主机", " @evil.test"},
	{"CRLF 注入", "us-east-1\r\nHost: evil.test"},
	{"制表符", "us-east-1\tevil"},
	{"空字节", "us-east-1\x00.evil.test"},
	{"大写(AWS region 恒为小写)", "US-EAST-1"},
	{"下划线", "us_east_1"},
	{"纯数字", "12345"},
	{"缺数字后缀", "us-east"},
	{"通配符", "*"},
	{"URL 编码的 @", "us-east-1%40evil.test"},
}

func TestValidateRegionRejectsAuthorityBreakingInput(t *testing.T) {
	for _, tc := range maliciousRegions {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := validateRegion(tc.region); err == nil {
				t.Fatalf("validateRegion(%q) 本应拒绝，却放行为 %q", tc.region, got)
			}
		})
	}
}

func TestValidateRegionAcceptsRealRegions(t *testing.T) {
	valid := []string{
		"us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
		"ap-southeast-3", "ap-northeast-1", "sa-east-1",
		"us-gov-west-1", "cn-north-1", "me-south-1", "af-south-1",
		"il-central-1", "ap-southeast-7",
	}
	for _, region := range valid {
		if got, err := validateRegion(region); err != nil || got != region {
			t.Fatalf("validateRegion(%q) 本应通过，得到 (%q, %v)", region, got, err)
		}
	}
	// 两侧空白应被裁剪后通过。
	if got, err := validateRegion("  us-east-1  "); err != nil || got != "us-east-1" {
		t.Fatalf("带空白的 region 应裁剪后通过，得到 (%q, %v)", got, err)
	}
	// 空值应报错，由调用方决定是否回退默认区域。
	if _, err := validateRegion("   "); err == nil {
		t.Fatalf("空 region 本应报错")
	}
}

// allTemplates 覆盖插件全部会插入 region 的上游端点模板。
var allTemplates = []struct {
	name     string
	template string
	suffix   string
	wantHost string
}{
	{"social 刷新", socialRefreshURLTemplate, "", "prod.us-east-1.auth.desktop.kiro.dev"},
	{"IDC 刷新", idcRefreshURLTemplate, "", "oidc.us-east-1.amazonaws.com"},
	{"生成", generateURLTemplate, "", "runtime.us-east-1.kiro.dev"},
	{"用量", usageURLTemplate, "", "q.us-east-1.amazonaws.com"},
	{"模型发现", listAvailableModelsURLTemplate, "", "management.us-east-1.kiro.dev"},
	{"OIDC 注册", ssoOIDCEndpointTemplate, "/client/register", "oidc.us-east-1.amazonaws.com"},
	{"OIDC 设备码", ssoOIDCEndpointTemplate, "/device_authorization", "oidc.us-east-1.amazonaws.com"},
	{"OIDC 换取 token", ssoOIDCEndpointTemplate, "/token", "oidc.us-east-1.amazonaws.com"},
}

// TestSafeEndpointRejectsMaliciousRegionForEveryTemplate 是本次安全修复的核心断言:
// 任何模板 × 任何注入取值都不得产出 URL。
func TestSafeEndpointRejectsMaliciousRegionForEveryTemplate(t *testing.T) {
	for _, tpl := range allTemplates {
		for _, tc := range maliciousRegions {
			t.Run(tpl.name+"/"+tc.name, func(t *testing.T) {
				got, err := safeEndpoint(tpl.template, tc.region, tpl.suffix)
				if err == nil {
					t.Fatalf("safeEndpoint(%q, %q) 本应拒绝，却产出 %q", tpl.template, tc.region, got)
				}
				if got != "" {
					t.Fatalf("被拒绝时不应返回 URL，得到 %q", got)
				}
			})
		}
	}
}

// TestSafeEndpointProducesExpectedHost 确认合法 region 仍指向预期 AWS/Kiro 主机。
func TestSafeEndpointProducesExpectedHost(t *testing.T) {
	for _, tpl := range allTemplates {
		t.Run(tpl.name, func(t *testing.T) {
			raw, err := safeEndpoint(tpl.template, "us-east-1", tpl.suffix)
			if err != nil {
				t.Fatalf("合法 region 本应通过: %v", err)
			}
			parsed, errParse := url.Parse(raw)
			if errParse != nil {
				t.Fatalf("解析产出的 URL 失败: %v", errParse)
			}
			if parsed.Scheme != "https" {
				t.Fatalf("scheme 应为 https，得到 %q", parsed.Scheme)
			}
			if parsed.Hostname() != tpl.wantHost {
				t.Fatalf("主机应为 %q，得到 %q（完整 URL %q）", tpl.wantHost, parsed.Hostname(), raw)
			}
			if parsed.User != nil {
				t.Fatalf("不应出现 userinfo: %q", raw)
			}
			if tpl.suffix != "" && !strings.HasSuffix(parsed.Path, tpl.suffix) {
				t.Fatalf("路径应以 %q 结尾，得到 %q", tpl.suffix, parsed.Path)
			}
		})
	}
}

func TestResolveRegion(t *testing.T) {
	// 注入取值必须报错，绝不放行、也不静默改用别的区域。
	for _, tc := range maliciousRegions {
		if got, err := resolveRegion(tc.region); err == nil {
			t.Fatalf("resolveRegion(%q) 本应报错，却返回 %q", tc.region, got)
		}
	}
	// 空值(字段缺省)跳过，选中首个非空且合法的取值。
	if got, err := resolveRegion("", "eu-west-1"); err != nil || got != "eu-west-1" {
		t.Fatalf("应选中 eu-west-1，得到 (%q, %v)", got, err)
	}
	// 首个非空取值非法时报错，不允许"退到下一个候选"绕过篡改。
	if got, err := resolveRegion("us-east-1@evil.test", "ap-northeast-1"); err == nil {
		t.Fatalf("首个非空取值非法时本应报错，却返回 %q", got)
	}
	// 全部缺省时回退默认区域，这是合法凭据的常见情形。
	if got, err := resolveRegion("", ""); err != nil || got != defaultKiroRegion {
		t.Fatalf("全空时应回退 %q，得到 (%q, %v)", defaultKiroRegion, got, err)
	}
	if got, err := resolveRegion(); err != nil || got != defaultKiroRegion {
		t.Fatalf("无候选时应回退 %q，得到 (%q, %v)", defaultKiroRegion, got, err)
	}
}

// TestRefreshRejectsMaliciousRegionWithoutSendingCredentials 是端到端回归:
// 凭据带注入 region 时，refresh 不得发出任何 HTTP 请求(即凭据不外泄)。
func TestRefreshRejectsMaliciousRegionWithoutSendingCredentials(t *testing.T) {
	oldHTTPDo := kiroHTTPDo
	t.Cleanup(func() { kiroHTTPDo = oldHTTPDo })

	for _, authMethod := range []string{"social", idcAuthMethod, builderIDAuthMethod} {
		for _, tc := range maliciousRegions {
			t.Run(authMethod+"/"+tc.name, func(t *testing.T) {
				// 任何外发请求都是安全缺陷:注入取值必须在发请求之前被拦下。
				kiroHTTPDo = func(req hostapi.HTTPRequest) (*hostapi.HTTPResponse, error) {
					t.Fatalf("非法 region 竟发出了请求，URL=%q（凭据可能外泄）", req.URL)
					return nil, nil
				}

				cred := kiroCredential{
					Type:         providerKiro,
					RefreshToken: "RT-secret",
					ClientID:     "cid",
					ClientSecret: "csecret",
					AuthMethod:   authMethod,
					Region:       tc.region,
					IDCRegion:    tc.region,
				}
				storage, errMarshal := json.Marshal(cred)
				if errMarshal != nil {
					t.Fatalf("编码凭据失败: %v", errMarshal)
				}
				reqBytes, errMarshal := json.Marshal(map[string]any{
					"StorageJSON":      storage,
					"host_callback_id": "cb-1",
				})
				if errMarshal != nil {
					t.Fatalf("编码请求失败: %v", errMarshal)
				}

				raw, errRefresh := refreshKiroAuth(reqBytes)
				if errRefresh != nil {
					t.Fatalf("refreshKiroAuth 返回内部错误: %v", errRefresh)
				}
				// 应是错误信封，而非成功。
				var env struct {
					OK bool `json:"ok"`
				}
				if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
					t.Fatalf("解析信封失败: %v", errUnmarshal)
				}
				if env.OK {
					t.Fatalf("非法 region 本应返回错误信封")
				}
			})
		}
	}
}

// TestParseKiroAuthRejectsMaliciousRegion 确认导入阶段就拦下投毒凭据。
func TestParseKiroAuthRejectsMaliciousRegion(t *testing.T) {
	for _, field := range []string{"region", "idcRegion"} {
		for _, tc := range maliciousRegions {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				cred := map[string]any{
					"type":         providerKiro,
					"refreshToken": "RT",
					"authMethod":   builderIDAuthMethod,
					field:          tc.region,
				}
				credJSON, errMarshal := json.Marshal(cred)
				if errMarshal != nil {
					t.Fatalf("编码凭据失败: %v", errMarshal)
				}
				reqBytes, errMarshal := json.Marshal(map[string]any{"RawJSON": credJSON})
				if errMarshal != nil {
					t.Fatalf("编码请求失败: %v", errMarshal)
				}

				raw, errParse := parseKiroAuth(reqBytes)
				if errParse != nil {
					t.Fatalf("parseKiroAuth 返回内部错误: %v", errParse)
				}
				var env struct {
					OK bool `json:"ok"`
				}
				if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
					t.Fatalf("解析信封失败: %v", errUnmarshal)
				}
				if env.OK {
					t.Fatalf("%s 为非法 region 时本应拒绝导入", field)
				}
			})
		}
	}
}

// TestParseKiroAuthAcceptsEmptyAndValidRegion 确认修复没有破坏正常导入:
// region 缺省或合法的凭据仍应被接收。
func TestParseKiroAuthAcceptsEmptyAndValidRegion(t *testing.T) {
	for _, region := range []string{"", "us-east-1", "eu-west-1"} {
		cred := map[string]any{
			"type":         providerKiro,
			"refreshToken": "RT",
			"authMethod":   builderIDAuthMethod,
		}
		if region != "" {
			cred["region"] = region
		}
		credJSON, errMarshal := json.Marshal(cred)
		if errMarshal != nil {
			t.Fatalf("编码凭据失败: %v", errMarshal)
		}
		reqBytes, errMarshal := json.Marshal(map[string]any{"RawJSON": credJSON})
		if errMarshal != nil {
			t.Fatalf("编码请求失败: %v", errMarshal)
		}

		raw, errParse := parseKiroAuth(reqBytes)
		if errParse != nil {
			t.Fatalf("parseKiroAuth 返回内部错误: %v", errParse)
		}
		var env struct {
			OK bool `json:"ok"`
		}
		if errUnmarshal := json.Unmarshal(raw, &env); errUnmarshal != nil {
			t.Fatalf("解析信封失败: %v", errUnmarshal)
		}
		if !env.OK {
			t.Fatalf("region=%q 的凭据本应被接收", region)
		}
	}
}
