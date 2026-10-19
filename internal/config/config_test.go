package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimal 是一份最小可用的配置，各用例在其基础上改动。
const minimal = `
version = 1

[server]
listen = "127.0.0.1:8787"
data_dir = "./data"

[transport]
mode = "pinned"
cert_file = "relay.crt"
key_file = "relay.key"
`

func mustParse(t *testing.T, text string) *Config {
	t.Helper()

	cfg, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("解析配置失败：%v", err)
	}
	return cfg
}

// checkErr 断言错误信息中含指定片段；want 为空表示应当通过。
func checkErr(t *testing.T, err error, want string) {
	t.Helper()

	if want == "" {
		if err != nil {
			t.Fatalf("期望通过，实际报错：%v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("期望报错并包含 %q，实际通过", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("错误信息 %q 不含 %q", err, want)
	}
}

func TestTemplateIsValid(t *testing.T) {
	cfg := mustParse(t, Template())

	if cfg.Version != CurrentVersion {
		t.Errorf("样例配置的 version 为 %d，期望 %d", cfg.Version, CurrentVersion)
	}
}

func TestWithCredentialEnablesRegistration(t *testing.T) {
	text, err := WithCredential("credential-for-tests")
	if err != nil {
		t.Fatalf("生成带凭证的配置失败：%v", err)
	}

	cfg := mustParse(t, text)
	if !cfg.Registration.Enabled {
		t.Fatal("生成的配置未开启注册")
	}
	if cfg.Registration.CredentialDigest != DigestCredential("credential-for-tests") {
		t.Fatalf("凭证摘要不符：%q", cfg.Registration.CredentialDigest)
	}
	if !strings.Contains(text, "#") {
		t.Error("生成的配置丢失了样例中的注释")
	}
}

func TestWithCredentialRejectsEmpty(t *testing.T) {
	if _, err := WithCredential(""); err == nil {
		t.Fatal("空凭证应当被拒绝")
	}
}

func TestPathHelpers(t *testing.T) {
	cfg := mustParse(t, minimal)

	for name, path := range map[string]string{
		"存储":   cfg.StorePath(),
		"密钥":   cfg.KeyPath(),
		"重载请求": cfg.ReloadRequestPath(),
	} {
		if filepath.Dir(path) != filepath.Clean(cfg.Server.DataDir) {
			t.Errorf("%s路径 %q 不在数据目录 %q 之内", name, path, cfg.Server.DataDir)
		}
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	_, err := Parse([]byte(minimal + "\n[extra]\nfoo = 1\n"))

	checkErr(t, err, "无法识别的配置项")
}

func TestParseRejectsWrongVersion(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(minimal, "version = 1", "version = 2", 1)))

	checkErr(t, err, "version 应为 1")
}

func TestParseRejectsMissingVersion(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(minimal, "version = 1\n", "", 1)))

	checkErr(t, err, "version 应为 1")
}

func TestTransportValidation(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"钉住自签证书可通过", minimal, ""},
		{"公网证书缺少文件", "version = 1\n[server]\nlisten = \"127.0.0.1:8787\"\n[transport]\nmode = \"https\"\n", "transport.cert_file"},
		{"明文不应携带证书", strings.Replace(minimal, `mode = "pinned"`, `mode = "plaintext"`, 1), "不应配置证书"},
		{"取值无效", strings.Replace(minimal, `mode = "pinned"`, `mode = "tls"`, 1), "transport.mode 取值无效"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.text))
			checkErr(t, err, c.want)
		})
	}
}

func TestTransportDegraded(t *testing.T) {
	cases := map[string]bool{
		ModeHTTPS:     false,
		ModePinned:    false,
		ModeInsecure:  true,
		ModePlaintext: true,
	}

	for mode, want := range cases {
		if got := (Transport{Mode: mode}).Degraded(); got != want {
			t.Errorf("传输级别 %s 的降级判定为 %t，期望 %t", mode, got, want)
		}
	}
}

func TestRegistrationValidation(t *testing.T) {
	valid := strings.Repeat("a", 64)
	registration := func(enabled bool, digest string) string {
		return minimal + "\n[registration]\nenabled = " + boolText(enabled) + "\ncredential_digest = \"" + digest + "\"\n"
	}

	cases := []struct {
		name string
		text string
		want string
	}{
		{"开启且摘要合法", registration(true, valid), ""},
		{"开启但摘要过短", registration(true, "abc"), "registration.credential_digest"},
		{"开启但摘要为大写", registration(true, strings.Repeat("A", 64)), "registration.credential_digest"},
		{"关闭却填写摘要", registration(false, valid), "不应填写"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.text))
			checkErr(t, err, c.want)
		})
	}
}

func TestApplyDefaultsFillsZeroValues(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()

	if cfg.Server.Listen != defaultListen {
		t.Errorf("监听地址默认为 %q，期望 %q", cfg.Server.Listen, defaultListen)
	}
	if cfg.Server.DataDir != defaultDataDir {
		t.Errorf("数据目录默认为 %q，期望 %q", cfg.Server.DataDir, defaultDataDir)
	}
	if cfg.Transport.Mode != ModeHTTPS {
		t.Errorf("传输模式默认为 %q，期望 %q", cfg.Transport.Mode, ModeHTTPS)
	}
	if cfg.Log.Level != defaultLogLevel {
		t.Errorf("日志级别默认为 %q，期望 %q", cfg.Log.Level, defaultLogLevel)
	}
	if cfg.Limits != (Limits{
		DevicesPerChannel:     defaultDevicesPerChannel,
		RecordsPerDevice:      defaultRecordsPerDevice,
		RecordsPerRequest:     defaultRecordsPerRequest,
		RecordBytes:           defaultRecordBytes,
		RevocationsPerChannel: defaultRevocationsPerChannel,
		RequestsPerMinute:     defaultRequestsPerMinute,
	}) {
		t.Errorf("上限默认值不符：%+v", cfg.Limits)
	}
}

func TestParseFillsLimitsDefaults(t *testing.T) {
	cfg := mustParse(t, minimal)

	if cfg.Limits.DevicesPerChannel != defaultDevicesPerChannel {
		t.Errorf("devices_per_channel 默认为 %d，期望 %d", cfg.Limits.DevicesPerChannel, defaultDevicesPerChannel)
	}
	if cfg.Log.Level != defaultLogLevel {
		t.Errorf("log.level 默认为 %q，期望 %q", cfg.Log.Level, defaultLogLevel)
	}
	if cfg.Registration.Enabled || cfg.Registration.CredentialDigest != "" {
		t.Errorf("注册默认应为关闭且摘要为空：%+v", cfg.Registration)
	}
}

func TestLimitsValidation(t *testing.T) {
	cfg := mustParse(t, minimal)
	cfg.Limits.DevicesPerChannel = 0
	cfg.Limits.RecordsPerDevice = -1
	cfg.Limits.RecordBytes = maxRecordBytes + 1
	cfg.Limits.RevocationsPerChannel = maxRevocationsPerChannel + 1

	err := cfg.Validate()

	for _, want := range []string{"limits.devices_per_channel", "limits.records_per_device", "limits.record_bytes", "limits.revocations_per_channel"} {
		checkErr(t, err, want)
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	var cfg Config

	err := cfg.Validate()

	checkErr(t, err, "version 应为 1")
	checkErr(t, err, "server.listen")
	checkErr(t, err, "server.data_dir")
	checkErr(t, err, "transport.mode 取值无效")
	checkErr(t, err, "log.level")
}

func TestListenValidation(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8787":  true,
		"0.0.0.0:80":      true,
		"[::1]:8787":      true,
		":8787":           false,
		"127.0.0.1":       false,
		"127.0.0.1:0":     false,
		"127.0.0.1:70000": false,
		"127.0.0.1:http":  false,
	}

	for value, ok := range cases {
		if err := validateListen(value); (err == nil) != ok {
			t.Errorf("监听地址 %q 的校验结果为 %v，期望通过为 %t", value, err, ok)
		}
	}
}

func TestLogLevelValidation(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg := mustParse(t, minimal)
		cfg.Log.Level = level
		if err := cfg.Validate(); err != nil {
			t.Errorf("日志级别 %q 应当通过，实际报错：%v", level, err)
		}
	}

	cfg := mustParse(t, minimal)
	cfg.Log.Level = "verbose"
	checkErr(t, cfg.Validate(), "log.level")
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wip-relay.toml")
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatalf("写入临时配置失败：%v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}

	if want := filepath.Join(dir, "data"); cfg.Server.DataDir != want {
		t.Errorf("数据目录解析为 %q，期望 %q", cfg.Server.DataDir, want)
	}
	if want := filepath.Join(dir, "relay.crt"); cfg.Transport.CertFile != want {
		t.Errorf("证书路径解析为 %q，期望 %q", cfg.Transport.CertFile, want)
	}
	if want := filepath.Join(dir, "relay.key"); cfg.Transport.KeyFile != want {
		t.Errorf("私钥路径解析为 %q，期望 %q", cfg.Transport.KeyFile, want)
	}
}

func TestLoadKeepsAbsolutePaths(t *testing.T) {
	dir := t.TempDir()
	absolute := filepath.Join(dir, "elsewhere")
	text := strings.Replace(minimal, `"./data"`, `"`+absolute+`"`, 1)
	path := filepath.Join(dir, "wip-relay.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("写入临时配置失败：%v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	if cfg.Server.DataDir != absolute {
		t.Errorf("绝对路径被改写为 %q，期望 %q", cfg.Server.DataDir, absolute)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.toml"))

	checkErr(t, err, "读取配置")
}

func TestLoadRejectsInvalidContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wip-relay.toml")
	if err := os.WriteFile(path, []byte("version = 2\n"), 0o600); err != nil {
		t.Fatalf("写入临时配置失败：%v", err)
	}

	_, err := Load(path)

	checkErr(t, err, "有误")
}

func TestMarshalRoundTrip(t *testing.T) {
	cfg := mustParse(t, minimal)

	data, err := cfg.Marshal()
	if err != nil {
		t.Fatalf("序列化配置失败：%v", err)
	}

	again, err := Parse(data)
	if err != nil {
		t.Fatalf("重新解析失败：%v", err)
	}
	if *again != *cfg {
		t.Errorf("往返后配置不一致：\n%+v\n%+v", *cfg, *again)
	}
}

func TestDigestCredential(t *testing.T) {
	first := DigestCredential("credential-a")

	if !isHexDigest(first) {
		t.Fatalf("摘要不是六十四位小写十六进制：%q", first)
	}
	if DigestCredential("credential-a") != first {
		t.Error("同一凭证两次求摘要结果不同")
	}
	if DigestCredential("credential-b") == first {
		t.Error("不同凭证得到相同摘要")
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
