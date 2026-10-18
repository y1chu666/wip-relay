package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/identity"
	"vaultwaystation/internal/store"
)

const (
	seededChannel = store.ChannelID("channel-a")
	seededDevice  = identity.Fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	seededPeer    = identity.Fingerprint("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
)

// writeConfig 在目录中写一份可用的配置，返回其路径。
func writeConfig(t *testing.T, dir string) string {
	t.Helper()

	text := `version = 1

[server]
listen = "127.0.0.1:8787"
data_dir = ` + strconv.Quote(filepath.Join(dir, "data")) + `

[transport]
mode = "pinned"
cert_file = "relay.crt"
key_file = "relay.key"

[limits]
devices_per_channel = 16
`
	path := filepath.Join(dir, "waystation.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}
	return path
}

// seed 向存储中写入一份样例数据。
func seed(t *testing.T, configPath string) {
	t.Helper()

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	opened, err := store.Open(cfg.StorePath())
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	defer func() { _ = opened.Close() }()

	channel := store.Channel{ID: seededChannel, Alias: "vault-example", CreatedAt: time.Unix(1700000000, 0).UTC()}
	if err := opened.CreateChannel(channel); err != nil {
		t.Fatalf("建立频道失败：%v", err)
	}
	device := store.Device{
		Fingerprint:  seededDevice,
		PublicKey:    []byte("public-key"),
		Label:        "device-a",
		RegisteredAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := opened.AddDevice(channel.ID, device); err != nil {
		t.Fatalf("写入设备失败：%v", err)
	}
	record := store.Record{
		Fingerprint: seededDevice,
		Sequence:    3,
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Payload:     []byte("ciphertext"),
		Signature:   []byte("signature"),
	}
	if _, err := opened.PutRecord(channel.ID, record); err != nil {
		t.Fatalf("写入记录失败：%v", err)
	}
	revocation := store.Revocation{
		Fingerprint: seededPeer,
		By:          seededDevice,
		At:          time.Unix(1700000000, 0).UTC(),
	}
	if err := opened.Revoke(channel.ID, revocation); err != nil {
		t.Fatalf("写入吊销纪录失败：%v", err)
	}
}

func TestInitWritesUsableConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.toml")

	code, stdout, stderr := run("init", "--config", path)

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if stderr != "" {
		t.Errorf("标准错误应为空，实际为 %q", stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取生成的配置失败：%v", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("生成的配置不可解析：%v", err)
	}
	if !cfg.Registration.Enabled {
		t.Error("生成的配置未开启注册")
	}

	// 标准输出里给出的凭证，其摘要必须与写进配置的摘要一致，
	// 否则这份凭证交给设备也注册不上。
	credential := findCredential(t, stdout)
	if config.DigestCredential(credential) != cfg.Registration.CredentialDigest {
		t.Errorf("标准输出给出的凭证 %q 与配置中的摘要不符", credential)
	}
}

// findCredential 从输出中取出那枚六十四位十六进制的注册凭证。
func findCredential(t *testing.T, stdout string) string {
	t.Helper()

	for _, line := range strings.Split(stdout, "\n") {
		token := strings.TrimSpace(line)
		if len(token) != 64 {
			continue
		}
		if _, err := hex.DecodeString(token); err == nil {
			return token
		}
	}
	t.Fatalf("标准输出中找不到注册凭证：%q", stdout)
	return ""
}

func TestInitKeepsGivenCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.toml")

	code, stdout, stderr := run("init", "--config", path, "--credential", "credential-for-tests")

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "credential-for-tests") {
		t.Error("标准输出未回显给定的凭证")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取生成的配置失败：%v", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatalf("生成的配置不可解析：%v", err)
	}
	if cfg.Registration.CredentialDigest != config.DigestCredential("credential-for-tests") {
		t.Errorf("凭证摘要不符：%q", cfg.Registration.CredentialDigest)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.toml")
	if code, _, stderr := run("init", "--config", path); code != exitOK {
		t.Fatalf("首次生成失败：%q", stderr)
	}

	code, _, stderr := run("init", "--config", path)

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "已存在") {
		t.Errorf("标准错误未说明文件已存在：%q", stderr)
	}
}

func TestInitRejectsUnknownFlag(t *testing.T) {
	code, _, _ := run("init", "--nonexistent")

	if code != exitUsage {
		t.Fatalf("退出码为 %d，期望 %d", code, exitUsage)
	}
}

func TestLabelOfFallsBackToPlaceholder(t *testing.T) {
	if got := labelOf(""); got != "（未命名）" {
		t.Errorf("空别名显示为 %q，期望占位说法", got)
	}
	if got := labelOf("device-a"); got != "device-a" {
		t.Errorf("别名显示为 %q，期望原样输出", got)
	}
}

func TestListReportsChannelsDevicesRecordsAndRevocations(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfig(t, dir)
	seed(t, configPath)

	code, stdout, stderr := run("list", "--config", configPath)

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	for _, want := range []string{string(seededChannel), "vault-example", seededDevice.String(), "device-a", "序号 3", seededPeer.String(), "吊销名单 1 条"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("标准输出不含 %q：\n%s", want, stdout)
		}
	}
}

func TestListWithoutChannels(t *testing.T) {
	configPath := writeConfig(t, t.TempDir())

	code, stdout, stderr := run("list", "--config", configPath)

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "尚无频道") {
		t.Errorf("标准输出未说明尚无频道：%q", stdout)
	}
}

func TestListReportsMissingConfig(t *testing.T) {
	code, _, stderr := run("list", "--config", filepath.Join(t.TempDir(), "missing.toml"))

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "执行失败") {
		t.Errorf("标准错误未说明失败原因：%q", stderr)
	}
}

func TestRecoverRemovesRevocation(t *testing.T) {
	dir := t.TempDir()
	configPath := writeConfig(t, dir)
	seed(t, configPath)

	code, stdout, stderr := run("recover", "--config", configPath,
		"--channel", string(seededChannel), "--device", seededPeer.String())

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, seededPeer.String()) {
		t.Errorf("标准输出未说明被恢复的设备：%q", stdout)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	opened, err := store.Open(cfg.StorePath())
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	defer func() { _ = opened.Close() }()

	if _, err := opened.Revocation(seededChannel, seededPeer); err == nil {
		t.Error("吊销纪录仍在存储中")
	}
}

func TestRecoverRequiresBothFlags(t *testing.T) {
	configPath := writeConfig(t, t.TempDir())

	for _, args := range [][]string{
		{"recover", "--config", configPath, "--channel", string(seededChannel)},
		{"recover", "--config", configPath, "--device", seededPeer.String()},
	} {
		code, _, stderr := run(args...)
		if code != exitUsage {
			t.Errorf("%v 的退出码为 %d，期望 %d", args, code, exitUsage)
		}
		if !strings.Contains(stderr, "--channel") {
			t.Errorf("%v 的标准错误未说明缺少参数：%q", args, stderr)
		}
	}
}

func TestRecoverRejectsMalformedFingerprint(t *testing.T) {
	configPath := writeConfig(t, t.TempDir())

	code, _, stderr := run("recover", "--config", configPath, "--channel", string(seededChannel), "--device", "不合规")

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "执行失败") {
		t.Errorf("标准错误未说明失败原因：%q", stderr)
	}
}

func TestRecoverReportsMissingRevocation(t *testing.T) {
	configPath := writeConfig(t, t.TempDir())

	code, _, stderr := run("recover", "--config", configPath,
		"--channel", string(seededChannel), "--device", seededPeer.String())

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "未被吊销") {
		t.Errorf("标准错误未说明设备未被吊销：%q", stderr)
	}
}
