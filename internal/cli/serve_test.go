package cli

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/server"
)

// writePlaintextConfig 写一份明文传输的配置，使用例不必准备证书。
func writePlaintextConfig(t *testing.T, dir, listen string) string {
	t.Helper()

	text := `version = 1

[server]
listen = ` + strconv.Quote(listen) + `
data_dir = ` + strconv.Quote(filepath.Join(dir, "data")) + `

[transport]
mode = "plaintext"
`
	path := filepath.Join(dir, "waystation.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}
	return path
}

func TestServeReportsStartupFailure(t *testing.T) {
	// 地址能通过配置校验却绑不上，用来确认启动失败会如实返回原因。
	configPath := writePlaintextConfig(t, t.TempDir(), "256.0.0.1:8787")

	code, _, stderr := run("serve", "--config", configPath)

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "监听") {
		t.Errorf("标准错误未说明监听失败：%q", stderr)
	}
}

func TestServeStopsCleanly(t *testing.T) {
	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:8787")

	restore := runServer
	runServer = func(_ context.Context, options server.Options) error {
		if options.ConfigPath != configPath {
			t.Errorf("启动参数中的配置路径为 %q，期望 %q", options.ConfigPath, configPath)
		}
		return nil
	}
	t.Cleanup(func() { runServer = restore })

	code, stdout, stderr := run("serve", "--config", configPath)

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, "服务已停止") {
		t.Errorf("标准输出未说明服务已停止：%q", stdout)
	}
}

func TestServeReportsShutdownFailure(t *testing.T) {
	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:8787")

	restore := runServer
	runServer = func(context.Context, server.Options) error {
		return os.ErrPermission
	}
	t.Cleanup(func() { runServer = restore })

	code, _, stderr := run("serve", "--config", configPath)

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "执行失败") {
		t.Errorf("标准错误未说明失败原因：%q", stderr)
	}
}

func TestServeRejectsUnknownFlag(t *testing.T) {
	if code, _, _ := run("serve", "--nonexistent"); code != exitUsage {
		t.Fatalf("退出码为 %d，期望 %d", code, exitUsage)
	}
}

func TestReloadWritesRequestFile(t *testing.T) {
	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:8787")

	code, stdout, stderr := run("reload", "--config", configPath)

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d；标准错误 %q", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, configPath) {
		t.Errorf("标准输出未提及配置文件：%q", stdout)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	if _, err := os.Stat(cfg.ReloadRequestPath()); err != nil {
		t.Errorf("未留下重载请求文件：%v", err)
	}
}

func TestReloadReportsBadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.toml")
	if err := os.WriteFile(path, []byte("这份配置读不出来"), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}

	code, _, stderr := run("reload", "--config", path)

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "执行失败") {
		t.Errorf("标准错误未说明失败原因：%q", stderr)
	}
}

func TestReloadReportsUnwritableRequestFile(t *testing.T) {
	// 数据目录无法建立，重载请求自然写不出去。
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, []byte("占位"), 0o600); err != nil {
		t.Fatalf("写入占位文件失败：%v", err)
	}
	configPath := writePlaintextConfig(t, dir, "127.0.0.1:8787")

	text := `version = 1

[server]
listen = "127.0.0.1:8787"
data_dir = ` + strconv.Quote(blocked+"/data") + `

[transport]
mode = "plaintext"
`
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatalf("改写配置失败：%v", err)
	}

	code, _, stderr := run("reload", "--config", configPath)

	if code != exitFail {
		t.Fatalf("退出码为 %d，期望 %d", code, exitFail)
	}
	if !strings.Contains(stderr, "数据目录") {
		t.Errorf("标准错误未说明数据目录不可用：%q", stderr)
	}
}

func TestReloadRejectsUnknownFlag(t *testing.T) {
	if code, _, _ := run("reload", "--nonexistent"); code != exitUsage {
		t.Fatalf("退出码为 %d，期望 %d", code, exitUsage)
	}
}
