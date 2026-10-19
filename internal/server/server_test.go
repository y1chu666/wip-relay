package server

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/y1chu666/wip-relay/internal/api"
	"github.com/y1chu666/wip-relay/internal/config"
	"github.com/y1chu666/wip-relay/internal/identity"
	"github.com/y1chu666/wip-relay/internal/store"
)

// writePlaintextConfig 写一份明文传输的配置：测试不需要真证书。
func writePlaintextConfig(t *testing.T, dir, listen, level string) string {
	t.Helper()

	text := `version = 1

[server]
listen = ` + strconv.Quote(listen) + `
data_dir = ` + strconv.Quote(filepath.Join(dir, "data")) + `

[transport]
mode = "plaintext"

[log]
level = ` + strconv.Quote(level) + `
`
	path := filepath.Join(dir, "wip-relay.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("写入配置失败：%v", err)
	}
	return path
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestLoadOrCreateKeyCreatesThenReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.key")

	first, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("首次生成密钥失败：%v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("密钥文件未建立：%v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("密钥文件权限为 %o，期望 %o", perm, keyFileMode)
	}

	second, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("再次读取密钥失败：%v", err)
	}
	if second.Fingerprint() != first.Fingerprint() {
		t.Error("再次读取得到的不是同一把密钥")
	}
}

func TestLoadOrCreateKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(path, []byte("不是十六进制\n"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败：%v", err)
	}

	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("密钥文件不可解析时应当报错")
	}
}

func TestLoadOrCreateKeyReportsReadFailure(t *testing.T) {
	// 指向目录而不是文件：读取会失败，且不是「不存在」。
	path := t.TempDir()

	_, err := loadOrCreateKey(path)

	if err == nil {
		t.Fatal("读取目录作为密钥文件时应当报错")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("错误不应被当作文件不存在：%v", err)
	}
}

func TestLogLevelMapping(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"未知取值":  slog.LevelInfo,
	}

	for name, want := range cases {
		if got := logLevel(name); got != want {
			t.Errorf("级别 %q 映射为 %v，期望 %v", name, got, want)
		}
	}
}

// newMiddle 装配一套接口实现，供重载相关的用例使用。
func newMiddle(t *testing.T, configPath string) *api.Server {
	t.Helper()

	settings, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	opened, err := store.Open(settings.StorePath())
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })

	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	return api.New(settings, opened, key, quietLogger())
}

func TestReloadOnceWithoutRequestDoesNothing(t *testing.T) {
	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:8787", "info")
	middle := newMiddle(t, configPath)

	if reloadOnce(configPath, middle, new(slog.LevelVar), quietLogger()) {
		t.Error("没有重载请求时不应重载")
	}
}

func TestReloadOnceAppliesNewSettings(t *testing.T) {
	dir := t.TempDir()
	configPath := writePlaintextConfig(t, dir, "127.0.0.1:8787", "info")
	middle := newMiddle(t, configPath)

	// 改写配置并留下重载请求。
	text := `version = 1

[server]
listen = "127.0.0.1:9999"
data_dir = ` + strconv.Quote(middle.Settings().Server.DataDir) + `

[transport]
mode = "plaintext"

[limits]
requests_per_minute = 42

[log]
level = "debug"
`
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatalf("改写配置失败：%v", err)
	}
	if err := os.WriteFile(middle.Settings().ReloadRequestPath(), []byte("请求\n"), 0o600); err != nil {
		t.Fatalf("写入重载请求失败：%v", err)
	}

	level := new(slog.LevelVar)
	if !reloadOnce(configPath, middle, level, quietLogger()) {
		t.Fatal("有重载请求时应当重载")
	}

	if got := middle.Settings().Limits.RequestsPerMinute; got != 42 {
		t.Errorf("重载后的每分钟请求上限为 %d，期望 42", got)
	}
	if level.Level() != slog.LevelDebug {
		t.Errorf("重载后的日志级别为 %v，期望 %v", level.Level(), slog.LevelDebug)
	}
	if _, err := os.Stat(middle.Settings().ReloadRequestPath()); err == nil {
		t.Error("重载请求文件应被移除")
	}
}

func TestReloadOnceKeepsOldSettingsOnBadConfig(t *testing.T) {
	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:8787", "info")
	middle := newMiddle(t, configPath)
	before := middle.Settings().Limits.RequestsPerMinute

	if err := os.WriteFile(configPath, []byte("这份配置读不出来"), 0o600); err != nil {
		t.Fatalf("改写配置失败：%v", err)
	}
	if err := os.WriteFile(middle.Settings().ReloadRequestPath(), []byte("请求\n"), 0o600); err != nil {
		t.Fatalf("写入重载请求失败：%v", err)
	}

	if reloadOnce(configPath, middle, new(slog.LevelVar), quietLogger()) {
		t.Error("配置不可用时不应报告重载成功")
	}
	if got := middle.Settings().Limits.RequestsPerMinute; got != before {
		t.Errorf("配置不可用时上限被改为 %d，期望保持 %d", got, before)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	server := newHTTPServer(http.NotFoundHandler(), "127.0.0.1:0")

	// 只设读头超时挡不住慢速正文：正文收完之前不会验签，连接就一直被占着。
	if server.ReadHeaderTimeout <= 0 {
		t.Fatalf("未设读头超时：%v", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout <= 0 {
		t.Fatalf("未设读超时：%v", server.ReadTimeout)
	}
	if server.WriteTimeout <= 0 {
		t.Fatalf("未设写超时：%v", server.WriteTimeout)
	}
	if server.IdleTimeout <= 0 {
		t.Fatalf("未设空闲超时：%v", server.IdleTimeout)
	}
	if server.Addr != "127.0.0.1:0" {
		t.Fatalf("监听地址未采用配置值：%q", server.Addr)
	}
}

func TestRunReportsListenFailure(t *testing.T) {
	// 地址能通过配置校验，却绑不上，用来确认启动失败会如实返回原因。
	configPath := writePlaintextConfig(t, t.TempDir(), "256.0.0.1:8787", "error")

	err := Run(context.Background(), Options{ConfigPath: configPath, Stderr: io.Discard})

	if err == nil {
		t.Fatal("地址无法绑定时应当报错")
	}
	if !strings.Contains(err.Error(), "监听") {
		t.Errorf("错误未说明监听失败：%v", err)
	}
}

func TestRunReportsMissingConfig(t *testing.T) {
	err := Run(context.Background(), Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.toml"),
		Stderr:     io.Discard,
	})

	if err == nil {
		t.Fatal("配置不存在时应当报错")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	// 先取一个空闲端口：配置校验不接受端口零，测试又需要一个能真正绑上的地址。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取得空闲端口失败：%v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("释放空闲端口失败：%v", err)
	}

	configPath := writePlaintextConfig(t, t.TempDir(), "127.0.0.1:"+strconv.Itoa(port), "error")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Options{ConfigPath: configPath, Stderr: io.Discard}) }()

	cancel()

	if err := <-done; err != nil {
		t.Fatalf("取消后应当正常退出，实际为：%v", err)
	}
}
