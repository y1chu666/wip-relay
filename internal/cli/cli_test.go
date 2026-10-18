package cli

import (
	"bytes"
	"strings"
	"testing"

	"vaultwaystation/internal/buildinfo"
)

// run 以给定参数执行一次调用，返回退出码与两端输出。
func run(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestVersionWritesVersionToStdout(t *testing.T) {
	code, stdout, stderr := run("version")

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d", code, exitOK)
	}
	if !strings.Contains(stdout, buildinfo.Version) {
		t.Errorf("标准输出不含版本号：%q", stdout)
	}
	if stderr != "" {
		t.Errorf("标准错误应为空，实际为 %q", stderr)
	}
}

func TestVersionAcceptsFlagForm(t *testing.T) {
	code, stdout, _ := run("--version")

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d", code, exitOK)
	}
	if stdout == "" {
		t.Error("标准输出为空")
	}
}

func TestHelpWritesUsageToStdout(t *testing.T) {
	code, stdout, stderr := run("help")

	if code != exitOK {
		t.Fatalf("退出码为 %d，期望 %d", code, exitOK)
	}
	if !strings.Contains(stdout, "用法") {
		t.Errorf("标准输出不含用法说明：%q", stdout)
	}
	if stderr != "" {
		t.Errorf("标准错误应为空，实际为 %q", stderr)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	code, stdout, stderr := run()

	if code != exitUsage {
		t.Fatalf("退出码为 %d，期望 %d", code, exitUsage)
	}
	if stdout != "" {
		t.Errorf("标准输出应为空，实际为 %q", stdout)
	}
	if !strings.Contains(stderr, "用法") {
		t.Errorf("标准错误不含用法说明：%q", stderr)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	code, _, stderr := run("frobnicate")

	if code != exitUsage {
		t.Fatalf("退出码为 %d，期望 %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "未知子命令") {
		t.Errorf("标准错误未指出未知子命令：%q", stderr)
	}
}
