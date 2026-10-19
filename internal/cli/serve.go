package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/y1chu666/wip-relay/internal/config"
	"github.com/y1chu666/wip-relay/internal/server"
)

// runServe 启动中继服务，直到收到中断或终止信号。
func runServe(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("serve", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件位置")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	// 服务端不依赖信号做重载，只把信号当作停止请求，因此各平台行为一致。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runServer(ctx, server.Options{ConfigPath: *configPath, Stderr: stderr}); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "服务已停止。")
	return exitOK
}

// runServer 指向真正的启动函数。
//
// 留成变量是为了让用例替换它：测试不必真正监听端口，也能走到正常停止之后的那几行。
var runServer = server.Run

// runReload 请正在运行的服务重新读取配置。
func runReload(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("reload", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件位置")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	// 先自己读一遍：配置写错时应当在这里就报错，而不是让运行中的服务读到一份坏配置。
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(stderr, err)
	}

	path := cfg.ReloadRequestPath()
	// 数据目录可能尚未建立：先把请求落下，服务启动后读到它即可。
	if err := os.MkdirAll(cfg.Server.DataDir, 0o700); err != nil {
		return fail(stderr, fmt.Errorf("建立数据目录 %s：%w", cfg.Server.DataDir, err))
	}

	marker := []byte(time.Now().UTC().Format(time.RFC3339) + "\n")
	if err := os.WriteFile(path, marker, 0o600); err != nil {
		return fail(stderr, fmt.Errorf("写入重载请求 %s：%w", path, err))
	}

	fmt.Fprintf(stdout, "已请求重新读取 %s；服务会在数秒内生效，结果记在服务的日志里。\n", *configPath)
	return exitOK
}
