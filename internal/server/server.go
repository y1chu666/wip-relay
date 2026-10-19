// Package server 把配置、存储、身份与接口装配成一个可运行的中继服务。
//
// 装配只发生在本包：命令行、接口与存储互不知晓彼此，它们的组合方式写在这里。
// 本包也负责配置重载——重载靠数据目录里的请求文件，不依赖信号，各平台行为一致。
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/y1chu666/wip-relay/internal/api"
	"github.com/y1chu666/wip-relay/internal/config"
	"github.com/y1chu666/wip-relay/internal/store"
)

// reloadInterval 是检查重载请求的间隔。
//
// 重载是人工动作，秒级延迟无妨，因此不必引入文件系统事件监听带来的平台差异。
const reloadInterval = 2 * time.Second

// shutdownTimeout 是收到停止信号后等待在途请求收尾的时间。
const shutdownTimeout = 10 * time.Second

// readHeaderTimeout 限制请求头的读取时长，避免慢速连接长期占住资源。
const readHeaderTimeout = 10 * time.Second

// 只设读头超时挡不住慢速正文：验签之前就要把正文收完，因此读整条请求也要有时限。
// 各请求都是几百字节的 JSON，三十秒足够；空闲连接不必久留，一分钟即断。
const (
	readTimeout  = 30 * time.Second
	writeTimeout = 30 * time.Second
	idleTimeout  = 60 * time.Second
)

// newHTTPServer 按监听地址装配 HTTP 服务。留成函数便于用例核对超时一类的取值。
func newHTTPServer(handler http.Handler, listen string) *http.Server {
	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// Options 是启动服务所需的信息。
type Options struct {
	// ConfigPath 是配置文件位置。
	ConfigPath string
	// Stderr 接收日志；留空时写到标准错误。
	Stderr io.Writer
}

// Run 启动服务并阻塞，直到 ctx 结束。
func Run(ctx context.Context, options Options) error {
	settings, err := config.Load(options.ConfigPath)
	if err != nil {
		return err
	}

	level := new(slog.LevelVar)
	level.Set(logLevel(settings.Log.Level))
	logger := slog.New(slog.NewTextHandler(options.stderr(), &slog.HandlerOptions{Level: level}))

	opened, err := store.Open(settings.StorePath())
	if err != nil {
		return err
	}
	defer func() { _ = opened.Close() }()

	key, err := loadOrCreateKey(settings.KeyPath())
	if err != nil {
		return err
	}

	middle := api.New(settings, opened, key, logger)
	httpServer := newHTTPServer(middle.Handler(), settings.Server.Listen)

	go watchReload(ctx, options.ConfigPath, middle, level, logger)

	logger.Info("中继服务已启动",
		"监听", settings.Server.Listen,
		"传输级别", settings.Transport.Mode,
		"数据目录", settings.Server.DataDir,
		"服务端指纹", key.Fingerprint().String())

	serveErr := make(chan error, 1)
	go func() { serveErr <- listen(httpServer, settings, logger) }()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		logger.Info("正在停止服务")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("停止服务：%w", err)
	}
	return nil
}

// listen 按传输级别决定是否启用传输层加密。
//
// 明文一级只影响服务端是否加密，客户端那一侧的四级校验是另一回事：
// 客户端自己决定是否接受未加密的中继。
func listen(httpServer *http.Server, settings *config.Config, logger *slog.Logger) error {
	plain := settings.Transport.Mode == config.ModePlaintext
	if plain {
		logger.Warn("传输级别为明文，注册与退役等破坏性操作将被拒绝")
	}

	var err error
	if plain {
		err = httpServer.ListenAndServe()
	} else {
		err = httpServer.ListenAndServeTLS(settings.Transport.CertFile, settings.Transport.KeyFile)
	}

	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("监听 %s：%w", settings.Server.Listen, err)
}

// watchReload 轮询重载请求文件，收到请求就重新读取配置。
func watchReload(ctx context.Context, configPath string, middle *api.Server, level *slog.LevelVar, logger *slog.Logger) {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		reloadOnce(configPath, middle, level, logger)
	}
}

// reloadOnce 处理一次重载请求；没有请求或重载失败都返回假。
//
// 配置读坏时保留原配置：一份写错的配置不该让正在服务的进程失败。
func reloadOnce(configPath string, middle *api.Server, level *slog.LevelVar, logger *slog.Logger) bool {
	path := middle.Settings().ReloadRequestPath()
	if _, err := os.Stat(path); err != nil {
		return false
	}
	if err := os.Remove(path); err != nil {
		logger.Error("移除重载请求失败", "原因", err)
		return false
	}

	settings, err := config.Load(configPath)
	if err != nil {
		logger.Error("重新读取配置失败，继续沿用原配置", "原因", err)
		return false
	}

	before := middle.Settings()
	middle.Reload(settings)
	level.Set(logLevel(settings.Log.Level))
	logger.Info("配置已重载")

	if before.Server.Listen != settings.Server.Listen {
		logger.Warn("监听地址的改动需要重启才能生效",
			"原地址", before.Server.Listen, "新地址", settings.Server.Listen)
	}
	return true
}

// logLevel 把配置中的级别名换成日志库的级别。
// 配置校验已经限定取值范围，这里仍给出兜底，以免日后新增级别时静默丢弃日志。
func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (o Options) stderr() io.Writer {
	if o.Stderr == nil {
		return os.Stderr
	}
	return o.Stderr
}
