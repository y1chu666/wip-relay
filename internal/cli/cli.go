// Package cli 实现 waystation 命令行的参数分发。
//
// 本包只负责识别子命令、装配下层并输出结果，业务规则不写在这里，
// 使各子命令能够脱离命令行单独测试。
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"vaultwaystation/internal/buildinfo"
	"vaultwaystation/internal/config"
	"vaultwaystation/internal/store"
)

// 退出码沿用惯例：0 表示成功，1 表示执行失败，2 表示用法错误。
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

// defaultConfigPath 是各子命令 --config 的默认取值。
const defaultConfigPath = "waystation.toml"

const usage = `用法：waystation <子命令> [选项]

子命令：
  init      生成配置样例，并写下一枚注册凭证
  list      列出频道、设备、状态记录与吊销名单
  recover   把设备移出吊销名单
  version   输出版本信息
  help      输出本说明

各子命令都接受 --config 指定配置文件，默认取当前目录下的 waystation.toml。
list 与 recover 直接打开存储文件，因此需要先停止正在运行的服务。
`

// Run 执行一次命令行调用，返回进程退出码。
//
// args 已由调用方去掉程序名；标准输出与标准错误作为参数传入，便于测试断言输出内容。
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, buildinfo.String())
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "list":
		return runList(args[1:], stdout, stderr)
	case "recover":
		return runRecover(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "未知子命令：%s\n", args[0])
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

// newFlagSet 建立一个把用法说明写到标准错误的参数集。
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

// fail 汇报一处错误，并给出失败退出码。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "执行失败：%v\n", err)
	return exitFail
}

// newCredential 生成一枚注册凭证。
func newCredential() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成注册凭证：%w", err)
	}
	return hex.EncodeToString(buf), nil
}

// writeExclusive 写入新文件，已存在时不覆盖。
//
// 配置文件一旦被误删重写，代价是设备全部要重新注册，因此这里宁可直接失败。
func writeExclusive(path, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s 已存在，如需重写请先把它移走", path)
		}
		return fmt.Errorf("写入 %s：%w", path, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := io.WriteString(file, content); err != nil {
		return fmt.Errorf("写入 %s：%w", path, err)
	}
	return nil
}

// openStore 读取配置并打开存储。
func openStore(configPath string) (*config.Config, *store.Store, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, err
	}

	opened, err := store.Open(cfg.StorePath())
	if err != nil {
		return nil, nil, fmt.Errorf("%w；若服务正在运行，请先停止它再试", err)
	}
	return cfg, opened, nil
}
