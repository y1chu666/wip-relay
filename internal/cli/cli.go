// Package cli 实现 waystation 命令行的参数分发。
//
// 本包只负责识别子命令并交给下层实现，业务规则不写在这里，
// 使各子命令能够脱离命令行单独测试。
package cli

import (
	"fmt"
	"io"

	"vaultwaystation/internal/buildinfo"
)

// 退出码沿用惯例：0 表示成功，2 表示用法错误。
const (
	exitOK    = 0
	exitUsage = 2
)

const usage = `用法：waystation <子命令>

子命令：
  version   输出版本信息
  help      输出本说明
`

// Run 执行一次命令行调用，返回进程退出码。
//
// args 已去掉程序名；标准输出与标准错误由调用方传入，便于测试断言输出内容。
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
	default:
		fmt.Fprintf(stderr, "未知子命令：%s\n", args[0])
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
}
