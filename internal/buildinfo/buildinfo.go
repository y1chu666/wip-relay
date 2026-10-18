// Package buildinfo 提供构建期注入的版本信息。
//
// 三个变量都由发布构建的链接参数注入；源码中的取值只用于未注入时的开发构建。
package buildinfo

import "fmt"

var (
	// Version 是语义化版本号。
	Version = "dev"
	// Commit 是构建所用提交的短标识。
	Commit = "none"
	// Date 是构建时间。
	Date = "unknown"
)

// String 返回一行版本描述，供命令行输出。
func String() string {
	return fmt.Sprintf("waystation %s (commit %s, built %s)", Version, Commit, Date)
}
