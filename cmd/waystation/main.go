// waystation 是 Vault Waystation 的中继服务端。
package main

import (
	"os"

	"vaultwaystation/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
