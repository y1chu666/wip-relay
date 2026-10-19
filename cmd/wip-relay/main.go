// wip-relay 是 WIP Relay 的中继服务端。
package main

import (
	"os"

	"github.com/y1chu666/wip-relay/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
