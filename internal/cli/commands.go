package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/y1chu666/wip-relay/internal/config"
	"github.com/y1chu666/wip-relay/internal/identity"
	"github.com/y1chu666/wip-relay/internal/store"
)

// runInit 生成配置样例，并写下一枚注册凭证。
func runInit(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("init", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件的写入位置")
	credential := flags.String("credential", "", "注册凭证；留空时随机生成一枚")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	value := *credential
	if value == "" {
		generated, err := newCredential()
		if err != nil {
			return fail(stderr, err)
		}
		value = generated
	}

	text, err := config.WithCredential(value)
	if err != nil {
		return fail(stderr, err)
	}
	if err := writeExclusive(*configPath, text); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, "配置已写入 %s，注册凭证如下：\n\n    %s\n\n", *configPath, value)
	fmt.Fprintln(stdout, "凭证只在此显示一次，请立即交给需要注册的设备；服务端只保存它的摘要。")
	return exitOK
}

// runList 列出频道、设备、状态记录与吊销名单。
func runList(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("list", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件位置")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	_, opened, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer func() { _ = opened.Close() }()

	channels, err := opened.Channels()
	if err != nil {
		return fail(stderr, err)
	}
	if len(channels) == 0 {
		fmt.Fprintln(stdout, "尚无频道。")
		return exitOK
	}

	for _, channel := range channels {
		fmt.Fprintf(stdout, "频道 %s（%s）\n", channel.ID, channel.Alias)

		devices, err := opened.Devices(channel.ID)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "  设备 %d 台：\n", len(devices))
		for _, device := range devices {
			fmt.Fprintf(stdout, "    %s  注册于 %s\n", device.Fingerprint, stamp(device.RegisteredAt))
		}

		records, err := opened.Records(channel.ID)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "  状态记录 %d 条：\n", len(records))
		for _, record := range records {
			fmt.Fprintf(stdout, "    %s  序号 %d  采集于 %s  内容 %d 字节\n",
				record.Fingerprint, record.Sequence, stamp(record.CollectedAt), len(record.Payload))
		}

		revocations, err := opened.Revocations(channel.ID)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "  吊销名单 %d 条：\n", len(revocations))
		for _, item := range revocations {
			fmt.Fprintf(stdout, "    %s  由 %s 于 %s\n", item.Fingerprint, item.By, stamp(item.At))
		}
	}
	return exitOK
}

// runRecover 把设备移出吊销名单。
func runRecover(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("recover", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件位置")
	channel := flags.String("channel", "", "频道标识")
	device := flags.String("device", "", "要移出吊销名单的设备指纹")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *channel == "" || *device == "" {
		fmt.Fprint(stderr, "recover 需要同时给出 --channel 与 --device。\n")
		return exitUsage
	}

	fingerprint, err := identity.ParseFingerprint(*device)
	if err != nil {
		return fail(stderr, err)
	}

	_, opened, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer func() { _ = opened.Close() }()

	if err := opened.Forgive(store.ChannelID(*channel), fingerprint); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, "已把 %s 移出频道 %s 的吊销名单；该设备需要重新注册才能继续使用。\n", fingerprint, *channel)
	return exitOK
}

// runToken 为已有频道生成新的令牌。
//
// 旧版本按别名建频道，没有令牌这一项；升级之后要为这些频道补一枚，
// 否则新设备只能加入新建的频道。重新执行会让旧令牌失效。
func runToken(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("token", stderr)
	configPath := flags.String("config", defaultConfigPath, "配置文件位置")
	channel := flags.String("channel", "", "频道标识")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if *channel == "" {
		fmt.Fprint(stderr, "token 需要给出 --channel。\n")
		return exitUsage
	}

	_, opened, err := openStore(*configPath)
	if err != nil {
		return fail(stderr, err)
	}
	defer func() { _ = opened.Close() }()

	stored, err := opened.Channel(store.ChannelID(*channel))
	if err != nil {
		return fail(stderr, err)
	}

	value, err := newChannelToken()
	if err != nil {
		return fail(stderr, err)
	}
	sum := sha256.Sum256([]byte(value))
	stored.TokenHash = sum[:]
	if err := opened.UpdateChannel(stored); err != nil {
		return fail(stderr, err)
	}

	fmt.Fprintf(stdout, "频道 %s（%s）的新令牌如下：\n\n    %s\n\n", stored.ID, stored.Alias, value)
	fmt.Fprintln(stdout, "令牌只在此显示一次；再次执行本命令会让旧令牌失效。")
	return exitOK
}

// newChannelToken 生成一枚频道令牌。
func newChannelToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成频道令牌：%w", err)
	}
	return hex.EncodeToString(buf), nil
}

// stamp 统一把时间折算为协调世界时输出。
func stamp(at time.Time) string {
	return at.UTC().Format(time.RFC3339)
}
