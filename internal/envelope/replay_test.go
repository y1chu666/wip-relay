package envelope

import (
	"testing"
	"time"

	"github.com/y1chu666/wip-relay/internal/identity"
)

const (
	deviceA = identity.Fingerprint("device-a")
	deviceB = identity.Fingerprint("device-b")
)

func TestReplayGuardRejectsRepeatedNonce(t *testing.T) {
	guard := NewReplayGuard(ClockSkew)
	now := time.Unix(1700000000, 0)

	if !guard.Accept(deviceA, "nonce", now) {
		t.Fatal("首次出现的随机值应当被接受")
	}
	if guard.Accept(deviceA, "nonce", now.Add(time.Second)) {
		t.Fatal("窗口期内重复的随机值应当被拒绝")
	}
}

func TestReplayGuardSeparatesDevices(t *testing.T) {
	guard := NewReplayGuard(ClockSkew)
	now := time.Unix(1700000000, 0)

	if !guard.Accept(deviceA, "nonce", now) {
		t.Fatal("设备甲的随机值应当被接受")
	}
	if !guard.Accept(deviceB, "nonce", now) {
		t.Fatal("不同设备取到相同随机值时不应互相影响")
	}
}

func TestReplayGuardForgetsExpiredNonce(t *testing.T) {
	guard := NewReplayGuard(ClockSkew)
	now := time.Unix(1700000000, 0)

	if !guard.Accept(deviceA, "nonce", now) {
		t.Fatal("首次出现的随机值应当被接受")
	}
	if !guard.Accept(deviceA, "nonce", now.Add(ClockSkew+time.Second)) {
		t.Fatal("窗口结束后的同一随机值应当重新被接受")
	}
}

func TestReplayGuardDefaultsWindow(t *testing.T) {
	for _, window := range []time.Duration{0, -time.Second} {
		if guard := NewReplayGuard(window); guard.window != ClockSkew {
			t.Errorf("窗口 %s 时的实际窗口为 %s，期望 %s", window, guard.window, ClockSkew)
		}
	}
}

func TestReplayGuardEnforcesLimit(t *testing.T) {
	guard := NewReplayGuard(ClockSkew)
	guard.limit = 2
	now := time.Unix(1700000000, 0)

	for offset, nonce := range []string{"1", "2", "3"} {
		guard.Accept(deviceA, nonce, now.Add(time.Duration(offset)*time.Second))
	}

	if len(guard.seen) != guard.limit {
		t.Fatalf("判重表条目数为 %d，期望 %d", len(guard.seen), guard.limit)
	}
	if !guard.Accept(deviceA, "1", now.Add(3*time.Second)) {
		t.Fatal("超过上限后应当淘汰最早条目，以便继续接受新随机值")
	}
}
