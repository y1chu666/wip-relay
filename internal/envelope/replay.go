package envelope

import (
	"sync"
	"time"

	"github.com/y1chu666/wip-relay/internal/identity"
)

// DefaultReplayLimit 是判重表允许保留的条目数上限。
//
// 设上限是为了让判重表不至于被大量陌生指纹撑爆内存；超出时淘汰最早过期的条目。
const DefaultReplayLimit = 1 << 16

// ReplayGuard 记录窗口期内出现过的一次性随机值，拒绝重复使用。
//
// 判重按「指纹与随机值」的组合进行，以免不同设备偶然取到相同随机值时互相影响。
type ReplayGuard struct {
	mu     sync.Mutex
	window time.Duration
	limit  int
	seen   map[string]time.Time
}

// NewReplayGuard 创建判重器。
//
// window 应当不小于允许的时钟偏差，否则陈旧随机值会在窗口结束前被遗忘。
func NewReplayGuard(window time.Duration) *ReplayGuard {
	if window <= 0 {
		window = ClockSkew
	}
	return &ReplayGuard{
		window: window,
		limit:  DefaultReplayLimit,
		seen:   make(map[string]time.Time),
	}
}

// Accept 判断该随机值是否为首次出现。
//
// 返回 false 表示窗口期内已经出现过，调用方应当拒绝该请求。
func (g *ReplayGuard) Accept(fingerprint identity.Fingerprint, nonce string, now time.Time) bool {
	key := fingerprint.String() + "\x00" + nonce

	g.mu.Lock()
	defer g.mu.Unlock()

	g.sweep(now)
	if _, repeated := g.seen[key]; repeated {
		return false
	}

	g.seen[key] = now.Add(g.window)
	g.enforceLimit()
	return true
}

// sweep 清除已经过期的条目。每次判重都顺手清理，无需另起定时任务。
func (g *ReplayGuard) sweep(now time.Time) {
	for key, expiry := range g.seen {
		if !now.Before(expiry) {
			delete(g.seen, key)
		}
	}
}

// enforceLimit 在条目超限时按过期时间淘汰最早的记录。
func (g *ReplayGuard) enforceLimit() {
	for len(g.seen) > g.limit {
		var oldestKey string
		var oldest time.Time

		for key, expiry := range g.seen {
			if oldest.IsZero() || expiry.Before(oldest) {
				oldestKey, oldest = key, expiry
			}
		}
		delete(g.seen, oldestKey)
	}
}
