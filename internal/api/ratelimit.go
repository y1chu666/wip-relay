package api

import (
	"sync"
	"time"
)

// window 是限流的统计周期。
const window = time.Minute

// limiter 按固定周期统计每个键的请求数。
//
// 固定窗口在周期交界处可能放过接近两倍的请求，但这里的目的是挡住失控的客户端与
// 粗糙的洪水，不是精细计费，因此不值得引入更复杂的算法。
type limiter struct {
	mu      sync.Mutex
	limit   int
	buckets map[string]*bucket
}

type bucket struct {
	start time.Time
	count int
}

func newLimiter(limit int) *limiter {
	return &limiter{limit: limit, buckets: make(map[string]*bucket)}
}

// setLimit 换用新的配额，供配置重载使用。
func (l *limiter) setLimit(limit int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.limit = limit
}

// allow 报告该键在当前周期内是否还有配额。
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.forget(now)

	current, ok := l.buckets[key]
	if !ok || now.Sub(current.start) >= window {
		l.buckets[key] = &bucket{start: now, count: 1}
		return true
	}

	current.count++
	return current.count <= l.limit
}

// forget 清除已经过期的计数，使表的规模与活跃来源数相称。
func (l *limiter) forget(now time.Time) {
	for key, current := range l.buckets {
		if now.Sub(current.start) >= window {
			delete(l.buckets, key)
		}
	}
}
