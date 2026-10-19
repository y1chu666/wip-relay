package envelope

import (
	"crypto/ed25519"
	"strconv"
	"strings"
	"time"

	"github.com/y1chu666/wip-relay/internal/identity"
)

const recordContext = "wip-relay-record-v1"

// Record 是状态记录中参与签名的要素。
//
// 记录的签名由设备本人完成，服务端不得代劳：其他设备据此确认记录确实出自该设备，
// 而不是由中继伪造。
type Record struct {
	Fingerprint identity.Fingerprint
	Channel     string
	Sequence    int64
	CollectedAt time.Time
	Payload     []byte
}

// SigningText 返回记录的规范文本。
//
// 采集时间一律折算为协调世界时，否则同一时刻在不同时区会算出不同的签名。
func (r Record) SigningText() string {
	return strings.Join([]string{
		recordContext,
		r.Channel,
		r.Fingerprint.String(),
		strconv.FormatInt(r.Sequence, 10),
		r.CollectedAt.UTC().Format(time.RFC3339),
		digest(r.Payload),
	}, "\n")
}

// Signature 计算记录签名。
func (r Record) Signature(key *identity.KeyPair) []byte {
	return key.Sign([]byte(r.SigningText()))
}

// Verify 校验记录签名。
func (r Record) Verify(public ed25519.PublicKey, signature []byte) error {
	return identity.Verify(public, []byte(r.SigningText()), signature)
}
