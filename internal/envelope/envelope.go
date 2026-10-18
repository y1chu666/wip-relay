// Package envelope 定义请求与响应的签名信封。
//
// 签名覆盖方法、路径与身份，使一份签名无法被挪用到其他端点或冒用其他设备。
// 规范文本以版本前缀开头，一经发布不得修改，只能另起新的前缀。
package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"vaultwaystation/internal/identity"
)

// ClockSkew 是允许的时钟偏差，超出即拒绝，以免陈旧请求被重放。
const ClockSkew = 60 * time.Second

// NonceBytes 是一次性随机值的字节数。
const NonceBytes = 32

const (
	requestContext  = "waystation-request-v1"
	responseContext = "waystation-response-v1"
)

var (
	// ErrTimestampSkew 表示时间戳超出允许窗口。
	ErrTimestampSkew = errors.New("时间戳超出允许窗口")
	// ErrFingerprint 表示指纹与先前钉住的公钥不符。
	ErrFingerprint = errors.New("指纹与钉住的公钥不符")
)

// NewNonce 生成一个一次性随机值。
func NewNonce() (string, error) {
	buf := make([]byte, NonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成一次性随机值：%w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Request 是请求中参与签名的要素。
type Request struct {
	Method      string
	Path        string
	Fingerprint identity.Fingerprint
	Timestamp   time.Time
	Nonce       string
	Body        []byte
}

// SigningText 返回请求的规范文本。
func (r Request) SigningText() string {
	return strings.Join([]string{
		requestContext,
		r.Method,
		r.Path,
		r.Fingerprint.String(),
		strconv.FormatInt(r.Timestamp.Unix(), 10),
		r.Nonce,
		digest(r.Body),
	}, "\n")
}

// Signature 计算请求签名。
func (r Request) Signature(key *identity.KeyPair) []byte {
	return key.Sign([]byte(r.SigningText()))
}

// Verify 校验请求签名。
//
// 先验签名再判新鲜度，避免把「时间戳可疑但签名有效」与「签名伪造」混为一谈：
// 只有签名成立时，时间偏差才值得反馈给对端用于校时。
func (r Request) Verify(public ed25519.PublicKey, signature []byte, now time.Time) error {
	if err := identity.Verify(public, []byte(r.SigningText()), signature); err != nil {
		return err
	}
	return r.CheckFreshness(now)
}

// CheckFreshness 检查时间戳是否落在允许窗口之内。
func (r Request) CheckFreshness(now time.Time) error {
	offset := now.Sub(r.Timestamp)
	if offset < 0 {
		offset = -offset
	}
	if offset > ClockSkew {
		return fmt.Errorf("%w：偏差 %s", ErrTimestampSkew, offset.Round(time.Second))
	}
	return nil
}

// Response 是响应中参与签名的要素。
type Response struct {
	Fingerprint identity.Fingerprint
	Status      int
	Body        []byte
}

// SigningText 返回响应的规范文本。
func (r Response) SigningText() string {
	return strings.Join([]string{
		responseContext,
		r.Fingerprint.String(),
		strconv.Itoa(r.Status),
		digest(r.Body),
	}, "\n")
}

// Signature 计算响应签名。
func (r Response) Signature(key *identity.KeyPair) []byte {
	return key.Sign([]byte(r.SigningText()))
}

// Verify 校验响应签名，并要求服务端指纹与首次配对时钉住的一致。
func (r Response) Verify(pinned identity.Fingerprint, public ed25519.PublicKey, signature []byte) error {
	if r.Fingerprint != pinned {
		return ErrFingerprint
	}
	return identity.Verify(public, []byte(r.SigningText()), signature)
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
