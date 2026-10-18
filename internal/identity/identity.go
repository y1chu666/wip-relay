// Package identity 负责设备密钥的生成、编码与签名校验。
//
// 设备身份就是公钥指纹，服务端不另行分配标识。私钥的编码形式为十六进制，
// 仅便于落盘与传递，不含口令保护，因此存放私钥的文件必须收紧权限，
// 且永远不得进入版本库。
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrBadSignature 表示签名与消息或公钥不符。
var ErrBadSignature = errors.New("签名无效")

// Fingerprint 是公钥的指纹，用作设备身份。
type Fingerprint string

// FingerprintOf 计算公钥指纹：公钥字节的 SHA-256，小写十六进制。
func FingerprintOf(public ed25519.PublicKey) Fingerprint {
	sum := sha256.Sum256(public)
	return Fingerprint(hex.EncodeToString(sum[:]))
}

// ParseFingerprint 解析指纹文本。
func ParseFingerprint(text string) (Fingerprint, error) {
	if !isLowerHex(text, sha256.Size*2) {
		return "", fmt.Errorf("指纹应为 %d 位小写十六进制：%q", sha256.Size*2, text)
	}
	return Fingerprint(text), nil
}

// String 返回指纹文本。
func (f Fingerprint) String() string {
	return string(f)
}

// KeyPair 是设备的密钥对。
type KeyPair struct {
	private ed25519.PrivateKey
}

// Generate 生成新的密钥对。
func Generate() (*KeyPair, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成密钥：%w", err)
	}
	return &KeyPair{private: private}, nil
}

// FromSeed 由种子构造密钥对。
func FromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("种子长度应为 %d 字节，实际为 %d", ed25519.SeedSize, len(seed))
	}
	return &KeyPair{private: ed25519.NewKeyFromSeed(seed)}, nil
}

// Public 返回公钥。
func (k *KeyPair) Public() ed25519.PublicKey {
	return k.private.Public().(ed25519.PublicKey)
}

// Fingerprint 返回本设备的身份。
func (k *KeyPair) Fingerprint() Fingerprint {
	return FingerprintOf(k.Public())
}

// Sign 对消息签名。
func (k *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(k.private, message)
}

// Encode 返回私钥的十六进制编码。
//
// 编码即明文，调用方负责存放位置与文件权限。
func (k *KeyPair) Encode() string {
	return hex.EncodeToString(k.private.Seed())
}

// Decode 解析 Encode 产生的文本。
func Decode(text string) (*KeyPair, error) {
	seed, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("解析私钥：%w", err)
	}
	return FromSeed(seed)
}

// Verify 校验消息签名。
//
// 这里先检查公钥长度，是因为标准库在长度不符时会直接 panic 而不是报错。
func Verify(public ed25519.PublicKey, message, signature []byte) error {
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥长度应为 %d 字节，实际为 %d", ed25519.PublicKeySize, len(public))
	}
	if !ed25519.Verify(public, message, signature) {
		return ErrBadSignature
	}
	return nil
}

func isLowerHex(text string, length int) bool {
	if len(text) != length {
		return false
	}
	for _, r := range text {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
