package identity

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T) *KeyPair {
	t.Helper()

	key, err := Generate()
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	return key
}

func TestGenerateProducesDistinctKeys(t *testing.T) {
	first, second := mustKey(t), mustKey(t)

	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("两次生成的密钥指纹相同")
	}
	if len(first.Public()) != ed25519.PublicKeySize {
		t.Fatalf("公钥长度为 %d，期望 %d", len(first.Public()), ed25519.PublicKeySize)
	}
}

func TestFingerprintIsLowerHex(t *testing.T) {
	fingerprint := mustKey(t).Fingerprint()

	if !isLowerHex(fingerprint.String(), 64) {
		t.Fatalf("指纹不是六十四位小写十六进制：%q", fingerprint)
	}
	if _, err := ParseFingerprint(fingerprint.String()); err != nil {
		t.Fatalf("自身产生的指纹无法解析：%v", err)
	}
}

func TestParseFingerprintRejectsInvalid(t *testing.T) {
	cases := []string{
		"",
		"abc",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("A", 64),
		strings.Repeat("g", 64),
	}

	for _, text := range cases {
		if _, err := ParseFingerprint(text); err == nil {
			t.Errorf("指纹 %q 应当被拒绝", text)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	key := mustKey(t)

	restored, err := Decode(key.Encode())
	if err != nil {
		t.Fatalf("解析私钥失败：%v", err)
	}
	if restored.Fingerprint() != key.Fingerprint() {
		t.Fatal("还原后的指纹与原文不符")
	}

	message := []byte("待签名的内容")
	if err := Verify(key.Public(), message, restored.Sign(message)); err != nil {
		t.Fatalf("还原后的密钥签名无法验证：%v", err)
	}
}

func TestDecodeRejectsInvalidText(t *testing.T) {
	cases := []string{"", "zz", strings.Repeat("a", 62), strings.Repeat("a", 66)}

	for _, text := range cases {
		if _, err := Decode(text); err == nil {
			t.Errorf("私钥文本 %q 应当被拒绝", text)
		}
	}
}

func TestFromSeedRejectsWrongLength(t *testing.T) {
	for _, size := range []int{0, 31, 33, 64} {
		if _, err := FromSeed(make([]byte, size)); err == nil {
			t.Errorf("长度为 %d 的种子应当被拒绝", size)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := mustKey(t)
	message := []byte("待签名的内容")

	if err := Verify(key.Public(), message, key.Sign(message)); err != nil {
		t.Fatalf("自签自验失败：%v", err)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	key := mustKey(t)
	signature := key.Sign([]byte("原文"))

	err := Verify(key.Public(), []byte("改动后的内容"), signature)

	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("改动正文后的错误为 %v，期望 %v", err, ErrBadSignature)
	}
}

func TestVerifyRejectsOtherKey(t *testing.T) {
	key, other := mustKey(t), mustKey(t)
	message := []byte("内容")

	err := Verify(other.Public(), message, key.Sign(message))

	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("用他人公钥验证的错误为 %v，期望 %v", err, ErrBadSignature)
	}
}

func TestVerifyRejectsWrongLengths(t *testing.T) {
	key := mustKey(t)
	message := []byte("内容")

	if err := Verify(make([]byte, 16), message, key.Sign(message)); err == nil {
		t.Error("公钥长度不符时应当报错")
	}
	if err := Verify(key.Public(), message, []byte("短签名")); !errors.Is(err, ErrBadSignature) {
		t.Errorf("签名长度不符时的错误为 %v，期望 %v", err, ErrBadSignature)
	}
}
