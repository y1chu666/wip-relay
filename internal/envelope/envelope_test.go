package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"

	"vaultwaystation/internal/identity"
)

func mustKey(t *testing.T) *identity.KeyPair {
	t.Helper()

	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	return key
}

// fixedRequest 返回一份要素固定的请求，供各用例改动其中一项。
func fixedRequest(t *testing.T, key *identity.KeyPair) Request {
	t.Helper()

	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("生成随机值失败：%v", err)
	}
	return Request{
		Method:      "POST",
		Path:        "/v1/report",
		Fingerprint: key.Fingerprint(),
		Timestamp:   time.Unix(1700000000, 0),
		Nonce:       nonce,
		Body:        []byte(`{"records":1}`),
	}
}

func TestNewNonceIsRandomHex(t *testing.T) {
	first, err := NewNonce()
	if err != nil {
		t.Fatalf("生成随机值失败：%v", err)
	}
	second, err := NewNonce()
	if err != nil {
		t.Fatalf("生成随机值失败：%v", err)
	}

	if first == second {
		t.Fatal("两次生成的随机值相同")
	}
	if len(first) != NonceBytes*2 {
		t.Fatalf("随机值长度为 %d，期望 %d", len(first), NonceBytes*2)
	}
}

func TestRequestSignatureVerifies(t *testing.T) {
	key := mustKey(t)
	request := fixedRequest(t, key)

	if err := request.Verify(key.Public(), request.Signature(key), request.Timestamp); err != nil {
		t.Fatalf("自签自验失败：%v", err)
	}
}

func TestRequestVerifyRejectsTamperedBody(t *testing.T) {
	key := mustKey(t)
	request := fixedRequest(t, key)
	signature := request.Signature(key)
	request.Body = []byte(`{"records":2}`)

	err := request.Verify(key.Public(), signature, request.Timestamp)

	if !errors.Is(err, identity.ErrBadSignature) {
		t.Fatalf("改动正文后的错误为 %v，期望 %v", err, identity.ErrBadSignature)
	}
}

func TestRequestVerifyRejectsOtherDevice(t *testing.T) {
	key, other := mustKey(t), mustKey(t)
	request := fixedRequest(t, key)

	err := request.Verify(other.Public(), request.Signature(key), request.Timestamp)

	if !errors.Is(err, identity.ErrBadSignature) {
		t.Fatalf("冒名请求的错误为 %v，期望 %v", err, identity.ErrBadSignature)
	}
}

func TestRequestSigningTextCoversEveryField(t *testing.T) {
	key := mustKey(t)
	base := fixedRequest(t, key)
	baseText := base.SigningText()

	mutations := map[string]func(*Request){
		"方法":  func(r *Request) { r.Method = "GET" },
		"路径":  func(r *Request) { r.Path = "/v1/pull" },
		"身份":  func(r *Request) { r.Fingerprint = identity.Fingerprint(strings.Repeat("0", 64)) },
		"时间戳": func(r *Request) { r.Timestamp = r.Timestamp.Add(time.Second) },
		"随机值": func(r *Request) { r.Nonce = strings.Repeat("1", 64) },
		"正文":  func(r *Request) { r.Body = []byte("other") },
	}

	for name, mutate := range mutations {
		changed := base
		mutate(&changed)
		if changed.SigningText() == baseText {
			t.Errorf("改动%s后规范文本未变化", name)
		}
	}
}

func TestRequestFreshness(t *testing.T) {
	key := mustKey(t)
	request := fixedRequest(t, key)
	signature := request.Signature(key)

	cases := []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{"同时刻", request.Timestamp, false},
		{"窗口内偏后", request.Timestamp.Add(ClockSkew), false},
		{"窗口内偏前", request.Timestamp.Add(-ClockSkew), false},
		{"超出窗口偏后", request.Timestamp.Add(ClockSkew + time.Second), true},
		{"超出窗口偏前", request.Timestamp.Add(-ClockSkew - time.Second), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := request.Verify(key.Public(), signature, c.now)
			if errors.Is(err, ErrTimestampSkew) != c.wantErr {
				t.Fatalf("偏差判定结果为 %v，期望报偏差错误为 %t", err, c.wantErr)
			}
		})
	}
}

func TestResponseSignatureVerifies(t *testing.T) {
	server := mustKey(t)
	response := Response{
		Fingerprint: server.Fingerprint(),
		Status:      200,
		Body:        []byte(`{"ok":true}`),
	}

	if err := response.Verify(server.Fingerprint(), server.Public(), response.Signature(server)); err != nil {
		t.Fatalf("自签自验失败：%v", err)
	}
}

func TestResponseVerifyRejectsUnpinnedFingerprint(t *testing.T) {
	server, rogue := mustKey(t), mustKey(t)
	response := Response{
		Fingerprint: rogue.Fingerprint(),
		Status:      200,
		Body:        []byte(`{"ok":true}`),
	}

	err := response.Verify(server.Fingerprint(), rogue.Public(), response.Signature(rogue))

	if !errors.Is(err, ErrFingerprint) {
		t.Fatalf("指纹不符的错误为 %v，期望 %v", err, ErrFingerprint)
	}
}

func TestResponseVerifyRejectsTamperedBody(t *testing.T) {
	server := mustKey(t)
	response := Response{
		Fingerprint: server.Fingerprint(),
		Status:      200,
		Body:        []byte(`{"ok":true}`),
	}
	signature := response.Signature(server)
	response.Body = []byte(`{"ok":false}`)

	err := response.Verify(server.Fingerprint(), server.Public(), signature)

	if !errors.Is(err, identity.ErrBadSignature) {
		t.Fatalf("改动正文后的错误为 %v，期望 %v", err, identity.ErrBadSignature)
	}
}

func TestResponseSigningTextCoversEveryField(t *testing.T) {
	server := mustKey(t)
	base := Response{
		Fingerprint: server.Fingerprint(),
		Status:      200,
		Body:        []byte(`{"ok":true}`),
	}
	baseText := base.SigningText()

	mutations := map[string]func(*Response){
		"身份": func(r *Response) { r.Fingerprint = identity.Fingerprint(strings.Repeat("0", 64)) },
		"状态": func(r *Response) { r.Status = 500 },
		"正文": func(r *Response) { r.Body = []byte("other") },
	}

	for name, mutate := range mutations {
		changed := base
		mutate(&changed)
		if changed.SigningText() == baseText {
			t.Errorf("改动%s后规范文本未变化", name)
		}
	}
}
