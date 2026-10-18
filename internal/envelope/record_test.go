package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"

	"vaultwaystation/internal/identity"
)

func fixedRecord(key *identity.KeyPair) Record {
	return Record{
		Fingerprint: key.Fingerprint(),
		Channel:     "channel-a",
		Sequence:    12,
		CollectedAt: time.Unix(1700000000, 0),
		Payload:     []byte("ciphertext"),
	}
}

func TestRecordSignatureVerifies(t *testing.T) {
	key := mustKey(t)
	record := fixedRecord(key)

	if err := record.Verify(key.Public(), record.Signature(key)); err != nil {
		t.Fatalf("自签自验失败：%v", err)
	}
}

func TestRecordVerifyRejectsTamperedPayload(t *testing.T) {
	key := mustKey(t)
	record := fixedRecord(key)
	signature := record.Signature(key)
	record.Payload = []byte("other")

	err := record.Verify(key.Public(), signature)

	if !errors.Is(err, identity.ErrBadSignature) {
		t.Fatalf("改动记录内容后的错误为 %v，期望 %v", err, identity.ErrBadSignature)
	}
}

func TestRecordVerifyRejectsOtherDevice(t *testing.T) {
	key, other := mustKey(t), mustKey(t)
	record := fixedRecord(key)

	err := record.Verify(other.Public(), record.Signature(key))

	if !errors.Is(err, identity.ErrBadSignature) {
		t.Fatalf("他人验证记录的错误为 %v，期望 %v", err, identity.ErrBadSignature)
	}
}

func TestRecordSigningTextIgnoresTimeZone(t *testing.T) {
	key := mustKey(t)
	record := fixedRecord(key)

	shanghai := time.FixedZone("东八区", 8*60*60)
	other := record
	other.CollectedAt = record.CollectedAt.In(shanghai)

	if other.SigningText() != record.SigningText() {
		t.Fatalf("同一时刻在不同时区算出的规范文本不同：\n%s\n%s", record.SigningText(), other.SigningText())
	}
}

func TestRecordSigningTextCoversEveryField(t *testing.T) {
	key := mustKey(t)
	base := fixedRecord(key)
	baseText := base.SigningText()

	mutations := map[string]func(*Record){
		"身份":   func(r *Record) { r.Fingerprint = identity.Fingerprint(strings.Repeat("0", 64)) },
		"频道":   func(r *Record) { r.Channel = "channel-b" },
		"序号":   func(r *Record) { r.Sequence++ },
		"采集时间": func(r *Record) { r.CollectedAt = r.CollectedAt.Add(time.Second) },
		"内容":   func(r *Record) { r.Payload = []byte("other") },
	}

	for name, mutate := range mutations {
		changed := base
		mutate(&changed)
		if changed.SigningText() == baseText {
			t.Errorf("改动%s后规范文本未变化", name)
		}
	}
}
