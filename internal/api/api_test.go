package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/envelope"
	"vaultwaystation/internal/identity"
	"vaultwaystation/internal/store"
)

const (
	testCredential = "credential-for-tests"
	testChannel    = "vault-example"

	pathRegister = "/v1/register"
	pathReport   = "/v1/report"
	pathRevoke   = "/v1/revoke"
	pathRetire   = "/v1/retire"
)

// testEnv 是一套可用的服务端，带一个固定的时钟，便于测试时间窗口。
type testEnv struct {
	t          *testing.T
	cfg        *config.Config
	store      *store.Store
	server     *Server
	handler    http.Handler
	now        time.Time
	remoteAddr string
}

func newEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()

	cfg := &config.Config{
		Version: config.CurrentVersion,
		Server:  config.Server{Listen: "127.0.0.1:8787", DataDir: t.TempDir()},
		Registration: config.Registration{
			Enabled:          true,
			CredentialDigest: config.DigestCredential(testCredential),
		},
		Transport: config.Transport{Mode: config.ModePinned, CertFile: "relay.crt", KeyFile: "relay.key"},
		Limits: config.Limits{
			DevicesPerChannel: 4,
			RecordsPerDevice:  4,
			RecordsPerRequest: 16,
			RecordBytes:       4096,
			RequestsPerMinute: 1000,
		},
		Log: config.Log{Level: "error"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("测试配置不合规：%v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "waystation.db"))
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("关闭存储失败：%v", err)
		}
	})

	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("生成服务端密钥失败：%v", err)
	}

	env := &testEnv{
		t:          t,
		cfg:        cfg,
		store:      st,
		server:     New(cfg, st, key, slog.New(slog.NewTextHandler(io.Discard, nil))),
		now:        time.Unix(1700000000, 0).UTC(),
		remoteAddr: "192.0.2.10:1234",
	}
	env.server.now = func() time.Time { return env.now }
	env.handler = env.server.Handler()
	return env
}

func newKey(t *testing.T) *identity.KeyPair {
	t.Helper()

	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("生成设备密钥失败：%v", err)
	}
	return key
}

// send 直接发出一次请求，签名由调用方给出。
func (e *testEnv) send(path string, body []byte, fingerprint identity.Fingerprint, timestamp time.Time, nonce string, signature []byte) (int, []byte, http.Header) {
	e.t.Helper()

	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set(headerFingerprint, fingerprint.String())
	request.Header.Set(headerTimestamp, strconv.FormatInt(timestamp.Unix(), 10))
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerSignature, hex.EncodeToString(signature))
	request.RemoteAddr = e.remoteAddr

	recorder := httptest.NewRecorder()
	e.handler.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		e.t.Fatalf("读取响应失败：%v", err)
	}
	return response.StatusCode, data, response.Header
}

// callAt 以指定时间与随机值发起一次请求。
func (e *testEnv) callAt(key *identity.KeyPair, path string, body []byte, timestamp time.Time, nonce string) (int, []byte, http.Header) {
	e.t.Helper()

	signed := envelope.Request{
		Method:      http.MethodPost,
		Path:        path,
		Fingerprint: key.Fingerprint(),
		Timestamp:   timestamp,
		Nonce:       nonce,
		Body:        body,
	}
	return e.send(path, body, key.Fingerprint(), timestamp, nonce, signed.Signature(key))
}

// call 以当前时钟与一个新的随机值发起一次请求。
func (e *testEnv) call(key *identity.KeyPair, path string, payload any) (int, []byte, http.Header) {
	e.t.Helper()

	nonce, err := envelope.NewNonce()
	if err != nil {
		e.t.Fatalf("生成随机值失败：%v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		e.t.Fatalf("序列化请求失败：%v", err)
	}
	return e.callAt(key, path, body, e.now, nonce)
}

// verifyResponse 核对响应的签名，顺带确认签名链路本身可用。
func (e *testEnv) verifyResponse(header http.Header, status int, body []byte) {
	e.t.Helper()

	fingerprint, err := identity.ParseFingerprint(header.Get(headerFingerprint))
	if err != nil {
		e.t.Fatalf("响应头中的指纹不合规：%v", err)
	}
	signature, err := hex.DecodeString(header.Get(headerSignature))
	if err != nil {
		e.t.Fatalf("响应头中的签名编码不合规：%v", err)
	}

	response := envelope.Response{Fingerprint: fingerprint, Status: status, Body: body}
	if err := response.Verify(e.server.key.Fingerprint(), e.server.key.Public(), signature); err != nil {
		e.t.Fatalf("响应签名校验失败：%v", err)
	}
}

// register 注册一台设备，并返回频道标识。
func (e *testEnv) register(key *identity.KeyPair) string {
	e.t.Helper()

	status, body, header := e.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})
	if status != http.StatusOK {
		e.t.Fatalf("注册失败：状态 %d，正文 %s", status, body)
	}
	e.verifyResponse(header, status, body)

	var response channelResponse
	if err := json.Unmarshal(body, &response); err != nil {
		e.t.Fatalf("解析注册响应失败：%v", err)
	}
	return response.ChannelID
}

// reportPayload 组装一次上报请求。
func (e *testEnv) reportPayload(key *identity.KeyPair, channelID string, sequence int64, payload []byte) reportRequest {
	record := envelope.Record{
		Fingerprint: key.Fingerprint(),
		Channel:     channelID,
		Sequence:    sequence,
		CollectedAt: e.now,
		Payload:     payload,
	}
	return reportRequest{
		ChannelID:   channelID,
		Sequence:    sequence,
		CollectedAt: e.now.UTC().Format(time.RFC3339),
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signature:   base64.StdEncoding.EncodeToString(record.Signature(key)),
	}
}

// report 上报一条状态记录。
func (e *testEnv) report(key *identity.KeyPair, channelID string, sequence int64, payload []byte) (int, []byte, http.Header) {
	e.t.Helper()

	return e.call(key, pathReport, e.reportPayload(key, channelID, sequence, payload))
}

// errorCode 取出错误响应中的代码。
func errorCode(t *testing.T, body []byte) string {
	t.Helper()

	var response errorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("解析错误响应失败：%v，正文 %s", err, body)
	}
	return response.Error.Code
}

func expectStatus(t *testing.T, status int, body []byte, want int) {
	t.Helper()

	if status != want {
		t.Fatalf("状态码为 %d，期望 %d；正文 %s", status, want, body)
	}
}

func TestRegisterCreatesChannelAndDevice(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	channelID := env.register(key)

	if channelID == "" {
		t.Fatal("频道标识为空")
	}
	devices, err := env.store.Devices(store.ChannelID(channelID))
	if err != nil {
		t.Fatalf("读取设备失败：%v", err)
	}
	if len(devices) != 1 || devices[0].Fingerprint != key.Fingerprint() {
		t.Fatalf("设备列表不符：%+v", devices)
	}
}

func TestRegisterJoinsExistingChannel(t *testing.T) {
	env := newEnv(t, nil)

	first := env.register(newKey(t))
	second := env.register(newKey(t))

	if first != second {
		t.Fatalf("同名仓库应当共用频道，实际为 %s 与 %s", first, second)
	}
}

func TestRegisterIsIdempotent(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	first := env.register(key)
	second := env.register(key)

	if first != second {
		t.Fatalf("重复注册返回的频道不同：%s 与 %s", first, second)
	}
	devices, err := env.store.Devices(store.ChannelID(first))
	if err != nil {
		t.Fatalf("读取设备失败：%v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("重复注册不应产生第二台设备：%+v", devices)
	}
}

func TestRegisterRejectsWrongCredential(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: "错误的凭证",
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusUnauthorized)
	if code := errorCode(t, body); code != codeUnauthorized {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeUnauthorized)
	}
}

func TestRegisterRejectsWhenDisabled(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Registration = config.Registration{}
	})
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusForbidden)
}

func TestRegisterRejectsDegradedTransport(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Transport = config.Transport{Mode: config.ModePlaintext}
	})
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusForbidden)
	if code := errorCode(t, body); code != codeForbidden {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeForbidden)
	}
}

func TestRegisterRejectsMismatchedFingerprint(t *testing.T) {
	env := newEnv(t, nil)
	key, other := newKey(t), newKey(t)

	// 声明的是 key 的指纹，给的却是 other 的公钥。
	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(other.Public()),
	})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestRegisterRejectsUnknownField(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	body := []byte(`{"channel":"` + testChannel + `","credential":"` + testCredential +
		`","public_key":"","extra":1}`)
	status, response, _ := env.callAt(key, pathRegister, body, env.now, mustNonce(t))

	expectStatus(t, status, response, http.StatusBadRequest)
}

func TestRegisterRejectsDeviceName(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	// 其余字段都合规，签名也成立，唯一的问题是多了一个名称。
	body := []byte(`{"channel":"` + testChannel + `","credential":"` + testCredential +
		`","label":"device-a","public_key":"` + base64.StdEncoding.EncodeToString(key.Public()) + `"}`)
	status, response, _ := env.callAt(key, pathRegister, body, env.now, mustNonce(t))

	expectStatus(t, status, response, http.StatusBadRequest)
	if code := errorCode(t, response); code != codeBadRequest {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeBadRequest)
	}
}

func TestRegisterRejectsAfterRevocation(t *testing.T) {
	env := newEnv(t, nil)
	first, second := newKey(t), newKey(t)
	channelID := env.register(first)
	env.register(second)

	status, body, _ := env.call(second, pathRevoke, revokeRequest{ChannelID: channelID, Target: first.Fingerprint().String()})
	expectStatus(t, status, body, http.StatusOK)

	status, body, _ = env.call(first, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(first.Public()),
	})

	expectStatus(t, status, body, http.StatusUnauthorized)
}

func TestRegisterRejectsWhenChannelIsFull(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.DevicesPerChannel = 1
	})
	env.register(newKey(t))
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusConflict)
}

func TestReportSharesStateWithPeers(t *testing.T) {
	env := newEnv(t, nil)
	first, second := newKey(t), newKey(t)
	channelID := env.register(first)
	env.register(second)

	status, body, header := env.report(first, channelID, 1, []byte("甲的密文"))
	expectStatus(t, status, body, http.StatusOK)
	env.verifyResponse(header, status, body)

	status, body, _ = env.report(second, channelID, 1, []byte("乙的密文"))
	expectStatus(t, status, body, http.StatusOK)

	var response reportResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("解析上报响应失败：%v", err)
	}
	if !response.Accepted {
		t.Error("上报未被接受")
	}
	if len(response.Records) != 1 {
		t.Fatalf("对端记录数为 %d，期望 1", len(response.Records))
	}
	if response.Records[0].Fingerprint != first.Fingerprint().String() {
		t.Fatalf("对端记录不属设备甲：%+v", response.Records[0])
	}
	if payload, err := base64.StdEncoding.DecodeString(response.Records[0].Payload); err != nil || string(payload) != "甲的密文" {
		t.Fatalf("对端记录内容不符：%+v", response.Records[0])
	}
	// 对端公钥随记录回送，接收方才能核对记录签名。
	if response.Records[0].PublicKey != base64.StdEncoding.EncodeToString(first.Public()) {
		t.Fatalf("对端记录未带上公钥：%+v", response.Records[0])
	}
}

func TestReportOnlyKeepsNewestSequence(t *testing.T) {
	env := newEnv(t, nil)
	first, second := newKey(t), newKey(t)
	channelID := env.register(first)
	env.register(second)

	status, body, _ := env.report(first, channelID, 5, []byte("新的"))
	expectStatus(t, status, body, http.StatusOK)

	status, body, _ = env.report(first, channelID, 5, []byte("同序号的另一次上报"))
	expectStatus(t, status, body, http.StatusOK)

	var response reportResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("解析上报响应失败：%v", err)
	}
	if response.Accepted {
		t.Error("序号未推进时不应接受为新记录")
	}

	record, err := env.store.Record(store.ChannelID(channelID), first.Fingerprint())
	if err != nil {
		t.Fatalf("读取记录失败：%v", err)
	}
	if string(record.Payload) != "新的" {
		t.Fatalf("既有记录被同序号的上报覆盖：%+v", record)
	}

	// 被拒时回送本设备既有记录：设备本地状态被回退时，只有拿到它才知道该从哪里继续。
	if response.Own == nil {
		t.Fatal("被拒时未回送本设备既有记录")
	}
	if response.Own.Sequence != 5 || response.Own.Payload != base64.StdEncoding.EncodeToString([]byte("新的")) {
		t.Fatalf("回送的既有记录不符：%+v", response.Own)
	}
}

func TestReportRejectsUnknownDevice(t *testing.T) {
	env := newEnv(t, nil)
	channelID := env.register(newKey(t))

	status, body, _ := env.report(newKey(t), channelID, 1, []byte("陌生设备的密文"))

	expectStatus(t, status, body, http.StatusUnauthorized)
	if code := errorCode(t, body); code != codeUnauthorized {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeUnauthorized)
	}
}

func TestReportRejectsTamperedBody(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	payload := env.reportPayload(key, channelID, 1, []byte("原始密文"))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化请求失败：%v", err)
	}
	// 签名盖在原文上，然后改动正文：请求签名的核对必须先于其他一切判断。
	tampered := bytes.Replace(body, []byte(base64.StdEncoding.EncodeToString([]byte("原始密文"))),
		[]byte(base64.StdEncoding.EncodeToString([]byte("改动密文"))), 1)

	nonce := mustNonce(t)
	signed := envelope.Request{
		Method:      http.MethodPost,
		Path:        pathReport,
		Fingerprint: key.Fingerprint(),
		Timestamp:   env.now,
		Nonce:       nonce,
		Body:        body,
	}
	status, response, _ := env.send(pathReport, tampered, key.Fingerprint(), env.now, nonce, signed.Signature(key))

	expectStatus(t, status, response, http.StatusUnauthorized)
}

func TestReportRejectsBadRecordSignature(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	payload := env.reportPayload(key, channelID, 1, []byte("原始密文"))
	// 记录内容与记录签名对不上：请求签名仍然有效，但记录签名不再成立。
	payload.Payload = base64.StdEncoding.EncodeToString([]byte("改动密文"))

	status, body, _ := env.call(key, pathReport, payload)

	expectStatus(t, status, body, http.StatusBadRequest)
	if code := errorCode(t, body); code != codeBadSignature {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeBadSignature)
	}
}

func TestReportRejectsStaleTimestamp(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	payload := env.reportPayload(key, channelID, 1, []byte("密文"))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化请求失败：%v", err)
	}

	status, response, _ := env.callAt(key, pathReport, body, env.now.Add(-envelope.ClockSkew-time.Minute), mustNonce(t))

	expectStatus(t, status, response, http.StatusUnauthorized)
	if code := errorCode(t, response); code != codeSkew {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeSkew)
	}
}

func TestReportRejectsReplayedNonce(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	payload := env.reportPayload(key, channelID, 1, []byte("密文"))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("序列化请求失败：%v", err)
	}
	nonce := mustNonce(t)

	status, response, _ := env.callAt(key, pathReport, body, env.now, nonce)
	expectStatus(t, status, response, http.StatusOK)

	status, response, _ = env.callAt(key, pathReport, body, env.now, nonce)

	expectStatus(t, status, response, http.StatusUnauthorized)
	if code := errorCode(t, response); code != codeReplay {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeReplay)
	}
}

func TestReportRejectsOversizedRecord(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	// 记录内容本身超限，但请求体尚未超过传输上限。
	oversized := bytes.Repeat([]byte("a"), env.cfg.Limits.RecordBytes+1)
	status, body, _ := env.report(key, channelID, 1, oversized)

	expectStatus(t, status, body, http.StatusRequestEntityTooLarge)
}

func TestReportRejectsMissingChannel(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, _ := env.call(key, pathReport, reportRequest{
		Sequence:    1,
		CollectedAt: env.now.UTC().Format(time.RFC3339),
		Payload:     base64.StdEncoding.EncodeToString([]byte("密文")),
		Signature:   base64.StdEncoding.EncodeToString([]byte("签名")),
	})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestRevokeRemovesDeviceAndKeepsRevocation(t *testing.T) {
	env := newEnv(t, nil)
	first, second := newKey(t), newKey(t)
	channelID := env.register(first)
	env.register(second)

	status, body, header := env.call(second, pathRevoke, revokeRequest{ChannelID: channelID, Target: first.Fingerprint().String()})
	expectStatus(t, status, body, http.StatusOK)
	env.verifyResponse(header, status, body)

	var response revokeResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("解析吊销响应失败：%v", err)
	}
	if response.Revoked != first.Fingerprint().String() {
		t.Fatalf("吊销结果不符：%+v", response)
	}

	// 吊销只记名单，不移除设备：被吊销的设备仍是频道成员，但请求一律被拒。
	if _, err := env.store.Device(store.ChannelID(channelID), first.Fingerprint()); err != nil {
		t.Errorf("吊销不应把设备移出列表：%v", err)
	}
	if _, err := env.store.Revocation(store.ChannelID(channelID), first.Fingerprint()); err != nil {
		t.Errorf("吊销纪录缺失：%v", err)
	}
	status, body, _ = env.report(first, channelID, 1, []byte("密文"))
	expectStatus(t, status, body, http.StatusUnauthorized)

	status, body, _ = env.report(second, channelID, 1, []byte("密文"))
	expectStatus(t, status, body, http.StatusOK)
	var reported reportResponse
	if err := json.Unmarshal(body, &reported); err != nil {
		t.Fatalf("解析上报响应失败：%v", err)
	}
	if len(reported.Revocations) != 1 || reported.Revocations[0].Fingerprint != first.Fingerprint().String() {
		t.Fatalf("上报未带回吊销名单：%+v", reported.Revocations)
	}
}

func TestRevokeRejectsLastDevice(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.call(key, pathRevoke, revokeRequest{ChannelID: channelID, Target: key.Fingerprint().String()})

	expectStatus(t, status, body, http.StatusConflict)
	if code := errorCode(t, body); code != codeConflict {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeConflict)
	}
}

func TestRevokeRejectsUnknownTarget(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.call(key, pathRevoke, revokeRequest{ChannelID: channelID, Target: newKey(t).Fingerprint().String()})

	expectStatus(t, status, body, http.StatusNotFound)
}

func TestRevokeRejectsDegradedTransport(t *testing.T) {
	env := newEnv(t, nil)
	first, second := newKey(t), newKey(t)
	channelID := env.register(first)
	env.register(second)

	env.cfg.Transport = config.Transport{Mode: config.ModePlaintext}
	status, body, _ := env.call(second, pathRevoke, revokeRequest{ChannelID: channelID, Target: first.Fingerprint().String()})

	expectStatus(t, status, body, http.StatusForbidden)
}

func TestRetireRemovesDeviceAndRecord(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)
	status, body, _ := env.report(key, channelID, 1, []byte("密文"))
	expectStatus(t, status, body, http.StatusOK)

	status, body, header := env.call(key, pathRetire, retireRequest{ChannelID: channelID})
	expectStatus(t, status, body, http.StatusOK)
	env.verifyResponse(header, status, body)

	channel := store.ChannelID(channelID)
	if _, err := env.store.Device(channel, key.Fingerprint()); err == nil {
		t.Error("退役后设备仍在列表中")
	}
	if _, err := env.store.Record(channel, key.Fingerprint()); err == nil {
		t.Error("退役后记录仍在存储中")
	}
	if _, err := env.store.Revocation(channel, key.Fingerprint()); err != nil {
		t.Errorf("退役后应当留有吊销纪录：%v", err)
	}
}

func TestRetireRejectsDegradedTransport(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	env.cfg.Transport = config.Transport{Mode: config.ModeInsecure}
	status, body, _ := env.call(key, pathRetire, retireRequest{ChannelID: channelID})

	expectStatus(t, status, body, http.StatusForbidden)
}

// TestRateLimitApplies 检查按来源地址的限流。
//
// 注册也占一次配额，因此上限设为二时，注册消耗一次、第一次上报消耗第二次、
// 第二次上报即被拒绝。
func TestRateLimitApplies(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.RequestsPerMinute = 2
	})
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.report(key, channelID, 1, []byte("密文"))
	expectStatus(t, status, body, http.StatusOK)

	status, body, _ = env.report(key, channelID, 2, []byte("密文"))

	expectStatus(t, status, body, http.StatusTooManyRequests)
	if code := errorCode(t, body); code != codeLimit {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeLimit)
	}
}

// TestRateLimitAppliesToDestructiveCommands 检查注册、吊销与退役同样受来源地址限流约束，
// 使它们在验签之前就被挡住。
func TestRateLimitAppliesToDestructiveCommands(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.RequestsPerMinute = 1
	})
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.call(key, pathRevoke, revokeRequest{ChannelID: channelID, Target: key.Fingerprint().String()})
	expectStatus(t, status, body, http.StatusTooManyRequests)

	status, body, _ = env.call(key, pathRetire, retireRequest{ChannelID: channelID})
	expectStatus(t, status, body, http.StatusTooManyRequests)

	other := newKey(t)
	status, body, _ = env.call(other, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(other.Public()),
	})
	expectStatus(t, status, body, http.StatusTooManyRequests)
}

func TestRegisterRejectsMissingChannelName(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestUnsupportedPathIsNotFound(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, _, _ := env.call(key, "/v1/unknown", struct{}{})

	if status != http.StatusNotFound {
		t.Fatalf("状态码为 %d，期望 %d", status, http.StatusNotFound)
	}
}

func TestMalformedHeadersAreRejected(t *testing.T) {
	env := newEnv(t, nil)
	body := []byte(`{}`)

	cases := map[string]func(*http.Request){
		"缺少指纹":    func(r *http.Request) { r.Header.Set(headerFingerprint, "") },
		"时间戳非数字":  func(r *http.Request) { r.Header.Set(headerTimestamp, "现在") },
		"随机值过短":   func(r *http.Request) { r.Header.Set(headerNonce, "短") },
		"签名非十六进制": func(r *http.Request) { r.Header.Set(headerSignature, "不是十六进制") },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, pathReport, bytes.NewReader(body))
			mutate(request)
			request.RemoteAddr = "192.0.2.10:1234"

			recorder := httptest.NewRecorder()
			env.handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("状态码为 %d，期望 %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestErrorResponseIsSigned(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, header := env.report(key, "channel-unknown", 1, []byte("密文"))

	expectStatus(t, status, body, http.StatusUnauthorized)
	env.verifyResponse(header, status, body)
}

func mustNonce(t *testing.T) string {
	t.Helper()

	nonce, err := envelope.NewNonce()
	if err != nil {
		t.Fatalf("生成随机值失败：%v", err)
	}
	return nonce
}

func TestRequestBodyTooLargeIsRejected(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.RecordBytes = 64
	})
	key := newKey(t)
	env.register(key)

	oversized := bytes.Repeat([]byte("a"), 64*4/3+8192+1)
	status, body, _ := env.callAt(key, pathReport, oversized, env.now, mustNonce(t))

	expectStatus(t, status, body, http.StatusRequestEntityTooLarge)
	if code := errorCode(t, body); code != codeLimit {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeLimit)
	}
}

// failingReader 用来模拟读不出正文的连接。
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("读取失败") }
func (failingReader) Close() error             { return nil }

func TestUnreadableBodyIsRejected(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	request := httptest.NewRequest(http.MethodPost, pathReport, failingReader{})
	request.Header.Set(headerFingerprint, key.Fingerprint().String())
	request.Header.Set(headerTimestamp, strconv.FormatInt(env.now.Unix(), 10))
	request.Header.Set(headerNonce, mustNonce(t))
	request.Header.Set(headerSignature, strings.Repeat("00", 64))
	request.RemoteAddr = "192.0.2.10:1234"

	recorder := httptest.NewRecorder()
	env.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("状态码为 %d，期望 %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestReportRejectsMalformedFields(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	cases := map[string]func(*reportRequest){
		"采集时间不可解析":   func(p *reportRequest) { p.CollectedAt = "昨天" },
		"序号为负":       func(p *reportRequest) { p.Sequence = -1 },
		"内容非 base64": func(p *reportRequest) { p.Payload = "***" },
		"签名非 base64": func(p *reportRequest) { p.Signature = "***" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := env.reportPayload(key, channelID, 1, []byte("密文"))
			mutate(&payload)

			status, body, _ := env.call(key, pathReport, payload)

			expectStatus(t, status, body, http.StatusBadRequest)
		})
	}
}

func TestRegisterRejectsMalformedPublicKey(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	cases := map[string]string{
		"非 base64": "***",
		"长度不符":     base64.StdEncoding.EncodeToString([]byte("短公钥")),
	}

	for name, publicKey := range cases {
		t.Run(name, func(t *testing.T) {
			status, body, _ := env.call(key, pathRegister, registerRequest{
				Channel:    testChannel,
				Credential: testCredential,
				PublicKey:  publicKey,
			})

			expectStatus(t, status, body, http.StatusBadRequest)
		})
	}
}

func TestRegisterReportsInternalFailure(t *testing.T) {
	env := newEnv(t, nil)
	// 注入失败：建立频道时取不到标识。
	env.server.newID = func() (store.ChannelID, error) { return "", errors.New("注入的失败") }
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusInternalServerError)
	if code := errorCode(t, body); code != codeInternal {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeInternal)
	}
}

func TestRevokeRejectsMalformedTarget(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.call(key, pathRevoke, revokeRequest{ChannelID: channelID, Target: "不合规"})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestRevokeRejectsMissingChannel(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, _ := env.call(key, pathRevoke, revokeRequest{Target: key.Fingerprint().String()})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestRetireRejectsMissingChannel(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	status, body, _ := env.call(key, pathRetire, retireRequest{})

	expectStatus(t, status, body, http.StatusBadRequest)
}

func TestRetireWithoutRecordSucceeds(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.call(key, pathRetire, retireRequest{ChannelID: channelID})

	expectStatus(t, status, body, http.StatusOK)
}

// TestRateLimitWindowResets 检查越过统计周期后配额恢复。
func TestRateLimitWindowResets(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.RequestsPerMinute = 2
	})
	key := newKey(t)
	channelID := env.register(key)

	status, body, _ := env.report(key, channelID, 1, []byte("密文"))
	expectStatus(t, status, body, http.StatusOK)

	status, body, _ = env.report(key, channelID, 2, []byte("密文"))
	expectStatus(t, status, body, http.StatusTooManyRequests)

	// 越过统计周期后配额恢复。
	env.now = env.now.Add(2 * time.Minute)
	status, body, _ = env.report(key, channelID, 3, []byte("密文"))
	expectStatus(t, status, body, http.StatusOK)
}

// TestRateLimitAppliesToDevice 检查设备级限流：来源地址各不相同，
// 因此只有设备自身的配额能挡住请求。
func TestRateLimitAppliesToDevice(t *testing.T) {
	env := newEnv(t, func(cfg *config.Config) {
		cfg.Limits.RequestsPerMinute = 2
	})
	key := newKey(t)
	channelID := env.register(key)

	for i := 1; i <= 2; i++ {
		env.remoteAddr = "192.0.2." + strconv.Itoa(10+i) + ":1234"
		status, body, _ := env.report(key, channelID, int64(i), []byte("密文"))
		expectStatus(t, status, body, http.StatusOK)
	}

	env.remoteAddr = "192.0.2.20:1234"
	status, body, _ := env.report(key, channelID, 3, []byte("密文"))

	expectStatus(t, status, body, http.StatusTooManyRequests)
}

// TestSourceAddressWithoutPortIsAccepted 检查来源地址解析不出端口时不会出错。
func TestSourceAddressWithoutPortIsAccepted(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)
	channelID := env.register(key)

	env.remoteAddr = "192.0.2.10"
	status, body, _ := env.report(key, channelID, 1, []byte("密文"))

	expectStatus(t, status, body, http.StatusOK)
}

// TestCorruptedPublicKeyIsReportedAsInternalError 检查存储中的公钥损坏时，
// 服务端把它当作自身的问题汇报，而不是归咎于客户端。
func TestCorruptedPublicKeyIsReportedAsInternalError(t *testing.T) {
	env := newEnv(t, nil)
	key := newKey(t)

	channel := store.Channel{ID: "channel-a", Alias: testChannel, CreatedAt: env.now}
	if err := env.store.CreateChannel(channel); err != nil {
		t.Fatalf("建立频道失败：%v", err)
	}
	device := store.Device{
		Fingerprint:  key.Fingerprint(),
		PublicKey:    []byte("长度不对的公钥"),
		RegisteredAt: env.now,
	}
	if err := env.store.AddDevice(channel.ID, device); err != nil {
		t.Fatalf("写入设备失败：%v", err)
	}

	status, body, _ := env.report(key, string(channel.ID), 1, []byte("密文"))

	expectStatus(t, status, body, http.StatusInternalServerError)
	if code := errorCode(t, body); code != codeInternal {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeInternal)
	}
}

// TestPanicIsContained 检查单个请求中的崩溃不会带倒整个服务。
func TestPanicIsContained(t *testing.T) {
	env := newEnv(t, nil)
	env.server.newID = func() (store.ChannelID, error) { panic("注入的崩溃") }
	key := newKey(t)

	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})

	expectStatus(t, status, body, http.StatusInternalServerError)
	if code := errorCode(t, body); code != codeInternal {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeInternal)
	}
}

func TestReloadSwapsSettingsAndLimit(t *testing.T) {
	env := newEnv(t, nil)

	settings := *env.cfg
	settings.Limits.RequestsPerMinute = 1
	env.server.Reload(&settings)

	if got := env.server.Settings().Limits.RequestsPerMinute; got != 1 {
		t.Fatalf("重载后每台设备的配额为 %d，期望 1", got)
	}
	if got := env.server.limiter.limit; got != 1 {
		t.Fatalf("限流器的配额为 %d，期望 1", got)
	}

	// 配额降到每分钟一次后，同一来源地址的第二次请求即被挡下。
	env.register(newKey(t))

	key := newKey(t)
	status, body, _ := env.call(key, pathRegister, registerRequest{
		Channel:    testChannel,
		Credential: testCredential,
		PublicKey:  base64.StdEncoding.EncodeToString(key.Public()),
	})
	expectStatus(t, status, body, http.StatusTooManyRequests)
	if code := errorCode(t, body); code != codeLimit {
		t.Fatalf("错误代码为 %q，期望 %q", code, codeLimit)
	}
}
