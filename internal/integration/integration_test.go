// Package integration 以真实监听端口与真实签名请求，串起配置、密钥、传输与接口。
//
// 单元测试各自替换掉一部分环境，本包相反：它用自签证书、真实端口与真实请求，
// 验证「请求带签名、服务端验签、响应带签名」这条链路确实成立，
// 也验证注册、上报、吊销与配置重载在真实连接上的表现。
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/envelope"
	"vaultwaystation/internal/identity"
	"vaultwaystation/internal/server"
)

const (
	credential  = "credential-for-tests"
	startupWait = 10 * time.Second
)

// harness 是一套已经跑起来的服务端，以及连上它的客户端。
type harness struct {
	t          *testing.T
	url        string
	configPath string
	serverKey  *identity.KeyPair
	httpClient *http.Client
}

// start 写证书与配置，启动服务，并等到端口可用。
func start(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "relay.crt")
	keyFile := filepath.Join(dir, "relay.key")
	material := selfSignedCertificate(t)
	writeFile(t, certFile, material.certPEM)
	writeFile(t, keyFile, material.keyPEM)

	port := freePort(t)
	configPath := filepath.Join(dir, "waystation.toml")
	writeFile(t, configPath, []byte(configText(dir, port)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, server.Options{ConfigPath: configPath, Stderr: io.Discard}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("服务退出时报错：%v", err)
			}
		case <-time.After(startupWait):
			t.Error("服务未在预期时间内退出")
		}
	})

	address := "127.0.0.1:" + strconv.Itoa(port)
	waitReady(t, address)

	settings, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	data, err := os.ReadFile(settings.KeyPath())
	if err != nil {
		t.Fatalf("读取服务端密钥失败：%v", err)
	}
	serverKey, err := identity.Decode(string(bytes.TrimSpace(data)))
	if err != nil {
		t.Fatalf("解析服务端密钥失败：%v", err)
	}

	return &harness{
		t:          t,
		url:        "https://" + address,
		configPath: configPath,
		serverKey:  serverKey,
		httpClient: pinnedClient(t, certFile),
	}
}

// pinnedClient 返回一个信任自签证书的客户端，模拟设备首次配对后钉住证书的情形。
func pinnedClient(t *testing.T, certFile string) *http.Client {
	t.Helper()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("读取证书失败：%v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("证书无法加入信任池")
	}

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// call 以设备身份发起一次请求，并核对响应签名。
func (h *harness) call(key *identity.KeyPair, path string, payload any) (int, []byte) {
	h.t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatalf("序列化请求失败：%v", err)
	}
	nonce, err := envelope.NewNonce()
	if err != nil {
		h.t.Fatalf("生成随机值失败：%v", err)
	}
	now := time.Now()

	signed := envelope.Request{
		Method:      http.MethodPost,
		Path:        path,
		Fingerprint: key.Fingerprint(),
		Timestamp:   now,
		Nonce:       nonce,
		Body:        body,
	}

	request, err := http.NewRequest(http.MethodPost, h.url+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatalf("构造请求失败：%v", err)
	}
	request.Header.Set("X-Waystation-Fingerprint", key.Fingerprint().String())
	request.Header.Set("X-Waystation-Timestamp", strconv.FormatInt(now.Unix(), 10))
	request.Header.Set("X-Waystation-Nonce", nonce)
	request.Header.Set("X-Waystation-Signature", hex.EncodeToString(signed.Signature(key)))

	response, err := h.httpClient.Do(request)
	if err != nil {
		h.t.Fatalf("请求 %s 失败：%v", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatalf("读取响应失败：%v", err)
	}
	h.verifyResponse(response, data)
	return response.StatusCode, data
}

// verifyResponse 核对响应签名：设备以首次配对时钉住的公钥为凭据。
func (h *harness) verifyResponse(response *http.Response, body []byte) {
	h.t.Helper()

	fingerprint, err := identity.ParseFingerprint(response.Header.Get("X-Waystation-Fingerprint"))
	if err != nil {
		h.t.Fatalf("响应头中的指纹不合规：%v", err)
	}
	if fingerprint != h.serverKey.Fingerprint() {
		h.t.Fatalf("响应来自指纹 %s 的服务端，期望 %s", fingerprint, h.serverKey.Fingerprint())
	}

	signature, err := hex.DecodeString(response.Header.Get("X-Waystation-Signature"))
	if err != nil {
		h.t.Fatalf("响应头中的签名编码不合规：%v", err)
	}
	signed := envelope.Response{Fingerprint: fingerprint, Status: response.StatusCode, Body: body}
	if err := signed.Verify(h.serverKey.Fingerprint(), h.serverKey.Public(), signature); err != nil {
		h.t.Fatalf("响应签名校验失败：%v", err)
	}
}

// register 注册一台设备，返回频道标识。
func (h *harness) register(key *identity.KeyPair, label string) string {
	h.t.Helper()

	status, body := h.call(key, "/v1/register", map[string]string{
		"channel":    "vault-example",
		"credential": credential,
		"label":      label,
		"public_key": base64.StdEncoding.EncodeToString(key.Public()),
	})
	if status != http.StatusOK {
		h.t.Fatalf("注册失败：状态 %d，正文 %s", status, body)
	}

	var response struct {
		ChannelID    string `json:"channel_id"`
		ChannelAlias string `json:"channel_alias"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		h.t.Fatalf("解析注册响应失败：%v", err)
	}
	if response.ChannelAlias != "vault-example" {
		h.t.Fatalf("频道别名为 %q，期望 vault-example", response.ChannelAlias)
	}
	return response.ChannelID
}

// report 上报一条状态记录，返回响应。
func (h *harness) report(key *identity.KeyPair, channelID string, sequence int64, payload []byte) (int, reportResponse) {
	h.t.Helper()

	collectedAt := time.Now().UTC()
	record := envelope.Record{
		Fingerprint: key.Fingerprint(),
		Channel:     channelID,
		Sequence:    sequence,
		CollectedAt: collectedAt,
		Payload:     payload,
	}

	status, body := h.call(key, "/v1/report", map[string]any{
		"channel_id":   channelID,
		"sequence":     sequence,
		"collected_at": collectedAt.Format(time.RFC3339),
		"payload":      base64.StdEncoding.EncodeToString(payload),
		"signature":    base64.StdEncoding.EncodeToString(record.Signature(key)),
	})

	var response reportResponse
	if len(body) > 0 {
		if err := json.Unmarshal(body, &response); err != nil {
			h.t.Fatalf("解析上报响应失败：%v", err)
		}
	}
	return status, response
}

type recordDTO struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	Sequence    int64  `json:"sequence"`
	CollectedAt string `json:"collected_at"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

type reportResponse struct {
	Accepted    bool        `json:"accepted"`
	Own         *recordDTO  `json:"own"`
	Records     []recordDTO `json:"records"`
	Revocations []struct {
		Fingerprint string `json:"fingerprint"`
		By          string `json:"by"`
		At          string `json:"at"`
	} `json:"revocations"`
}

func TestExchangeOverPinnedTLS(t *testing.T) {
	h := start(t)
	first, second := newKey(t), newKey(t)

	// 两台设备以同一枚凭证注册到同一仓库，得到同一个频道。
	channel := h.register(first, "device-a")
	if other := h.register(second, "device-b"); other != channel {
		t.Fatalf("两台设备得到了不同的频道：%s 与 %s", channel, other)
	}

	// 甲先上报：此时还没有对端，因此回应里没有别人的记录。
	status, response := h.report(first, channel, 1, []byte("甲的密文"))
	if status != http.StatusOK {
		t.Fatalf("甲上报失败：状态 %d", status)
	}
	if !response.Accepted || len(response.Records) != 0 {
		t.Fatalf("甲的上报结果不符：%+v", response)
	}

	// 乙上报，回应里应当带回甲的记录，且记录的签名可用甲的公钥核对。
	status, response = h.report(second, channel, 1, []byte("乙的密文"))
	if status != http.StatusOK {
		t.Fatalf("乙上报失败：状态 %d", status)
	}
	if len(response.Records) != 1 {
		t.Fatalf("乙读到的对端记录数为 %d，期望 1", len(response.Records))
	}

	peer := response.Records[0]
	if peer.Fingerprint != first.Fingerprint().String() {
		t.Fatalf("对端记录来自 %s，期望 %s", peer.Fingerprint, first.Fingerprint())
	}
	peerPayload, err := base64.StdEncoding.DecodeString(peer.Payload)
	if err != nil {
		t.Fatalf("对端记录内容编码不合规：%v", err)
	}
	if string(peerPayload) != "甲的密文" {
		t.Fatalf("对端记录内容为 %q", peerPayload)
	}

	peerSignature, err := base64.StdEncoding.DecodeString(peer.Signature)
	if err != nil {
		t.Fatalf("对端记录签名编码不合规：%v", err)
	}
	collectedAt, err := time.Parse(time.RFC3339, peer.CollectedAt)
	if err != nil {
		t.Fatalf("对端记录的采集时间不合规：%v", err)
	}
	record := envelope.Record{
		Fingerprint: first.Fingerprint(),
		Channel:     channel,
		Sequence:    peer.Sequence,
		CollectedAt: collectedAt,
		Payload:     peerPayload,
	}
	// 核对签名所用的公钥取自回应本身，与设备甲的公钥一致。
	peerPublicKey, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		t.Fatalf("对端公钥编码不合规：%v", err)
	}
	if !bytes.Equal(peerPublicKey, first.Public()) {
		t.Fatalf("对端公钥不符：%x", peerPublicKey)
	}
	if err := record.Verify(ed25519.PublicKey(peerPublicKey), peerSignature); err != nil {
		t.Fatalf("对端记录签名校验失败：%v", err)
	}
}

func TestRejectedReportReturnsOwnRecord(t *testing.T) {
	h := start(t)
	first, second := newKey(t), newKey(t)
	channel := h.register(first, "device-a")
	h.register(second, "device-b")

	if status, _ := h.report(first, channel, 4, []byte("既有的密文")); status != http.StatusOK {
		t.Fatalf("首次上报失败：状态 %d", status)
	}

	// 本地状态被回退时序号会落在既有记录之后，此时被拒并回送既有记录。
	status, response := h.report(first, channel, 2, []byte("回退后的密文"))
	if status != http.StatusOK {
		t.Fatalf("上报失败：状态 %d", status)
	}
	if response.Accepted {
		t.Fatal("序号落后于既有记录时不应被接受")
	}
	if response.Own == nil || response.Own.Sequence != 4 {
		t.Fatalf("未回送本设备既有记录：%+v", response.Own)
	}
	if payload, err := base64.StdEncoding.DecodeString(response.Own.Payload); err != nil || string(payload) != "既有的密文" {
		t.Fatalf("回送的既有记录内容不符：%+v", response.Own)
	}

	// 按既有记录推进序号后即可继续上报。
	status, response = h.report(first, channel, 5, []byte("推进后的密文"))
	if status != http.StatusOK || !response.Accepted {
		t.Fatalf("推进序号后的上报未被接受：状态 %d，响应 %+v", status, response)
	}
}

func TestRevocationIsVisibleToPeers(t *testing.T) {
	h := start(t)
	first, second := newKey(t), newKey(t)
	channel := h.register(first, "device-a")
	h.register(second, "device-b")

	status, body := h.call(second, "/v1/revoke", map[string]string{
		"channel_id": channel,
		"target":     first.Fingerprint().String(),
	})
	if status != http.StatusOK {
		t.Fatalf("吊销失败：状态 %d，正文 %s", status, body)
	}

	// 被吊销的设备再也上报不了，而且是同一个错误，不区分「不存在」与「已吊销」。
	status, _ = h.report(first, channel, 1, []byte("甲的密文"))
	if status != http.StatusUnauthorized {
		t.Fatalf("被吊销设备的上报状态为 %d，期望 %d", status, http.StatusUnauthorized)
	}

	status, response := h.report(second, channel, 1, []byte("乙的密文"))
	if status != http.StatusOK {
		t.Fatalf("乙上报失败：状态 %d", status)
	}
	if len(response.Revocations) != 1 || response.Revocations[0].Fingerprint != first.Fingerprint().String() {
		t.Fatalf("上报未带回吊销名单：%+v", response.Revocations)
	}
}

func TestReloadRequestFileTakesEffect(t *testing.T) {
	h := start(t)
	key := newKey(t)
	h.register(key, "device-a")

	// 关闭注册，并用重载请求让它生效：服务端应当读到新配置，拒绝后续注册。
	settings, err := config.Load(h.configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	text, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatalf("读取配置文本失败：%v", err)
	}
	updated := bytes.Replace(text, []byte("enabled = true"), []byte("enabled = false"), 1)
	updated = bytes.Replace(updated, []byte(`credential_digest = "`+settings.Registration.CredentialDigest+`"`), []byte(`credential_digest = ""`), 1)
	writeFile(t, h.configPath, updated)

	writeFile(t, settings.ReloadRequestPath(), []byte("请求\n"))
	waitReloaded(t, settings.ReloadRequestPath())

	status, _ := h.call(newKey(t), "/v1/register", map[string]string{
		"channel":    "vault-example",
		"credential": credential,
		"label":      "device-b",
		"public_key": "不合规",
	})
	if status != http.StatusForbidden {
		t.Fatalf("关闭注册后的注册状态为 %d，期望 %d", status, http.StatusForbidden)
	}
}

// waitReloaded 等待服务端取走重载请求文件。
func waitReloaded(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(startupWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("服务端未在预期时间内处理重载请求")
}

func TestPlaintextRelayRefusesDestructiveCommands(t *testing.T) {
	h := startPlaintext(t)

	status, body := h.call(newKey(t), "/v1/register", map[string]string{
		"channel":    "vault-example",
		"credential": credential,
		"label":      "device-a",
		"public_key": "不合规",
	})
	if status != http.StatusForbidden {
		t.Fatalf("明文传输下的注册状态为 %d，期望 %d；正文 %s", status, http.StatusForbidden, body)
	}
}

// startPlaintext 启动一个明文传输的服务端，用于验证降级状态下的限制。
func startPlaintext(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	port := freePort(t)
	configPath := filepath.Join(dir, "waystation.toml")
	writeFile(t, configPath, []byte(plaintextConfigText(dir, port)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, server.Options{ConfigPath: configPath, Stderr: io.Discard}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("服务退出时报错：%v", err)
			}
		case <-time.After(startupWait):
			t.Error("服务未在预期时间内退出")
		}
	})

	address := "127.0.0.1:" + strconv.Itoa(port)
	waitReady(t, address)

	settings, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("读取配置失败：%v", err)
	}
	data, err := os.ReadFile(settings.KeyPath())
	if err != nil {
		t.Fatalf("读取服务端密钥失败：%v", err)
	}
	serverKey, err := identity.Decode(string(bytes.TrimSpace(data)))
	if err != nil {
		t.Fatalf("解析服务端密钥失败：%v", err)
	}

	return &harness{
		t:          t,
		url:        "http://" + address,
		configPath: configPath,
		serverKey:  serverKey,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func configText(dir string, port int) string {
	return `version = 1

[server]
listen = "127.0.0.1:` + strconv.Itoa(port) + `"
data_dir = ` + strconv.Quote(filepath.Join(dir, "data")) + `

[registration]
enabled = true
credential_digest = ` + strconv.Quote(config.DigestCredential(credential)) + `

[transport]
mode = "pinned"
cert_file = "relay.crt"
key_file = "relay.key"

[log]
level = "error"
`
}

func plaintextConfigText(dir string, port int) string {
	return `version = 1

[server]
listen = "127.0.0.1:` + strconv.Itoa(port) + `"
data_dir = ` + strconv.Quote(filepath.Join(dir, "data")) + `

[registration]
enabled = true
credential_digest = ` + strconv.Quote(config.DigestCredential(credential)) + `

[transport]
mode = "plaintext"

[log]
level = "error"
`
}

type certificate struct {
	certPEM []byte
	keyPEM  []byte
}

// selfSignedCertificate 生成一份自签证书，仅用于测试。
func selfSignedCertificate(t *testing.T) certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成证书密钥失败：%v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败：%v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码证书私钥失败：%v", err)
	}

	return certificate{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// freePort 取一个空闲端口。
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取得空闲端口失败：%v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("释放空闲端口失败：%v", err)
	}
	return port
}

// waitReady 等待端口可以连接。
func waitReady(t *testing.T, address string) {
	t.Helper()

	deadline := time.Now().Add(startupWait)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("服务未在预期时间内开始监听 %s", address)
}

func newKey(t *testing.T) *identity.KeyPair {
	t.Helper()

	key, err := identity.Generate()
	if err != nil {
		t.Fatalf("生成设备密钥失败：%v", err)
	}
	return key
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("写入 %s 失败：%v", path, err)
	}
}
