// Package api 实现中继服务端的 HTTP 接口。
//
// 接口只做校验、存取与转达：服务端读不懂记录内容，也不替设备推进序号，
// 因此即便这里实现有误，中继也无法伪造其他设备的状态。
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/envelope"
	"vaultwaystation/internal/identity"
	"vaultwaystation/internal/store"
)

// 请求头名称。签名覆盖方法、路径与正文摘要，因此这些头本身不必再签。
const (
	headerFingerprint = "X-Waystation-Fingerprint"
	headerTimestamp   = "X-Waystation-Timestamp"
	headerNonce       = "X-Waystation-Nonce"
	headerSignature   = "X-Waystation-Signature"
	// headerPublicKey 随每次回应给出服务端公钥，供客户端首次配对时钉住。
	// 公钥本就不必保密，放在这里省去一个只为取公钥而设的端点。
	headerPublicKey = "X-Waystation-Public-Key"
)

// 错误代码。客户端按代码判断，不解析文案。
const (
	codeBadRequest   = "bad_request"
	codeBadSignature = "bad_signature"
	codeUnauthorized = "unauthorized"
	codeForbidden    = "forbidden"
	codeReplay       = "replay"
	codeSkew         = "skew"
	codeNotFound     = "not_found"
	codeConflict     = "conflict"
	codeLimit        = "limit"
	codeInternal     = "internal"
)

// 注册与吊销路径上可预期的失败：设备已被吊销、频道已满、目标不在频道内或已是最后一台可用设备。
var (
	errDeviceRevoked = errors.New("设备已被吊销")
	errChannelFull   = errors.New("频道内设备数已达上限")
	errLastDevice    = errors.New("不允许吊销频道内最后一台可用设备")
)

// channelIDBytes 是频道标识的随机字节数。
const channelIDBytes = 16

// Server 是中继服务端的接口实现。
type Server struct {
	// settings 用原子指针存放，使配置重载与并发请求互不阻塞。
	settings atomic.Pointer[config.Config]

	store   *store.Store
	key     *identity.KeyPair
	replay  *envelope.ReplayGuard
	limiter *limiter
	logger  *slog.Logger

	// channelMu 串行化会改动频道成员状态的请求：注册（解析或建立频道、数设备、
	// 写设备）与吊销（核对目标、数可用设备、写名单）必须各自一起完成，否则并发
	// 请求既能突破设备数上限、为同一个别名建出多个频道，也能把频道吊销到一台
	// 可用设备不剩。存储以独占方式打开，服务端因此只能是单进程，进程内串行即可。
	channelMu sync.Mutex

	// now 与 newID 允许在测试中固定取值。
	now   func() time.Time
	newID func() (store.ChannelID, error)
}

// New 创建接口实现。
func New(cfg *config.Config, st *store.Store, key *identity.KeyPair, logger *slog.Logger) *Server {
	server := &Server{
		store:   st,
		key:     key,
		replay:  envelope.NewReplayGuard(envelope.ClockSkew),
		limiter: newLimiter(cfg.Limits.RequestsPerMinute),
		logger:  logger,
		now:     time.Now,
		newID:   newChannelID,
	}
	server.settings.Store(cfg)
	return server
}

// Settings 返回当前生效的配置。
func (s *Server) Settings() *config.Config {
	return s.settings.Load()
}

// Reload 换用一份新配置，使各项上限与传输级别立即生效。
//
// 监听地址与证书在进程启动时已经就位，重载改不动它们，那需要重启。
// 限流器沿用同一个，只是换了配额：计数保留下来并无坏处，窗口一过自然清零。
func (s *Server) Reload(settings *config.Config) {
	s.settings.Store(settings)
	s.limiter.setLimit(settings.Limits.RequestsPerMinute)
}

// Handler 返回可供 http.Server 使用的处理器。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.handleRegister)
	mux.HandleFunc("POST /v1/report", s.handleReport)
	mux.HandleFunc("POST /v1/revoke", s.handleRevoke)
	mux.HandleFunc("POST /v1/retire", s.handleRetire)
	return s.recoverPanics(mux)
}

// signedRequest 是一次带签名的请求。
type signedRequest struct {
	Body        []byte
	Fingerprint identity.Fingerprint
	Timestamp   time.Time
	Nonce       string
	Signature   []byte
}

// recoverPanics 兜住单个请求的崩溃，避免整个服务因此退出。
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if cause := recover(); cause != nil {
				s.logger.Error("处理请求时崩溃", "路径", r.URL.Path, "原因", cause)
				s.writeError(w, http.StatusInternalServerError, codeInternal, "服务端内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// readSignedRequest 读取请求体与签名相关的请求头，任何一处不合规都即时回复并返回假。
func (s *Server) readSignedRequest(w http.ResponseWriter, r *http.Request, cfg *config.Config) (signedRequest, bool) {
	var request signedRequest

	body, err := s.readBody(w, r, cfg)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, http.StatusRequestEntityTooLarge, codeLimit, "请求体超过允许大小")
			return signedRequest{}, false
		}
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "读取请求体失败")
		return signedRequest{}, false
	}
	request.Body = body

	fingerprint, err := identity.ParseFingerprint(r.Header.Get(headerFingerprint))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "请求头中的设备指纹不合规")
		return signedRequest{}, false
	}
	request.Fingerprint = fingerprint

	seconds, err := strconv.ParseInt(r.Header.Get(headerTimestamp), 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "请求头中的时间戳不合规")
		return signedRequest{}, false
	}
	request.Timestamp = time.Unix(seconds, 0)

	request.Nonce = r.Header.Get(headerNonce)
	if len(request.Nonce) != envelope.NonceBytes*2 {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "请求头中的一次性随机值不合规")
		return signedRequest{}, false
	}

	signature, err := hex.DecodeString(r.Header.Get(headerSignature))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "请求头中的签名编码不合规")
		return signedRequest{}, false
	}
	request.Signature = signature

	return request, true
}

// readBody 读取请求体，并施加与记录大小相称的上限。
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, cfg *config.Config) ([]byte, error) {
	// 上限留出编码开销：正文里除了记录本身，还有 JSON 结构与签名。
	limit := int64(cfg.Limits.RecordBytes)*4/3 + 8192
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

// verify 校验签名、时间窗口与新鲜度，失败时回复并返回假。
func (s *Server) verify(w http.ResponseWriter, r *http.Request, request signedRequest, public ed25519.PublicKey) bool {
	now := s.now()

	incoming := envelope.Request{
		Method:      r.Method,
		Path:        r.URL.Path,
		Fingerprint: request.Fingerprint,
		Timestamp:   request.Timestamp,
		Nonce:       request.Nonce,
		Body:        request.Body,
	}

	if err := incoming.Verify(public, request.Signature, now); err != nil {
		switch {
		case errors.Is(err, envelope.ErrTimestampSkew):
			// 把服务端时间回报给对端，便于其校正时钟后重试。
			s.writeError(w, http.StatusUnauthorized, codeSkew,
				fmt.Sprintf("时间戳超出允许窗口；服务端时间为 %s", now.UTC().Format(time.RFC3339)))
		case errors.Is(err, identity.ErrBadSignature):
			s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "签名校验未通过")
		default:
			// 剩下的唯一可能是存储里的公钥已经损坏，这属于服务端自己的问题。
			s.logger.Error("存储中的公钥不可用", "设备", request.Fingerprint.String(), "原因", err)
			s.writeError(w, http.StatusInternalServerError, codeInternal, "服务端内部错误")
		}
		return false
	}

	if !s.replay.Accept(request.Fingerprint, request.Nonce, now) {
		s.writeError(w, http.StatusUnauthorized, codeReplay, "该一次性随机值已经用过")
		return false
	}
	return true
}

// authenticate 取出设备并完成签名校验与设备级限流。
//
// 设备维度的计数放在验签之后：设备指纹在频道内是公开的（对端上报时就会拿到），
// 若先计数再验签，任何人只要知道指纹就能用它把该设备的配额耗光，属未认证的拒绝服务。
// 验签之前的挡量由来源地址维度负责。
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, request signedRequest, channel store.ChannelID) (store.Device, bool) {
	device, err := s.deviceFor(channel, request.Fingerprint)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "设备未注册或已被吊销")
		return store.Device{}, false
	}

	if !s.verify(w, r, request, ed25519.PublicKey(device.PublicKey)) {
		return store.Device{}, false
	}

	if !s.limiter.allow("device:"+device.Fingerprint.String(), s.now()) {
		s.writeError(w, http.StatusTooManyRequests, codeLimit, "请求过于频繁")
		return store.Device{}, false
	}
	return device, true
}

// deviceFor 取出频道内已注册且未被吊销的设备。
//
// 频道不存在、设备未注册与设备已被吊销返回同一个错误：这三种情形对外没有差别，
// 区分开来只会替人探测某台设备是否曾经注册。
func (s *Server) deviceFor(channel store.ChannelID, fingerprint identity.Fingerprint) (store.Device, error) {
	device, err := s.store.Device(channel, fingerprint)
	if err != nil {
		return store.Device{}, err
	}

	if _, err := s.store.Revocation(channel, fingerprint); err == nil {
		return store.Device{}, store.ErrNotRevoked
	} else if !errors.Is(err, store.ErrNotRevoked) {
		return store.Device{}, err
	}
	return device, nil
}

// allowAddress 按来源地址限流，用于在验签之前挡住大量请求。
func (s *Server) allowAddress(w http.ResponseWriter, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if !s.limiter.allow("addr:"+host, s.now()) {
		s.writeError(w, http.StatusTooManyRequests, codeLimit, "请求过于频繁")
		return false
	}
	return true
}

// allowDestructive 拒绝在降级传输下执行破坏性操作。
//
// 降级意味着中间人可能在场，此时允许注册或退役，等于把设备身份交到对手手上。
func (s *Server) allowDestructive(w http.ResponseWriter, cfg *config.Config) bool {
	if cfg.Transport.Degraded() {
		s.writeError(w, http.StatusForbidden, codeForbidden, "当前传输级别属于降级，禁止执行注册与退役")
		return false
	}
	return true
}

// decode 解析请求体；多写字段视为不合规，以免客户端写错字段名而被默默忽略。
func (s *Server) decode(w http.ResponseWriter, body []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "请求内容不合规")
		return false
	}
	return true
}

// internal 记录并回复内部错误。具体原因只进日志，不返回给客户端。
func (s *Server) internal(w http.ResponseWriter, err error) {
	s.logger.Error("服务端内部错误", "原因", err)
	s.writeError(w, http.StatusInternalServerError, codeInternal, "服务端内部错误")
}

// writeError 回复一条错误。
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, errorResponse{Error: errorPayload{Code: code, Message: message}})
}

// writeJSON 以服务端私钥签名后写出响应。
//
// 响应签名覆盖状态码与正文摘要，客户端凭首次配对时钉住的公钥核对，
// 因此中间人即便替换了正文，也无法出示可验证的签名。
func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("序列化响应失败", "原因", err)
		status = http.StatusInternalServerError
		body = []byte(`{"error":{"code":"` + codeInternal + `","message":"服务端内部错误"}}`)
	}

	response := envelope.Response{
		Fingerprint: s.key.Fingerprint(),
		Status:      status,
		Body:        body,
	}

	w.Header().Set(headerFingerprint, response.Fingerprint.String())
	w.Header().Set(headerPublicKey, base64.StdEncoding.EncodeToString(s.key.Public()))
	w.Header().Set(headerSignature, hex.EncodeToString(response.Signature(s.key)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if _, err := w.Write(body); err != nil {
		s.logger.Error("写出响应失败", "原因", err)
	}
}

// newChannelID 生成频道标识。
func newChannelID() (store.ChannelID, error) {
	buf := make([]byte, channelIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成频道标识：%w", err)
	}
	return store.ChannelID(hex.EncodeToString(buf)), nil
}
