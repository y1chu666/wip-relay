package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/y1chu666/wip-relay/internal/config"
	"github.com/y1chu666/wip-relay/internal/envelope"
	"github.com/y1chu666/wip-relay/internal/identity"
	"github.com/y1chu666/wip-relay/internal/store"
)

// errorPayload 是错误正文。
type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorResponse 是全部错误回复的统一外形。
type errorResponse struct {
	Error errorPayload `json:"error"`
}

// channelResponse 是注册成功后返回的频道信息。
type channelResponse struct {
	ChannelID    string `json:"channel_id"`
	ChannelAlias string `json:"channel_alias"`
	// ChannelToken 只在新建频道时返回一次；加入已有频道时为空。
	ChannelToken string `json:"channel_token,omitempty"`
}

// registerRequest 是注册请求。
//
// 请求里没有设备名称：名称由各设备写进自己那份加密内容，中继看不到，
// 也就不必在注册时把名字交到这里。
type registerRequest struct {
	// Alias 是频道显示名，允许重复，也不参与频道识别。
	Alias string `json:"alias"`
	// ChannelID 为空表示新建频道；不为空表示加入这个频道。
	ChannelID string `json:"channel_id"`
	// ChannelToken 是加入已有频道时出示的令牌，与 ChannelID 配对使用。
	ChannelToken string `json:"channel_token"`
	// Credential 只在新建频道时出示。
	Credential string `json:"credential"`
	PublicKey  string `json:"public_key"`
}

// reportRequest 是上报请求。
type reportRequest struct {
	ChannelID   string `json:"channel_id"`
	Sequence    int64  `json:"sequence"`
	CollectedAt string `json:"collected_at"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// recordDTO 是一条状态记录。
//
// 公钥随记录一并给出，使接收方得以核对记录签名，确认它确实出自该设备；
// 客户端首次见到某台设备的公钥即钉住，此后公钥变化就说明身份对不上，应当停止采用。
type recordDTO struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	Sequence    int64  `json:"sequence"`
	CollectedAt string `json:"collected_at"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// revocationDTO 是一条吊销纪录。
type revocationDTO struct {
	Fingerprint string `json:"fingerprint"`
	By          string `json:"by"`
	At          string `json:"at"`
}

// reportResponse 是上报的回复。
//
// 被拒时一并回送本设备既有记录：设备本地状态被回退，或同一身份被复制到两台机器时，
// 它的序号会落在中继已有记录之后，只有拿到既有记录才知道该从哪里继续，否则无从对齐。
type reportResponse struct {
	Accepted    bool            `json:"accepted"`
	Own         *recordDTO      `json:"own,omitempty"`
	Records     []recordDTO     `json:"records"`
	Revocations []revocationDTO `json:"revocations"`
	// Truncated 表示回送的记录因大小或条数上限被截断：对端据此知道自己的视图不完整。
	Truncated bool `json:"truncated,omitempty"`
}

// 上报响应的容量约束。
//
// 不设约束时，响应大小随频道内设备数、单条记录大小与吊销名单长度线性增长，
// 最坏可到数 GB：收件方每次上报都要整份组装一次。上限取在插件 8 MiB 响应上限
// 之下，使频道再大也不至于把对端直接挤下线。
const (
	maxReportBytes      = 7 << 20
	recordOverheadBytes = 256
	revocationRowBytes  = 256
	// revocationsShare 是吊销名单在回送里最多占用的字节数。吊销条目同样只增不减，
	// 若与记录共用整份预算，一份堆长的名单就能把各端状态挤得一条也回不去。
	revocationsShare = maxReportBytes / 4
)

// maxSequence 是允许上报的序号上界。
//
// 客户端的序号用 JavaScript 数值表示，超过 2^53-1 就无法精确表示；若任由某台设备
// 写进这样的序号，中继会把无从解析的记录回送给同频道所有设备，使它们每次同步都失败。
const maxSequence = 1<<53 - 1

// revokeRequest 是吊销请求。
type revokeRequest struct {
	ChannelID string `json:"channel_id"`
	Target    string `json:"target"`
}

// revokeResponse 是吊销的回复。
type revokeResponse struct {
	Revoked string `json:"revoked"`
}

// retireRequest 是退役请求。
type retireRequest struct {
	ChannelID string `json:"channel_id"`
}

// retireResponse 是退役的回复。
type retireResponse struct {
	Retired string `json:"retired"`
}

// handleRegister 处理设备注册。
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()

	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w, cfg) {
		return
	}

	request, ok := s.readSignedRequest(w, r, cfg)
	if !ok {
		return
	}

	var payload registerRequest
	if !s.decode(w, request.Body, &payload) {
		return
	}

	if payload.ChannelID == "" && !cfg.Registration.Enabled {
		s.writeError(w, http.StatusForbidden, codeForbidden, "服务端当前未开放注册")
		return
	}

	publicKey, err := base64.StdEncoding.DecodeString(payload.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "公钥不合规")
		return
	}
	if identity.FingerprintOf(publicKey) != request.Fingerprint {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "公钥与请求头中的指纹不符")
		return
	}
	// 注册尚未登记设备，因此这里用请求自带的公钥验签；指纹与公钥的对应关系已在上面核对。
	if !s.verify(w, r, request, ed25519.PublicKey(publicKey)) {
		return
	}

	channel, token, err := s.register(cfg, payload, request, publicKey)
	switch {
	case errors.Is(err, errRegistrationClosed):
		s.writeError(w, http.StatusForbidden, codeForbidden, "服务端当前未开放注册")
		return
	case errors.Is(err, errBadCredential):
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "注册凭证不正确")
		return
	case errors.Is(err, errMissingAlias):
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "缺少频道别名")
		return
	case errors.Is(err, errChannelNotFound):
		s.writeError(w, http.StatusNotFound, codeNotFound, "频道不存在")
		return
	case errors.Is(err, errBadChannelToken):
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "频道令牌不正确")
		return
	case errors.Is(err, errDeviceRevoked):
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "该设备已被吊销，不能再次注册")
		return
	case errors.Is(err, errChannelFull):
		s.writeError(w, http.StatusConflict, codeLimit, "频道内设备数已达上限")
		return
	case err != nil:
		s.internal(w, err)
		return
	}

	if token == "" {
		s.logger.Info("设备已加入频道", "频道", channel.ID, "设备", request.Fingerprint.String())
	} else {
		s.logger.Info("频道已创建", "频道", channel.ID, "别名", channel.Alias)
	}
	s.writeJSON(w, http.StatusOK, channelResponse{
		ChannelID:    string(channel.ID),
		ChannelAlias: channel.Alias,
		ChannelToken: token,
	})
}

// register 在临界区里完成创建或加入，并登记设备。
//
// 频道标识由服务端生成、全局唯一；别名只用于显示，允许重复。加入已有频道必须
// 出示与该标识配对的令牌，否则任何拿到注册凭证的人都能闯进别人的频道。
func (s *Server) register(
	cfg *config.Config,
	payload registerRequest,
	request signedRequest,
	publicKey ed25519.PublicKey,
) (store.Channel, string, error) {
	s.channelMu.Lock()
	defer s.channelMu.Unlock()

	channel, issued, err := s.resolveChannel(cfg, payload)
	if err != nil {
		return store.Channel{}, "", err
	}
	if err := s.addDevice(cfg, channel, request, publicKey); err != nil {
		return store.Channel{}, "", err
	}
	return channel, issued, nil
}

// resolveChannel 决定这次注册是新建频道还是加入已有频道。
//
// 新建时生成令牌并只返回这一次；加入时只核对令牌摘要，不再回传令牌。
func (s *Server) resolveChannel(
	cfg *config.Config,
	payload registerRequest,
) (store.Channel, string, error) {
	if payload.ChannelID != "" {
		channel, err := s.store.Channel(store.ChannelID(payload.ChannelID))
		switch {
		case errors.Is(err, store.ErrChannelNotFound):
			return store.Channel{}, "", errChannelNotFound
		case err != nil:
			return store.Channel{}, "", err
		}
		if !tokenMatches(channel.TokenHash, payload.ChannelToken) {
			return store.Channel{}, "", errBadChannelToken
		}
		return channel, "", nil
	}

	if !cfg.Registration.Enabled {
		return store.Channel{}, "", errRegistrationClosed
	}
	if config.DigestCredential(payload.Credential) != cfg.Registration.CredentialDigest {
		return store.Channel{}, "", errBadCredential
	}
	if payload.Alias == "" {
		return store.Channel{}, "", errMissingAlias
	}

	token, err := newChannelToken()
	if err != nil {
		return store.Channel{}, "", err
	}
	id, err := s.newID()
	if err != nil {
		return store.Channel{}, "", err
	}
	channel := store.Channel{
		ID:        id,
		Alias:     payload.Alias,
		TokenHash: digestToken(token),
		CreatedAt: s.now().UTC(),
	}
	if err := s.store.CreateChannel(channel); err != nil {
		return store.Channel{}, "", err
	}
	return channel, token, nil
}

// addDevice 检查吊销、重复注册与设备数上限，然后把设备写进频道。
func (s *Server) addDevice(
	cfg *config.Config,
	channel store.Channel,
	request signedRequest,
	publicKey ed25519.PublicKey,
) error {
	if _, err := s.store.Revocation(channel.ID, request.Fingerprint); err == nil {
		return errDeviceRevoked
	} else if !errors.Is(err, store.ErrNotRevoked) {
		return err
	}

	if _, err := s.store.Device(channel.ID, request.Fingerprint); err == nil {
		// 重复注册视为幂等：设备已经在频道里，直接回以频道信息。
		return nil
	} else if !errors.Is(err, store.ErrDeviceNotFound) {
		return err
	}

	count, err := s.store.CountDevices(channel.ID)
	if err != nil {
		return err
	}
	if count >= cfg.Limits.DevicesPerChannel {
		return errChannelFull
	}

	return s.store.AddDevice(channel.ID, store.Device{
		Fingerprint:  request.Fingerprint,
		PublicKey:    publicKey,
		RegisteredAt: s.now().UTC(),
	})
}

// newChannelToken 生成一枚频道令牌；只在创建频道时返回一次。
func newChannelToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// digestToken 取令牌的摘要；服务端只保存摘要。
func digestToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// tokenMatches 以常数时间比较，免得比较耗时泄露前缀信息。
func tokenMatches(hash []byte, token string) bool {
	if len(hash) == 0 || token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash, sum[:]) == 1
}

// handleReport 处理状态上报，并把频道内其他设备的状态一并回送。
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()

	if !s.allowAddress(w, r) {
		return
	}

	request, ok := s.readSignedRequest(w, r, cfg)
	if !ok {
		return
	}

	var payload reportRequest
	if !s.decode(w, request.Body, &payload) {
		return
	}

	channel := store.ChannelID(payload.ChannelID)
	if channel == "" {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "缺少频道标识")
		return
	}

	device, ok := s.authenticate(w, r, request, channel)
	if !ok {
		return
	}

	collectedAt, err := time.Parse(time.RFC3339, payload.CollectedAt)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "采集时间不合规")
		return
	}
	if payload.Sequence < 0 {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "序号不得为负数")
		return
	}
	if payload.Sequence > maxSequence {
		// 文案里的上界必须与 maxSequence 一致：用例会拿两者比对，改一处而忘了另一处即失败。
		s.writeError(w, http.StatusBadRequest, codeBadRequest,
			"序号超出可表示范围（上界 9007199254740991）：请在客户端核对本机计数后重置")
		return
	}

	recordPayload, err := base64.StdEncoding.DecodeString(payload.Payload)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "记录内容编码不合规")
		return
	}
	if len(recordPayload) > cfg.Limits.RecordBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, codeLimit, "记录内容超过允许大小")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "记录签名编码不合规")
		return
	}

	record := store.Record{
		Fingerprint: device.Fingerprint,
		Sequence:    payload.Sequence,
		CollectedAt: collectedAt.UTC(),
		Payload:     recordPayload,
		Signature:   signature,
	}

	// 记录签名由设备本人完成，服务端只做核对，绝不代签。
	signed := envelope.Record{
		Fingerprint: record.Fingerprint,
		Channel:     string(channel),
		Sequence:    record.Sequence,
		CollectedAt: record.CollectedAt,
		Payload:     record.Payload,
	}
	if err := signed.Verify(ed25519.PublicKey(device.PublicKey), record.Signature); err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadSignature, "记录签名校验未通过")
		return
	}

	accepted, err := s.store.PutRecord(channel, record)
	if err != nil {
		s.internal(w, err)
		return
	}

	records, err := s.store.Records(channel)
	if err != nil {
		s.internal(w, err)
		return
	}
	revocations, err := s.store.Revocations(channel)
	if err != nil {
		s.internal(w, err)
		return
	}

	devices, err := s.store.Devices(channel)
	if err != nil {
		s.internal(w, err)
		return
	}
	publicKeys := make(map[identity.Fingerprint]string, len(devices))
	for _, item := range devices {
		publicKeys[item.Fingerprint] = base64.StdEncoding.EncodeToString(item.PublicKey)
	}

	response := reportResponse{
		Accepted:    accepted,
		Records:     make([]recordDTO, 0, len(records)),
		Revocations: make([]revocationDTO, 0, len(revocations)),
	}
	revocations, response.Truncated = trimRevocations(revocations, revocationsInReply(cfg))
	for _, item := range revocations {
		response.Revocations = append(response.Revocations, revocationDTO{
			Fingerprint: item.Fingerprint.String(),
			By:          item.By.String(),
			At:          item.At.UTC().Format(time.RFC3339),
		})
	}

	budget := maxReportBytes - len(response.Revocations)*revocationRowBytes
	if !accepted {
		existing, err := s.store.Record(channel, device.Fingerprint)
		if err != nil {
			s.internal(w, err)
			return
		}
		own := toRecordDTO(existing, publicKeys[device.Fingerprint])
		response.Own = &own
		budget -= estimateRecordBytes(len(existing.Payload), len(existing.Signature))
	}

	others := make([]store.Record, 0, len(records))
	for _, item := range records {
		// 不回送调用者自己的记录：它比谁都清楚自己刚才上报了什么。
		if item.Fingerprint == device.Fingerprint {
			continue
		}
		others = append(others, item)
	}
	// 从新到旧回送：预算不够时先保住最新的状态，免得某台设备长期取不到。
	sort.SliceStable(others, func(i, j int) bool {
		return others[i].CollectedAt.After(others[j].CollectedAt)
	})

	for _, item := range others {
		if len(response.Records) >= cfg.Limits.RecordsPerRequest {
			response.Truncated = true
			break
		}
		size := estimateRecordBytes(len(item.Payload), len(item.Signature))
		// 第一条一律回送：只带回一条也胜过一条都不带，否则对端永远停在旧状态上。
		// 例外是本设备被拒的这一轮：既有记录必须回去，它是本设备继续上报的唯一线索，
		// 而其余记录下一轮还有机会——设备推进序号之后就不再是被拒了。
		if size > budget && (len(response.Records) > 0 || response.Own != nil) {
			response.Truncated = true
			break
		}
		budget -= size
		response.Records = append(response.Records, toRecordDTO(item, publicKeys[item.Fingerprint]))
	}

	s.writeJSON(w, http.StatusOK, response)
}

// estimateRecordBytes 估计一条记录在响应里占用的字节数：正文与签名按 base64 折算，
// 其余字段按常量计。宁可略高估，也不要让响应越过客户端的上限。
func estimateRecordBytes(payload, signature int) int {
	return base64Len(payload) + base64Len(signature) + recordOverheadBytes
}

// revocationsInReply 是回送里吊销条数的上限：既不超过频道自己的上限，也不越过
// 吊销名单在回送预算里分到的那一份。
func revocationsInReply(cfg *config.Config) int {
	return min(cfg.Limits.RevocationsPerChannel, revocationsShare/revocationRowBytes)
}

// trimRevocations 把吊销名单截到给定条数，并报告是否截断。
//
// 截断时按时间从新到旧取舍：刚发生的吊销最需要尽快送到对端，早先的条目客户端多半
// 已经收下，放到下一轮再取不会漏掉。名单本身按指纹排序，直接截尾会每次都漏掉同一批。
func trimRevocations(revocations []store.Revocation, limit int) ([]store.Revocation, bool) {
	if len(revocations) <= limit {
		return revocations, false
	}

	kept := append([]store.Revocation(nil), revocations...)
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].At.After(kept[j].At) })
	return kept[:limit], true
}

// base64Len 是 n 字节按标准 base64 编码后的长度。
func base64Len(n int) int {
	return (n + 2) / 3 * 4
}

// toRecordDTO 把库中的记录整理成回复里的形状。公钥可能缺失，此时留空，
// 由客户端判断该条记录无法核对而暂时不用。
func toRecordDTO(record store.Record, publicKey string) recordDTO {
	return recordDTO{
		Fingerprint: record.Fingerprint.String(),
		PublicKey:   publicKey,
		Sequence:    record.Sequence,
		CollectedAt: record.CollectedAt.UTC().Format(time.RFC3339),
		Payload:     base64.StdEncoding.EncodeToString(record.Payload),
		Signature:   base64.StdEncoding.EncodeToString(record.Signature),
	}
}

// handleRevoke 处理吊销请求。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()

	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w, cfg) {
		return
	}

	request, ok := s.readSignedRequest(w, r, cfg)
	if !ok {
		return
	}

	var payload revokeRequest
	if !s.decode(w, request.Body, &payload) {
		return
	}

	channel := store.ChannelID(payload.ChannelID)
	if channel == "" {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "缺少频道标识")
		return
	}

	device, ok := s.authenticate(w, r, request, channel)
	if !ok {
		return
	}

	target, err := identity.ParseFingerprint(payload.Target)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "被吊销设备的指纹不合规")
		return
	}

	err = s.revokeDevice(cfg, channel, device.Fingerprint, target)
	switch {
	case errors.Is(err, store.ErrDeviceNotFound):
		s.writeError(w, http.StatusNotFound, codeNotFound, "该设备不在频道内")
		return
	case errors.Is(err, errLastDevice):
		// 防自锁：吊销之后频道里会一台可用设备也不剩，谁也进不来了。
		s.writeError(w, http.StatusConflict, codeConflict, "不允许吊销频道内最后一台可用设备")
		return
	case errors.Is(err, errRevocationsFull):
		s.writeError(w, http.StatusConflict, codeLimit, revocationsFullMessage)
		return
	case err != nil:
		s.internal(w, err)
		return
	}

	s.logger.Info("设备已被吊销", "频道", channel, "设备", target.String(), "发起者", device.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, revokeResponse{Revoked: target.String()})
}

// revokeDevice 在临界区里完成一次吊销：核对目标在频道内、防自锁、核对名单上限、
// 写入名单。
//
// 这些事必须一起完成。吊销不移除设备，被吊销的设备留在列表里却已是废票，因此
// 「会不会把频道吊销空」只能按未被吊销的设备数判断；判定与写入之间若能插进别的
// 请求，两台设备就会各自通过判定，结果仍是频道里一台可用设备也不剩。
func (s *Server) revokeDevice(cfg *config.Config, channel store.ChannelID, by, target identity.Fingerprint) error {
	s.channelMu.Lock()
	defer s.channelMu.Unlock()

	if _, err := s.store.Device(channel, target); err != nil {
		return err
	}

	active, revoked, err := s.channelMembers(channel)
	if err != nil {
		return err
	}
	if active[target] {
		// 目标已被吊销时两项判定都不适用：重复吊销不改变既有条目，也就不会
		// 把频道吊销空，也不必占新的条数。
		if revoked >= cfg.Limits.RevocationsPerChannel {
			return errRevocationsFull
		}
		if len(active) <= 1 {
			return errLastDevice
		}
	}

	return s.store.Revoke(channel, store.Revocation{Fingerprint: target, By: by, At: s.now().UTC()})
}

// channelMembers 返回频道内尚未被吊销的设备，以及吊销名单的条数。
//
// 吊销不移除设备，设备列表里既有可用设备，也有只剩名分的废票，两者必须分开数。
func (s *Server) channelMembers(channel store.ChannelID) (map[identity.Fingerprint]bool, int, error) {
	devices, err := s.store.Devices(channel)
	if err != nil {
		return nil, 0, err
	}
	revocations, err := s.store.Revocations(channel)
	if err != nil {
		return nil, 0, err
	}

	revoked := make(map[identity.Fingerprint]bool, len(revocations))
	for _, item := range revocations {
		revoked[item.Fingerprint] = true
	}

	active := make(map[identity.Fingerprint]bool, len(devices))
	for _, item := range devices {
		if !revoked[item.Fingerprint] {
			active[item.Fingerprint] = true
		}
	}
	return active, len(revocations), nil
}

// handleRetire 处理设备退役：删除自己的记录、移出设备列表并记入吊销，一步不可回退。
func (s *Server) handleRetire(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings()

	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w, cfg) {
		return
	}

	request, ok := s.readSignedRequest(w, r, cfg)
	if !ok {
		return
	}

	var payload retireRequest
	if !s.decode(w, request.Body, &payload) {
		return
	}

	channel := store.ChannelID(payload.ChannelID)
	if channel == "" {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "缺少频道标识")
		return
	}

	device, ok := s.authenticate(w, r, request, channel)
	if !ok {
		return
	}

	err := s.retireDevice(cfg, channel, device.Fingerprint)
	switch {
	case errors.Is(err, errRevocationsFull):
		s.writeError(w, http.StatusConflict, codeLimit, revocationsFullMessage)
		return
	case err != nil:
		s.internal(w, err)
		return
	}

	s.logger.Info("设备已退役", "频道", channel, "设备", device.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, retireResponse{Retired: device.Fingerprint.String()})
}

// retireDevice 在临界区里完成退役：核对名单上限、删除记录、移出设备列表、
// 记入吊销名单。
//
// 退役没有门槛，但它同样要占一条吊销纪录。若不与吊销共用同一份上限，反复注册
// 再退役就能把名单堆到任意长，而同频道的对端每次上报都要取回整份名单。
func (s *Server) retireDevice(cfg *config.Config, channel store.ChannelID, fingerprint identity.Fingerprint) error {
	s.channelMu.Lock()
	defer s.channelMu.Unlock()

	count, err := s.store.CountRevocations(channel)
	if err != nil {
		return err
	}
	if count >= cfg.Limits.RevocationsPerChannel {
		return errRevocationsFull
	}

	if err := s.store.DeleteRecord(channel, fingerprint); err != nil && !errors.Is(err, store.ErrRecordNotFound) {
		return err
	}
	if err := s.store.RemoveDevice(channel, fingerprint); err != nil {
		return err
	}
	revocation := store.Revocation{Fingerprint: fingerprint, By: fingerprint, At: s.now().UTC()}
	return s.store.Revoke(channel, revocation)
}
