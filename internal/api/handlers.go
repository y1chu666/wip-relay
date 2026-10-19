package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"sort"
	"time"

	"vaultwaystation/internal/config"
	"vaultwaystation/internal/envelope"
	"vaultwaystation/internal/identity"
	"vaultwaystation/internal/store"
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
}

// registerRequest 是注册请求。
//
// 请求里没有设备名称：名称由各设备写进自己那份加密内容，中继看不到，
// 也就不必在注册时把名字交到这里。
type registerRequest struct {
	// Channel 是设备所报的仓库名称，服务端据此加入或建立频道。
	Channel    string `json:"channel"`
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
// 不设约束时，响应大小随频道内设备数与单条记录大小线性增长，最坏可到数 GB：
// 收件方每次上报都要整份组装一次。上限取在插件 8 MiB 响应上限之下，
// 使频道再大也不至于把对端直接挤下线。
const (
	maxReportBytes      = 7 << 20
	recordOverheadBytes = 256
	revocationRowBytes  = 256
)

//
// 客户端的序号用 JavaScript 数值表示，超过 2^53-1 就无法精确表示；若任由某台设备
// 写进这样的序号，中继会把无从解析的记录回送给同频道所有设备，使它们每次同步都失败。
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
	if payload.Channel == "" {
		s.writeError(w, http.StatusBadRequest, codeBadRequest, "缺少仓库名称")
		return
	}

	if !cfg.Registration.Enabled {
		s.writeError(w, http.StatusForbidden, codeForbidden, "服务端当前未开放注册")
		return
	}
	if config.DigestCredential(payload.Credential) != cfg.Registration.CredentialDigest {
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "注册凭证不正确")
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

	channel, err := s.registerDevice(cfg, payload.Channel, request, publicKey)
	switch {
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

	s.logger.Info("设备已注册", "频道", channel.ID, "设备", request.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, channelResponse{ChannelID: string(channel.ID), ChannelAlias: channel.Alias})
}

// registerDevice 在临界区里完成注册：解析或建立频道、检查吊销与重复注册、
// 数设备、写入设备。
//
// 检查与写入之间若能被别的请求插进来，并发注册就能突破设备数上限，也会为同一个
// 别名建出多个频道——那会让同一仓库的两台设备互相看不到对方的记录。
func (s *Server) registerDevice(cfg *config.Config, alias string, request signedRequest, publicKey ed25519.PublicKey) (store.Channel, error) {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()

	channel, err := s.channelByName(alias)
	if err != nil {
		return store.Channel{}, err
	}

	if _, err := s.store.Revocation(channel.ID, request.Fingerprint); err == nil {
		return store.Channel{}, errDeviceRevoked
	} else if !errors.Is(err, store.ErrNotRevoked) {
		return store.Channel{}, err
	}

	if _, err := s.store.Device(channel.ID, request.Fingerprint); err == nil {
		// 重复注册视为幂等：设备已经在频道里，直接回以频道信息。
		return channel, nil
	} else if !errors.Is(err, store.ErrDeviceNotFound) {
		return store.Channel{}, err
	}

	count, err := s.store.CountDevices(channel.ID)
	if err != nil {
		return store.Channel{}, err
	}
	if count >= cfg.Limits.DevicesPerChannel {
		return store.Channel{}, errChannelFull
	}

	device := store.Device{
		Fingerprint:  request.Fingerprint,
		PublicKey:    publicKey,
		RegisteredAt: s.now().UTC(),
	}
	if err := s.store.AddDevice(channel.ID, device); err != nil {
		return store.Channel{}, err
	}
	return channel, nil
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
		if len(response.Records) > 0 && size > budget {
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
	if _, err := s.store.Device(channel, target); err != nil {
		s.writeError(w, http.StatusNotFound, codeNotFound, "该设备不在频道内")
		return
	}

	count, err := s.store.CountDevices(channel)
	if err != nil {
		s.internal(w, err)
		return
	}
	if count <= 1 {
		// 防自锁：频道里只剩一台设备时不许吊销，否则谁也进不来了。
		s.writeError(w, http.StatusConflict, codeConflict, "不允许吊销频道内最后一台已注册设备")
		return
	}

	revocation := store.Revocation{Fingerprint: target, By: device.Fingerprint, At: s.now().UTC()}
	if err := s.store.Revoke(channel, revocation); err != nil {
		s.internal(w, err)
		return
	}

	s.logger.Info("设备已被吊销", "频道", channel, "设备", target.String(), "发起者", device.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, revokeResponse{Revoked: target.String()})
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

	if err := s.store.DeleteRecord(channel, device.Fingerprint); err != nil && !errors.Is(err, store.ErrRecordNotFound) {
		s.internal(w, err)
		return
	}
	if err := s.store.RemoveDevice(channel, device.Fingerprint); err != nil {
		s.internal(w, err)
		return
	}
	revocation := store.Revocation{Fingerprint: device.Fingerprint, By: device.Fingerprint, At: s.now().UTC()}
	if err := s.store.Revoke(channel, revocation); err != nil {
		s.internal(w, err)
		return
	}

	s.logger.Info("设备已退役", "频道", channel, "设备", device.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, retireResponse{Retired: device.Fingerprint.String()})
}

// channelByName 找出以该名称作为别名的频道，没有则建立。
//
// 调用方已保证名称非空。别名相同即视为同一个仓库；两台设备同时以同一名称注册时
// 有可能各建一个频道，但注册本是罕见动作，这里不为它引入额外的协调。
func (s *Server) channelByName(alias string) (store.Channel, error) {
	channels, err := s.store.Channels()
	if err != nil {
		return store.Channel{}, err
	}
	for _, channel := range channels {
		if channel.Alias == alias {
			return channel, nil
		}
	}

	id, err := s.newID()
	if err != nil {
		return store.Channel{}, err
	}
	channel := store.Channel{ID: id, Alias: alias, CreatedAt: s.now().UTC()}
	if err := s.store.CreateChannel(channel); err != nil {
		return store.Channel{}, err
	}
	return channel, nil
}
