package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
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
type registerRequest struct {
	// Channel 是设备所报的仓库名称，服务端据此加入或建立频道。
	Channel    string `json:"channel"`
	Credential string `json:"credential"`
	Label      string `json:"label"`
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
type recordDTO struct {
	Fingerprint string `json:"fingerprint"`
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

// reportResponse 是上报的回复：是否被接受，以及频道内其他设备的状态与吊销名单。
type reportResponse struct {
	Accepted    bool            `json:"accepted"`
	Records     []recordDTO     `json:"records"`
	Revocations []revocationDTO `json:"revocations"`
}

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
	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w) {
		return
	}

	request, ok := s.readSignedRequest(w, r)
	if !ok {
		return
	}

	var payload registerRequest
	if !s.decode(w, request.Body, &payload) {
		return
	}

	if !s.cfg.Registration.Enabled {
		s.writeError(w, http.StatusForbidden, codeForbidden, "服务端当前未开放注册")
		return
	}
	if config.DigestCredential(payload.Credential) != s.cfg.Registration.CredentialDigest {
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

	channel, err := s.channelByName(payload.Channel)
	if err != nil {
		s.internal(w, err)
		return
	}

	if _, err := s.store.Revocation(channel.ID, request.Fingerprint); err == nil {
		s.writeError(w, http.StatusUnauthorized, codeUnauthorized, "该设备已被吊销，不能再次注册")
		return
	} else if !errors.Is(err, store.ErrNotRevoked) {
		s.internal(w, err)
		return
	}

	if _, err := s.store.Device(channel.ID, request.Fingerprint); err == nil {
		// 重复注册视为幂等：设备已经在频道里，直接回以频道信息。
		s.writeJSON(w, http.StatusOK, channelResponse{ChannelID: string(channel.ID), ChannelAlias: channel.Alias})
		return
	} else if !errors.Is(err, store.ErrDeviceNotFound) {
		s.internal(w, err)
		return
	}

	count, err := s.store.CountDevices(channel.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if count >= s.cfg.Limits.DevicesPerChannel {
		s.writeError(w, http.StatusConflict, codeLimit, "频道内设备数已达上限")
		return
	}

	device := store.Device{
		Fingerprint:  request.Fingerprint,
		PublicKey:    publicKey,
		Label:        payload.Label,
		RegisteredAt: s.now().UTC(),
	}
	if err := s.store.AddDevice(channel.ID, device); err != nil {
		s.internal(w, err)
		return
	}

	s.logger.Info("设备已注册", "频道", channel.ID, "设备", request.Fingerprint.String())
	s.writeJSON(w, http.StatusOK, channelResponse{ChannelID: string(channel.ID), ChannelAlias: channel.Alias})
}

// handleReport 处理状态上报，并把频道内其他设备的状态一并回送。
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if !s.allowAddress(w, r) {
		return
	}

	request, ok := s.readSignedRequest(w, r)
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
	if len(recordPayload) > s.cfg.Limits.RecordBytes {
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

	response := reportResponse{
		Accepted:    accepted,
		Records:     make([]recordDTO, 0, len(records)),
		Revocations: make([]revocationDTO, 0, len(revocations)),
	}
	for _, item := range records {
		// 不回送调用者自己的记录：它比谁都清楚自己刚才上报了什么。
		if item.Fingerprint == device.Fingerprint {
			continue
		}
		response.Records = append(response.Records, recordDTO{
			Fingerprint: item.Fingerprint.String(),
			Sequence:    item.Sequence,
			CollectedAt: item.CollectedAt.UTC().Format(time.RFC3339),
			Payload:     base64.StdEncoding.EncodeToString(item.Payload),
			Signature:   base64.StdEncoding.EncodeToString(item.Signature),
		})
	}
	for _, item := range revocations {
		response.Revocations = append(response.Revocations, revocationDTO{
			Fingerprint: item.Fingerprint.String(),
			By:          item.By.String(),
			At:          item.At.UTC().Format(time.RFC3339),
		})
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleRevoke 处理吊销请求。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w) {
		return
	}

	request, ok := s.readSignedRequest(w, r)
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
	if !s.allowAddress(w, r) {
		return
	}
	if !s.allowDestructive(w) {
		return
	}

	request, ok := s.readSignedRequest(w, r)
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
// 别名相同即视为同一个仓库；两台设备同时以同一名称注册时有可能各建一个频道，
// 但注册本是罕见动作，这里不为它引入额外的协调。
func (s *Server) channelByName(alias string) (store.Channel, error) {
	if alias == "" {
		return store.Channel{}, errors.New("缺少仓库名称")
	}

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
