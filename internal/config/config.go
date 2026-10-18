// Package config 负责读取、校验与写回服务端配置。
//
// 配置以文件为唯一事实来源，因此校验规则集中于此：
// 其他部分只能使用本包返回且已通过校验的配置，不得自行补默认值或放宽限制。
package config

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// CurrentVersion 是当前支持的配置格式版本。
const CurrentVersion = 1

// 传输等级，与协议中的四级传输一一对应。
const (
	ModeHTTPS     = "https"
	ModePinned    = "pinned"
	ModeInsecure  = "insecure"
	ModePlaintext = "plaintext"
)

// 各项上限。设上限是为了让一份写错的配置不至于把服务端拖垮。
const (
	maxDevicesPerChannel = 1024
	maxRecordsPerDevice  = 64
	maxRecordsPerRequest = 4096
	maxRecordBytes       = 4 << 20
	maxRequestsPerMinute = 6000
)

// 默认值：配置项留空或填零时取以下取值。
const (
	defaultListen            = "127.0.0.1:8787"
	defaultDataDir           = "./data"
	defaultDevicesPerChannel = 16
	defaultRecordsPerDevice  = 8
	defaultRecordsPerRequest = 512
	defaultRecordBytes       = 64 << 10
	defaultRequestsPerMinute = 240
	defaultLogLevel          = "info"
)

//go:embed example.toml
var example string

// Config 是一份完整的服务端配置。
type Config struct {
	Version      int          `toml:"version"`
	Server       Server       `toml:"server"`
	Registration Registration `toml:"registration"`
	Transport    Transport    `toml:"transport"`
	Limits       Limits       `toml:"limits"`
	Log          Log          `toml:"log"`
}

// Server 描述监听与数据存放位置。
type Server struct {
	// Listen 为「主机:端口」形式，主机不得省略，以免误绑全部网卡。
	Listen string `toml:"listen"`
	// DataDir 为数据目录，相对路径按配置文件所在目录解析。
	DataDir string `toml:"data_dir"`
}

// Registration 描述设备注册的开关与凭证摘要。
type Registration struct {
	// Enabled 控制是否接受注册请求。设备注册完毕后应当关闭。
	Enabled bool `toml:"enabled"`
	// CredentialDigest 为注册凭证的摘要，服务端不保存凭证原文。
	CredentialDigest string `toml:"credential_digest"`
}

// Transport 描述传输级别与证书位置。
type Transport struct {
	// Mode 取 ModeHTTPS、ModePinned、ModeInsecure、ModePlaintext 之一。
	Mode     string `toml:"mode"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

// Degraded 报告当前传输级别是否属于降级。
//
// 降级时不得执行注册与退役等破坏性操作；该约束由调用方检查，本方法只如实报告。
func (t Transport) Degraded() bool {
	return t.Mode == ModeInsecure || t.Mode == ModePlaintext
}

// Limits 是限流与容量上限。
type Limits struct {
	DevicesPerChannel int `toml:"devices_per_channel"`
	RecordsPerDevice  int `toml:"records_per_device"`
	RecordsPerRequest int `toml:"records_per_request"`
	RecordBytes       int `toml:"record_bytes"`
	RequestsPerMinute int `toml:"requests_per_minute"`
}

// Log 描述日志输出。
type Log struct {
	// Level 取 debug、info、warn、error 之一。
	Level string `toml:"level"`
}

// Load 读取并校验配置文件。
//
// 相对路径按配置文件所在目录解析，使服务端行为不随启动目录变化。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s：%w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("配置 %s 有误：%w", path, err)
	}

	base := filepath.Dir(path)
	cfg.Server.DataDir = resolve(base, cfg.Server.DataDir)
	cfg.Transport.CertFile = resolve(base, cfg.Transport.CertFile)
	cfg.Transport.KeyFile = resolve(base, cfg.Transport.KeyFile)
	return cfg, nil
}

// Parse 解析、补默认值并校验一份配置内容。
//
// 无法识别的配置项一律报错，避免写错键名却被默默忽略。
func Parse(data []byte) (*Config, error) {
	var cfg Config

	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return nil, fmt.Errorf("存在无法识别的配置项：%s", strings.Join(keys, "、"))
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate 校验配置，并把发现的问题一并返回，便于一次改完。
func (c *Config) Validate() error {
	var problems []error

	if c.Version != CurrentVersion {
		problems = append(problems, fmt.Errorf("version 应为 %d，实际为 %d", CurrentVersion, c.Version))
	}
	if err := validateListen(c.Server.Listen); err != nil {
		problems = append(problems, err)
	}
	if c.Server.DataDir == "" {
		problems = append(problems, errors.New("server.data_dir 不得为空"))
	}
	problems = append(problems, c.validateRegistration()...)
	problems = append(problems, c.validateTransport()...)
	problems = append(problems, c.validateLimits()...)
	problems = append(problems, validateLogLevel(c.Log.Level)...)

	return errors.Join(problems...)
}

// Marshal 输出可被 Parse 接受的配置文本。
func (c *Config) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return nil, fmt.Errorf("序列化配置：%w", err)
	}
	return buf.Bytes(), nil
}

// Template 返回一份可直接使用的配置样例，其中注册默认关闭。
func Template() string {
	return example
}

// WithCredential 在配置样例的基础上开启注册，并写入凭证摘要。
//
// 这里直接改写样例文本，为的是保留样例里的注释：样例是给人读的，注释比字段本身更值得留下。
// 若样例措辞有变导致改写落空，这里会明确报错，而不是给出一份注册仍然关闭的配置。
func WithCredential(credential string) (string, error) {
	if credential == "" {
		return "", errors.New("注册凭证不得为空")
	}

	const (
		registrationOff = "enabled = false"
		emptyDigest     = `credential_digest = ""`
	)
	if !strings.Contains(example, registrationOff) || !strings.Contains(example, emptyDigest) {
		return "", errors.New("配置样例已改，无法写入注册凭证")
	}

	text := strings.Replace(example, registrationOff, "enabled = true", 1)
	text = strings.Replace(text, emptyDigest, `credential_digest = "`+DigestCredential(credential)+`"`, 1)

	cfg, err := Parse([]byte(text))
	if err != nil {
		return "", fmt.Errorf("生成的配置未通过校验：%w", err)
	}
	if !cfg.Registration.Enabled {
		return "", errors.New("生成的配置未开启注册")
	}
	return text, nil
}

// StorePath 返回存储文件的位置。存储与配置文件分开放置，二者各有各的备份节奏。
func (c *Config) StorePath() string {
	return filepath.Join(c.Server.DataDir, "store.db")
}

// KeyPath 返回服务端密钥文件的位置。
//
// 密钥一经生成不再更换：客户端在首次配对时钉住这把公钥，换了就等于换了服务端。
func (c *Config) KeyPath() string {
	return filepath.Join(c.Server.DataDir, "server.key")
}

// ReloadRequestPath 返回重载请求文件的位置。
//
// 重载靠文件握手，不用信号，也不额外开放管理入口：各平台行为一致，
// 而能写数据目录的人本来就已掌握这台机器。
func (c *Config) ReloadRequestPath() string {
	return filepath.Join(c.Server.DataDir, "reload.request")
}

// DigestCredential 返回注册凭证的摘要。
//
// 服务端只保存摘要而不保存原文，因此这里必须使用单向散列。
func DigestCredential(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = defaultListen
	}
	if c.Server.DataDir == "" {
		c.Server.DataDir = defaultDataDir
	}
	if c.Transport.Mode == "" {
		c.Transport.Mode = ModeHTTPS
	}
	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}

	limits := &c.Limits
	if limits.DevicesPerChannel == 0 {
		limits.DevicesPerChannel = defaultDevicesPerChannel
	}
	if limits.RecordsPerDevice == 0 {
		limits.RecordsPerDevice = defaultRecordsPerDevice
	}
	if limits.RecordsPerRequest == 0 {
		limits.RecordsPerRequest = defaultRecordsPerRequest
	}
	if limits.RecordBytes == 0 {
		limits.RecordBytes = defaultRecordBytes
	}
	if limits.RequestsPerMinute == 0 {
		limits.RequestsPerMinute = defaultRequestsPerMinute
	}
}

func (c *Config) validateRegistration() []error {
	if c.Registration.Enabled && !isHexDigest(c.Registration.CredentialDigest) {
		return []error{errors.New("registration.credential_digest 应为六十四位小写十六进制的凭证摘要")}
	}
	if !c.Registration.Enabled && c.Registration.CredentialDigest != "" {
		return []error{errors.New("registration.enabled 为 false 时不应填写 registration.credential_digest")}
	}
	return nil
}

func (c *Config) validateTransport() []error {
	var problems []error

	switch c.Transport.Mode {
	case ModeHTTPS, ModePinned:
		if c.Transport.CertFile == "" {
			problems = append(problems, errors.New("启用传输加密时必须填写 transport.cert_file"))
		}
		if c.Transport.KeyFile == "" {
			problems = append(problems, errors.New("启用传输加密时必须填写 transport.key_file"))
		}
	case ModeInsecure, ModePlaintext:
		if c.Transport.CertFile != "" || c.Transport.KeyFile != "" {
			problems = append(problems, fmt.Errorf("transport.mode 为 %s 时不应配置证书", c.Transport.Mode))
		}
	default:
		problems = append(problems, fmt.Errorf(
			"transport.mode 取值无效：%q，可选值为 %s、%s、%s、%s",
			c.Transport.Mode, ModeHTTPS, ModePinned, ModeInsecure, ModePlaintext))
	}
	return problems
}

func (c *Config) validateLimits() []error {
	rules := []struct {
		name  string
		value int
		max   int
	}{
		{"limits.devices_per_channel", c.Limits.DevicesPerChannel, maxDevicesPerChannel},
		{"limits.records_per_device", c.Limits.RecordsPerDevice, maxRecordsPerDevice},
		{"limits.records_per_request", c.Limits.RecordsPerRequest, maxRecordsPerRequest},
		{"limits.record_bytes", c.Limits.RecordBytes, maxRecordBytes},
		{"limits.requests_per_minute", c.Limits.RequestsPerMinute, maxRequestsPerMinute},
	}

	var problems []error
	for _, rule := range rules {
		switch {
		case rule.value <= 0:
			problems = append(problems, fmt.Errorf("%s 必须为正数，实际为 %d", rule.name, rule.value))
		case rule.value > rule.max:
			problems = append(problems, fmt.Errorf("%s 超过上限 %d，实际为 %d", rule.name, rule.max, rule.value))
		}
	}
	return problems
}

func validateListen(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("server.listen 应为「主机:端口」形式：%q", value)
	}
	if host == "" {
		return fmt.Errorf("server.listen 未指明主机：%q", value)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("server.listen 的端口无效：%q", value)
	}
	return nil
}

func validateLogLevel(level string) []error {
	switch level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return []error{fmt.Errorf("log.level 取值无效：%q，可选值为 debug、info、warn、error", level)}
	}
}

func isHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func resolve(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
