// Package store 把频道、设备、状态记录与吊销名单落到本地存储。
//
// 本包只管存取，不判定业务规则。例如「不允许吊销最后一台设备」需要跨记录判断，
// 放在这里会让存取层承担不属于它的语义，因此由调用方检查。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"vaultwaystation/internal/identity"
)

// SchemaVersion 是当前的存储结构版本。
const SchemaVersion = 1

// fingerprintChars 是公钥指纹文本的长度，即 SHA-256 的十六进制表示。
const fingerprintChars = 64

var (
	// ErrChannelNotFound 表示频道不存在。
	ErrChannelNotFound = errors.New("频道不存在")
	// ErrChannelExists 表示频道标识已被占用。
	ErrChannelExists = errors.New("频道已存在")
	// ErrDeviceNotFound 表示设备不在该频道内。
	ErrDeviceNotFound = errors.New("设备不存在")
	// ErrDeviceExists 表示设备已在该频道注册。
	ErrDeviceExists = errors.New("设备已注册")
	// ErrRecordNotFound 表示该设备尚未上报状态记录。
	ErrRecordNotFound = errors.New("记录不存在")
	// ErrNotRevoked 表示该设备不在吊销名单中。
	ErrNotRevoked = errors.New("该设备未被吊销")
)

const (
	metaBucket    = "meta"
	channelBucket = "channels"
	deviceBucket  = "devices"
	recordBucket  = "records"
	revokedBucket = "revoked"
	schemaKey     = "schema"
)

// ChannelID 是频道的不可变标识。
//
// 频道标识不得包含零字节，因为它被用作组合键的分隔符；标识由服务端生成，
// 一律为十六进制串，天然满足该约束。
type ChannelID string

// Channel 是一个频道，对应某台设备上的一个笔记仓库。
type Channel struct {
	ID        ChannelID
	Alias     string
	CreatedAt time.Time
}

// Device 是一台已注册设备。
type Device struct {
	Fingerprint  identity.Fingerprint
	PublicKey    []byte
	RegisteredAt time.Time
}

// Record 是一台设备上报的状态记录。
type Record struct {
	Fingerprint identity.Fingerprint
	Sequence    int64
	CollectedAt time.Time
	// Payload 是端到端加密后的内容，服务端只负责搬运，不作解析。
	Payload   []byte
	Signature []byte
}

// Revocation 是一次吊销。
type Revocation struct {
	Fingerprint identity.Fingerprint
	By          identity.Fingerprint
	At          time.Time
}

// Store 是本地存储，可供多个协程并发使用，写操作由底层存储串行化。
type Store struct {
	db *bolt.DB
}

// Open 打开存储文件，文件不存在时创建。
func Open(path string) (*Store, error) {
	// 数据目录可能尚未建好：让程序自己备好它，比要求运维先手工创建更可靠。
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("建立数据目录 %s：%w", dir, err)
		}
	}

	// 文件已被占用时等待一秒即放弃：宁可启动失败，也不要长时间挂住不动。
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("打开存储 %s：%w", path, err)
	}

	if err := db.Update(prepare); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化存储 %s：%w", path, err)
	}
	return &Store{db: db}, nil
}

// Close 关闭存储。
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("关闭存储：%w", err)
	}
	return nil
}

// CreateChannel 建立频道；标识已被占用时返回 ErrChannelExists。
func (s *Store) CreateChannel(channel Channel) error {
	return s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(channelBucket))
		key := []byte(channel.ID)
		if bucket.Get(key) != nil {
			return ErrChannelExists
		}
		return putJSON(bucket, key, channel)
	})
}

// Channel 读取一个频道。
func (s *Store) Channel(id ChannelID) (Channel, error) {
	var channel Channel
	var found bool

	err := s.read(func(tx *bolt.Tx) error {
		var err error
		channel, found, err = readJSON[Channel](tx.Bucket([]byte(channelBucket)), []byte(id))
		return err
	})
	if err != nil {
		return Channel{}, err
	}
	if !found {
		return Channel{}, ErrChannelNotFound
	}
	return channel, nil
}

// Channels 列出全部频道，按标识排序。
func (s *Store) Channels() ([]Channel, error) {
	var channels []Channel

	err := s.read(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(channelBucket)).ForEach(func(_, raw []byte) error {
			var channel Channel
			if err := json.Unmarshal(raw, &channel); err != nil {
				return fmt.Errorf("解析频道：%w", err)
			}
			channels = append(channels, channel)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(channels, func(i, j int) bool { return channels[i].ID < channels[j].ID })
	return channels, nil
}

// AddDevice 把设备加入频道；频道不存在或设备已注册时返回对应的错误。
func (s *Store) AddDevice(channel ChannelID, device Device) error {
	return s.write(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte(channelBucket)).Get([]byte(channel)) == nil {
			return ErrChannelNotFound
		}

		bucket := tx.Bucket([]byte(deviceBucket))
		key := scopedKey(channel, device.Fingerprint)
		if bucket.Get(key) != nil {
			return ErrDeviceExists
		}
		return putJSON(bucket, key, device)
	})
}

// Device 读取频道内的设备。
func (s *Store) Device(channel ChannelID, fingerprint identity.Fingerprint) (Device, error) {
	var device Device
	var found bool

	err := s.read(func(tx *bolt.Tx) error {
		var err error
		device, found, err = readJSON[Device](tx.Bucket([]byte(deviceBucket)), scopedKey(channel, fingerprint))
		return err
	})
	if err != nil {
		return Device{}, err
	}
	if !found {
		return Device{}, ErrDeviceNotFound
	}
	return device, nil
}

// Devices 列出频道内的设备，按指纹排序。
func (s *Store) Devices(channel ChannelID) ([]Device, error) {
	devices, err := collect[Device](s, deviceBucket, channel)
	if err != nil {
		return nil, err
	}

	sort.Slice(devices, func(i, j int) bool { return devices[i].Fingerprint < devices[j].Fingerprint })
	return devices, nil
}

// CountDevices 统计频道内的设备数。
func (s *Store) CountDevices(channel ChannelID) (int, error) {
	devices, err := s.Devices(channel)
	if err != nil {
		return 0, err
	}
	return len(devices), nil
}

// RemoveDevice 把设备移出频道。
func (s *Store) RemoveDevice(channel ChannelID, fingerprint identity.Fingerprint) error {
	return s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(deviceBucket))
		key := scopedKey(channel, fingerprint)
		if bucket.Get(key) == nil {
			return ErrDeviceNotFound
		}
		return bucket.Delete(key)
	})
}

// PutRecord 保存状态记录，仅在序号更新时覆盖既有记录。
//
// 返回假表示既有记录的序号不小于本次上报，此时调用方应当把既有记录回给设备：
// 服务端只按序号取新，不判断内容。序号相同而内容不同属于异常，交由客户端提示。
func (s *Store) PutRecord(channel ChannelID, record Record) (bool, error) {
	written := false

	err := s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(recordBucket))
		key := scopedKey(channel, record.Fingerprint)

		existing, found, err := readJSON[Record](bucket, key)
		if err != nil {
			return err
		}
		if found && existing.Sequence >= record.Sequence {
			return nil
		}

		written = true
		return putJSON(bucket, key, record)
	})
	return written, err
}

// Record 读取一台设备的状态记录。
func (s *Store) Record(channel ChannelID, fingerprint identity.Fingerprint) (Record, error) {
	var record Record
	var found bool

	err := s.read(func(tx *bolt.Tx) error {
		var err error
		record, found, err = readJSON[Record](tx.Bucket([]byte(recordBucket)), scopedKey(channel, fingerprint))
		return err
	})
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, ErrRecordNotFound
	}
	return record, nil
}

// Records 列出频道内的全部状态记录，按设备指纹排序。
func (s *Store) Records(channel ChannelID) ([]Record, error) {
	records, err := collect[Record](s, recordBucket, channel)
	if err != nil {
		return nil, err
	}

	sort.Slice(records, func(i, j int) bool { return records[i].Fingerprint < records[j].Fingerprint })
	return records, nil
}

// DeleteRecord 删除一台设备的状态记录。
func (s *Store) DeleteRecord(channel ChannelID, fingerprint identity.Fingerprint) error {
	return s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(recordBucket))
		key := scopedKey(channel, fingerprint)
		if bucket.Get(key) == nil {
			return ErrRecordNotFound
		}
		return bucket.Delete(key)
	})
}

// Revoke 把设备记入吊销名单。
//
// 重复吊销不改变既有条目：吊销是单向的，最早那一次纪录即为事实。
func (s *Store) Revoke(channel ChannelID, revocation Revocation) error {
	return s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(revokedBucket))
		key := scopedKey(channel, revocation.Fingerprint)
		if bucket.Get(key) != nil {
			return nil
		}
		return putJSON(bucket, key, revocation)
	})
}

// Revocation 读取一条吊销纪录；该设备未被吊销时返回 ErrNotRevoked。
func (s *Store) Revocation(channel ChannelID, fingerprint identity.Fingerprint) (Revocation, error) {
	var revocation Revocation
	var found bool

	err := s.read(func(tx *bolt.Tx) error {
		var err error
		revocation, found, err = readJSON[Revocation](tx.Bucket([]byte(revokedBucket)), scopedKey(channel, fingerprint))
		return err
	})
	if err != nil {
		return Revocation{}, err
	}
	if !found {
		return Revocation{}, ErrNotRevoked
	}
	return revocation, nil
}

// Revocations 列出频道内的吊销名单，按设备指纹排序。
func (s *Store) Revocations(channel ChannelID) ([]Revocation, error) {
	revocations, err := collect[Revocation](s, revokedBucket, channel)
	if err != nil {
		return nil, err
	}

	sort.Slice(revocations, func(i, j int) bool { return revocations[i].Fingerprint < revocations[j].Fingerprint })
	return revocations, nil
}

// Forgive 把设备移出吊销名单，供极端情形下的恢复使用；未被吊销时返回 ErrNotRevoked。
func (s *Store) Forgive(channel ChannelID, fingerprint identity.Fingerprint) error {
	return s.write(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(revokedBucket))
		key := scopedKey(channel, fingerprint)
		if bucket.Get(key) == nil {
			return ErrNotRevoked
		}
		return bucket.Delete(key)
	})
}

func prepare(tx *bolt.Tx) error {
	for _, name := range []string{metaBucket, channelBucket, deviceBucket, recordBucket, revokedBucket} {
		if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
			return err
		}
	}

	meta := tx.Bucket([]byte(metaBucket))
	stored := meta.Get([]byte(schemaKey))
	if stored == nil {
		return meta.Put([]byte(schemaKey), []byte(strconv.Itoa(SchemaVersion)))
	}

	version, err := strconv.Atoi(string(stored))
	if err != nil {
		return fmt.Errorf("读取存储版本：%w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("存储版本为 %d，本程序支持 %d，请先迁移数据", version, SchemaVersion)
	}
	return nil
}

func (s *Store) write(fn func(*bolt.Tx) error) error {
	return s.db.Update(fn)
}

func (s *Store) read(fn func(*bolt.Tx) error) error {
	return s.db.View(fn)
}

// collect 读取某个桶中属于指定频道的全部取值。
func collect[T any](s *Store, bucketName string, channel ChannelID) ([]T, error) {
	var values []T

	err := s.read(func(tx *bolt.Tx) error {
		prefix := scopedPrefix(channel)
		return tx.Bucket([]byte(bucketName)).ForEach(func(key, raw []byte) error {
			if !bytes.HasPrefix(key, prefix) {
				return nil
			}

			var value T
			if err := json.Unmarshal(raw, &value); err != nil {
				return fmt.Errorf("解析 %s：%w", bucketName, err)
			}
			values = append(values, value)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

func putJSON(bucket *bolt.Bucket, key []byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("编码数据：%w", err)
	}
	if err := bucket.Put(key, data); err != nil {
		return fmt.Errorf("写入数据：%w", err)
	}
	return nil
}

// readJSON 读取并解析一条记录；第二个返回值为假表示键不存在。
func readJSON[T any](bucket *bolt.Bucket, key []byte) (T, bool, error) {
	var value T

	data := bucket.Get(key)
	if data == nil {
		return value, false, nil
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, false, fmt.Errorf("解析数据：%w", err)
	}
	return value, true, nil
}

func scopedKey(channel ChannelID, fingerprint identity.Fingerprint) []byte {
	return append(scopedPrefix(channel), fingerprint...)
}

// scopedPrefix 返回频道的组合键前缀，即频道标识加上用作分隔的零字节。
// 返回值的容量按指纹长度留有余量，调用方可以继续追加而不必再次复制。
func scopedPrefix(channel ChannelID) []byte {
	prefix := make([]byte, 0, len(channel)+1+fingerprintChars)
	prefix = append(prefix, channel...)
	return append(prefix, 0)
}
