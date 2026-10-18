package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"vaultwaystation/internal/identity"
)

const (
	channelA = ChannelID("channel-a")
	channelB = ChannelID("channel-b")

	deviceA = identity.Fingerprint("device-a")
	deviceB = identity.Fingerprint("device-b")
)

func newStore(t *testing.T) *Store {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "waystation.db"))
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("关闭存储失败：%v", err)
		}
	})
	return store
}

func createChannel(t *testing.T, store *Store, id ChannelID) {
	t.Helper()

	channel := Channel{ID: id, Alias: "vault-example", CreatedAt: time.Unix(1700000000, 0)}
	if err := store.CreateChannel(channel); err != nil {
		t.Fatalf("建立频道 %s 失败：%v", id, err)
	}
}

func sampleDevice(fingerprint identity.Fingerprint) Device {
	return Device{
		Fingerprint:  fingerprint,
		PublicKey:    []byte("public-key"),
		Label:        "device-a",
		RegisteredAt: time.Unix(1700000000, 0),
	}
}

func sampleRecord(fingerprint identity.Fingerprint, sequence int64) Record {
	return Record{
		Fingerprint: fingerprint,
		Sequence:    sequence,
		CollectedAt: time.Unix(1700000000, 0),
		Payload:     []byte("ciphertext"),
		Signature:   []byte("signature"),
	}
}

func TestCreateAndReadChannel(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	channel, err := store.Channel(channelA)
	if err != nil {
		t.Fatalf("读取频道失败：%v", err)
	}
	if channel.ID != channelA || channel.Alias != "vault-example" {
		t.Fatalf("读回的频道不符：%+v", channel)
	}
}

func TestCreateChannelRejectsDuplicate(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	err := store.CreateChannel(Channel{ID: channelA, Alias: "另一个名字"})

	if !errors.Is(err, ErrChannelExists) {
		t.Fatalf("重复建立频道的错误为 %v，期望 %v", err, ErrChannelExists)
	}
}

func TestChannelNotFound(t *testing.T) {
	store := newStore(t)

	_, err := store.Channel(channelA)

	if !errors.Is(err, ErrChannelNotFound) {
		t.Fatalf("读取不存在频道的错误为 %v，期望 %v", err, ErrChannelNotFound)
	}
}

func TestChannelsAreSorted(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelB)
	createChannel(t, store, channelA)

	channels, err := store.Channels()
	if err != nil {
		t.Fatalf("列出频道失败：%v", err)
	}
	if len(channels) != 2 || channels[0].ID != channelA || channels[1].ID != channelB {
		t.Fatalf("频道列表未按标识排序：%+v", channels)
	}
}

func TestAddDeviceRequiresChannel(t *testing.T) {
	store := newStore(t)

	err := store.AddDevice(channelA, sampleDevice(deviceA))

	if !errors.Is(err, ErrChannelNotFound) {
		t.Fatalf("向不存在频道添加设备的错误为 %v，期望 %v", err, ErrChannelNotFound)
	}
}

func TestAddDeviceRejectsDuplicate(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if err := store.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}

	err := store.AddDevice(channelA, sampleDevice(deviceA))

	if !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("重复注册的错误为 %v，期望 %v", err, ErrDeviceExists)
	}
}

func TestDeviceRoundTrip(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if err := store.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}

	device, err := store.Device(channelA, deviceA)
	if err != nil {
		t.Fatalf("读取设备失败：%v", err)
	}
	if device.Fingerprint != deviceA || string(device.PublicKey) != "public-key" {
		t.Fatalf("读回的设备不符：%+v", device)
	}
}

func TestDeviceNotFound(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	_, err := store.Device(channelA, deviceA)

	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("读取不存在设备的错误为 %v，期望 %v", err, ErrDeviceNotFound)
	}
}

func TestDevicesAreSortedAndCounted(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if err := store.AddDevice(channelA, sampleDevice(deviceB)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}
	if err := store.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}

	devices, err := store.Devices(channelA)
	if err != nil {
		t.Fatalf("列出设备失败：%v", err)
	}
	if len(devices) != 2 || devices[0].Fingerprint != deviceA {
		t.Fatalf("设备列表未按指纹排序：%+v", devices)
	}

	count, err := store.CountDevices(channelA)
	if err != nil {
		t.Fatalf("统计设备失败：%v", err)
	}
	if count != 2 {
		t.Fatalf("设备数为 %d，期望 2", count)
	}
}

func TestDevicesAreScopedToChannel(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	createChannel(t, store, channelB)
	if err := store.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}

	devices, err := store.Devices(channelB)
	if err != nil {
		t.Fatalf("列出设备失败：%v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("另一频道不应看到设备：%+v", devices)
	}
}

func TestRemoveDevice(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if err := store.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}

	if err := store.RemoveDevice(channelA, deviceA); err != nil {
		t.Fatalf("移除设备失败：%v", err)
	}
	if _, err := store.Device(channelA, deviceA); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("移除后的读取错误为 %v，期望 %v", err, ErrDeviceNotFound)
	}
}

func TestRemoveDeviceNotFound(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	err := store.RemoveDevice(channelA, deviceA)

	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("移除不存在设备的错误为 %v，期望 %v", err, ErrDeviceNotFound)
	}
}

func TestPutRecordKeepsNewest(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	written, err := store.PutRecord(channelA, sampleRecord(deviceA, 2))
	if err != nil || !written {
		t.Fatalf("首次写入的结果为 %t 与 %v，期望写入成功", written, err)
	}

	written, err = store.PutRecord(channelA, sampleRecord(deviceA, 3))
	if err != nil || !written {
		t.Fatalf("更新序号的结果为 %t 与 %v，期望写入成功", written, err)
	}

	for _, sequence := range []int64{3, 1} {
		written, err = store.PutRecord(channelA, sampleRecord(deviceA, sequence))
		if err != nil {
			t.Fatalf("写入序号 %d 失败：%v", sequence, err)
		}
		if written {
			t.Errorf("序号 %d 不新于既有记录，不应写入", sequence)
		}
	}

	record, err := store.Record(channelA, deviceA)
	if err != nil {
		t.Fatalf("读取记录失败：%v", err)
	}
	if record.Sequence != 3 {
		t.Fatalf("记录序号为 %d，期望 3", record.Sequence)
	}
}

func TestRecordNotFound(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	_, err := store.Record(channelA, deviceA)

	if !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("读取不存在记录的错误为 %v，期望 %v", err, ErrRecordNotFound)
	}
}

func TestRecordsAreScopedToChannel(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	createChannel(t, store, channelB)
	if _, err := store.PutRecord(channelA, sampleRecord(deviceA, 1)); err != nil {
		t.Fatalf("写入记录失败：%v", err)
	}

	records, err := store.Records(channelB)
	if err != nil {
		t.Fatalf("列出记录失败：%v", err)
	}
	if len(records) != 0 {
		t.Fatalf("另一频道不应看到记录：%+v", records)
	}

	records, err = store.Records(channelA)
	if err != nil {
		t.Fatalf("列出记录失败：%v", err)
	}
	if len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("频道内的记录不符：%+v", records)
	}
}

func TestDeleteRecord(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if _, err := store.PutRecord(channelA, sampleRecord(deviceA, 1)); err != nil {
		t.Fatalf("写入记录失败：%v", err)
	}

	if err := store.DeleteRecord(channelA, deviceA); err != nil {
		t.Fatalf("删除记录失败：%v", err)
	}
	if _, err := store.Record(channelA, deviceA); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("删除后的读取错误为 %v，期望 %v", err, ErrRecordNotFound)
	}
}

func TestDeleteRecordNotFound(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	err := store.DeleteRecord(channelA, deviceA)

	if !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("删除不存在记录的错误为 %v，期望 %v", err, ErrRecordNotFound)
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	first := Revocation{Fingerprint: deviceA, By: deviceB, At: time.Unix(1700000000, 0)}
	later := Revocation{Fingerprint: deviceA, By: deviceB, At: time.Unix(1700000600, 0)}

	if err := store.Revoke(channelA, first); err != nil {
		t.Fatalf("吊销失败：%v", err)
	}
	if err := store.Revoke(channelA, later); err != nil {
		t.Fatalf("重复吊销失败：%v", err)
	}

	revocation, err := store.Revocation(channelA, deviceA)
	if err != nil {
		t.Fatalf("读取吊销纪录失败：%v", err)
	}
	if !revocation.At.Equal(first.At) {
		t.Fatalf("重复吊销改写了既有纪录：%+v", revocation)
	}
}

func TestRevocationNotFound(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	_, err := store.Revocation(channelA, deviceA)

	if !errors.Is(err, ErrNotRevoked) {
		t.Fatalf("读取未吊销设备的错误为 %v，期望 %v", err, ErrNotRevoked)
	}
}

func TestRevocationsAreListedAndForgiven(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)
	if err := store.Revoke(channelA, Revocation{Fingerprint: deviceA, By: deviceB, At: time.Unix(1700000000, 0)}); err != nil {
		t.Fatalf("吊销失败：%v", err)
	}

	revocations, err := store.Revocations(channelA)
	if err != nil {
		t.Fatalf("列出吊销名单失败：%v", err)
	}
	if len(revocations) != 1 || revocations[0].Fingerprint != deviceA {
		t.Fatalf("吊销名单不符：%+v", revocations)
	}

	if err := store.Forgive(channelA, deviceA); err != nil {
		t.Fatalf("移除吊销纪录失败：%v", err)
	}
	if _, err := store.Revocation(channelA, deviceA); !errors.Is(err, ErrNotRevoked) {
		t.Fatalf("移除后的读取错误为 %v，期望 %v", err, ErrNotRevoked)
	}
}

func TestForgiveRequiresRevocation(t *testing.T) {
	store := newStore(t)
	createChannel(t, store, channelA)

	err := store.Forgive(channelA, deviceA)

	if !errors.Is(err, ErrNotRevoked) {
		t.Fatalf("移除未吊销设备的错误为 %v，期望 %v", err, ErrNotRevoked)
	}
}

func TestDataSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	createChannel(t, first, channelA)
	if err := first.AddDevice(channelA, sampleDevice(deviceA)); err != nil {
		t.Fatalf("添加设备失败：%v", err)
	}
	if _, err := first.PutRecord(channelA, sampleRecord(deviceA, 7)); err != nil {
		t.Fatalf("写入记录失败：%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭存储失败：%v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开存储失败：%v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	record, err := second.Record(channelA, deviceA)
	if err != nil {
		t.Fatalf("读取记录失败：%v", err)
	}
	if record.Sequence != 7 {
		t.Fatalf("重新打开后记录序号为 %d，期望 7", record.Sequence)
	}
}

// TestOperationsFailAfterClose 覆盖各方法在存储不可用时的报错分支，
// 这些分支只有在存储关闭或损坏时才会走到。
func TestOperationsFailAfterClose(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "waystation.db"))
	if err != nil {
		t.Fatalf("打开存储失败：%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭存储失败：%v", err)
	}

	calls := map[string]func() error{
		"建立频道": func() error { return store.CreateChannel(Channel{ID: channelA}) },
		"读取频道": func() error { _, err := store.Channel(channelA); return err },
		"列出频道": func() error { _, err := store.Channels(); return err },
		"添加设备": func() error { return store.AddDevice(channelA, sampleDevice(deviceA)) },
		"读取设备": func() error { _, err := store.Device(channelA, deviceA); return err },
		"列出设备": func() error { _, err := store.Devices(channelA); return err },
		"统计设备": func() error { _, err := store.CountDevices(channelA); return err },
		"移除设备": func() error { return store.RemoveDevice(channelA, deviceA) },
		"写入记录": func() error { _, err := store.PutRecord(channelA, sampleRecord(deviceA, 1)); return err },
		"读取记录": func() error { _, err := store.Record(channelA, deviceA); return err },
		"列出记录": func() error { _, err := store.Records(channelA); return err },
		"删除记录": func() error { return store.DeleteRecord(channelA, deviceA) },
		"吊销":   func() error { return store.Revoke(channelA, Revocation{Fingerprint: deviceA}) },
		"读取吊销": func() error { _, err := store.Revocation(channelA, deviceA); return err },
		"列出吊销": func() error { _, err := store.Revocations(channelA); return err },
		"移除吊销": func() error { return store.Forgive(channelA, deviceA) },
	}

	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("存储关闭后执行「%s」应当报错", name)
		}
	}
}

func TestOpenRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waystation.db")

	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("建立测试用存储失败：%v", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(metaBucket))
		if err != nil {
			return err
		}
		return bucket.Put([]byte(schemaKey), []byte("99"))
	}); err != nil {
		t.Fatalf("写入测试用版本号失败：%v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭测试用存储失败：%v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("存储版本不符时应当报错")
	}
}
