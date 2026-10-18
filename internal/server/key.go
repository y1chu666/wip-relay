package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"vaultwaystation/internal/identity"
)

// keyFileMode 是密钥文件的权限：内容即明文私钥，只许属主读写。
const keyFileMode = 0o600

// loadOrCreateKey 读取服务端密钥，首次运行时生成并落盘。
//
// 密钥一经生成不再更换：客户端在首次配对时钉住这把公钥，换了等于换了服务端，
// 全部设备都要重新配对。因此写入时用排他创建，绝不覆盖既有文件。
func loadOrCreateKey(path string) (*identity.KeyPair, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err := identity.Decode(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("读取服务端密钥 %s：%w", path, err)
		}
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("读取服务端密钥 %s：%w", path, err)
	}

	key, err := identity.Generate()
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		return nil, fmt.Errorf("写入服务端密钥 %s：%w", path, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := io.WriteString(file, key.Encode()+"\n"); err != nil {
		return nil, fmt.Errorf("写入服务端密钥 %s：%w", path, err)
	}
	return key, nil
}
