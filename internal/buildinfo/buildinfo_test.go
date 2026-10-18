package buildinfo

import (
	"strings"
	"testing"
)

func TestStringIncludesAllFields(t *testing.T) {
	got := String()
	for _, want := range []string{Version, Commit, Date} {
		if !strings.Contains(got, want) {
			t.Fatalf("版本描述缺少字段 %q：%s", want, got)
		}
	}
}
