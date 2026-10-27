package xray

import (
	"testing"

	"github.com/cedar2025/xboard-node/internal/model"
	hysteria "github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestAuthenticatedAccountRejectsChangedUUID(t *testing.T) {
	old := model.UserSpec{ID: 1, UUID: "11111111-1111-4111-8111-111111111111"}
	changed := "22222222-2222-4222-8222-222222222222"
	for _, proto := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria"} {
		for _, cipher := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
			t.Run(proto+"/"+cipher, func(t *testing.T) {
				user, err := toMemoryUser(proto, &model.NodeSpec{Cipher: cipher}, old)
				if err != nil {
					t.Fatal(err)
				}
				if !accountMatchesUUID(user.Account, old.UUID) || accountMatchesUUID(user.Account, changed) {
					t.Fatal("account identity did not distinguish current and revoked UUIDs")
				}
			})
		}
	}
}

func TestHysteriaIdentityKeepsValidatorVRSemantics(t *testing.T) {
	account := &hysteria.MemoryAccount{Auth: "11111111-1111-1234-8111-111111111111"}
	if !accountMatchesUUID(account, "11111111-1111-4111-8111-111111111111") {
		t.Fatal("valid VR variant rejected")
	}
	if accountMatchesUUID(account, "22222222-2222-4222-8222-222222222222") {
		t.Fatal("changed identity admitted")
	}
}
