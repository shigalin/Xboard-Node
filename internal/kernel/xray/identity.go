package xray

import (
	"bytes"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	hysteria "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
)

// A Mux child retains the account authenticated on its outer connection. Its
// email alone is insufficient: an ID keeps the same email after a UUID change.
func accountMatchesUUID(account protocol.Account, credential string) bool {
	switch a := account.(type) {
	case nil:
		// SOCKS/HTTP carry their authenticated username in Email, not Account.
		return true
	case *vless.MemoryAccount:
		id, err := uuid.ParseString(credential)
		return err == nil && a.ID != nil && a.ID.UUID() == id
	case *vmess.MemoryAccount:
		id, err := uuid.ParseString(credential)
		return err == nil && a.ID != nil && a.ID.UUID() == id
	case *trojan.MemoryAccount:
		return a.Password == credential
	case *shadowsocks.MemoryAccount:
		return a.Password == credential
	case *ss2022.MemoryAccount:
		return len(a.Key) > 0 && bytes.Equal(a.Key, ss2022UserKey(credential, len(a.Key)))
	case *hysteria.MemoryAccount:
		// Match Hysteria's validator: UUID bytes 6/7 encode the client's VR.
		got, errGot := uuid.ParseString(a.Auth)
		want, errWant := uuid.ParseString(credential)
		if errGot == nil && errWant == nil {
			got[6], got[7], want[6], want[7] = 0, 0, 0, 0
			return got == want
		}
		return a.Auth == credential
	default:
		return false
	}
}
