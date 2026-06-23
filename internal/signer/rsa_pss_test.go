package signer

import (
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gtkit/encry/internal/keyring"
	encryrsa "github.com/gtkit/encry/rsa"
)

const (
	rsaKID     = "k1"
	rsaKeySize = 2048
)

var (
	rsaKeyOnce sync.Once
	rsaKeyPair keyring.RSAKeyPair
	rsaAltOnce sync.Once
	rsaAltPair keyring.RSAKeyPair
)

func sharedRSAKey(t *testing.T) keyring.RSAKeyPair {
	t.Helper()
	rsaKeyOnce.Do(func() {
		priv, pub, err := encryrsa.GenerateKeyPair(rsaKeySize)
		if err != nil {
			t.Fatalf("generate rsa: %v", err)
		}
		rsaKeyPair = keyring.RSAKeyPair{Private: priv, Public: pub}
	})
	return rsaKeyPair
}

func altRSAKey(t *testing.T) keyring.RSAKeyPair {
	t.Helper()
	rsaAltOnce.Do(func() {
		priv, pub, err := encryrsa.GenerateKeyPair(rsaKeySize)
		if err != nil {
			t.Fatalf("generate alt rsa: %v", err)
		}
		rsaAltPair = keyring.RSAKeyPair{Private: priv, Public: pub}
	})
	return rsaAltPair
}

func newRSARing(
	t *testing.T,
	keys map[string]keyring.RSAKeyPair,
) *keyring.Ring[keyring.RSAKeyPair] {
	t.Helper()
	ring := keyring.New[keyring.RSAKeyPair]()
	if err := ring.Store(rsaKID, keys); err != nil {
		t.Fatalf("store rsa ring: %v", err)
	}
	return ring
}

func TestRSAPSSService_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "simple", payload: []byte("message")},
		{name: "empty", payload: []byte("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring := newRSARing(t, map[string]keyring.RSAKeyPair{rsaKID: sharedRSAKey(t)})
			svc := NewRSAPSS(ring, crypto.SHA256, nil)

			signed, err := svc.Sign(tt.payload)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			ok, err := svc.Verify(tt.payload, signed)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Error("verify = false, want true")
			}
		})
	}
}

func TestRSAPSSService_VerifyWith_CustomHash(t *testing.T) {
	t.Parallel()

	ring := newRSARing(t, map[string]keyring.RSAKeyPair{rsaKID: sharedRSAKey(t)})
	svc := NewRSAPSS(ring, crypto.SHA512, nil)

	signed, err := svc.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := svc.VerifyWith([]byte("payload"), signed, crypto.SHA512, nil)
	if err != nil {
		t.Fatalf("verifyWith: %v", err)
	}
	if !ok {
		t.Error("verify = false, want true")
	}

	// 哈希不匹配应返回 false（无错误）。
	mismatch, err := svc.VerifyWith([]byte("payload"), signed, crypto.SHA256, nil)
	if err != nil {
		t.Fatalf("verifyWith mismatch: %v", err)
	}
	if mismatch {
		t.Error("verify with mismatched hash = true, want false")
	}
}

func TestRSAPSSService_Sign_RingNotInitialized(t *testing.T) {
	t.Parallel()

	svc := NewRSAPSS(keyring.New[keyring.RSAKeyPair](), crypto.SHA256, nil)
	_, err := svc.Sign([]byte("x"))
	if !errors.Is(err, keyring.ErrRingNotInitialized) {
		t.Errorf("error = %v, want ErrRingNotInitialized", err)
	}
}

func TestRSAPSSService_Verify_Errors(t *testing.T) {
	t.Parallel()

	pair := sharedRSAKey(t)
	baseRing := newRSARing(t, map[string]keyring.RSAKeyPair{rsaKID: pair})
	signed, err := NewRSAPSS(baseRing, crypto.SHA256, nil).Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("setup sign: %v", err)
	}

	tests := []struct {
		name      string
		ring      *keyring.Ring[keyring.RSAKeyPair]
		payload   []byte
		signed    string
		wantOK    bool
		wantErr   error
		wantNoErr bool
	}{
		{
			name:    "invalid signature format",
			ring:    baseRing,
			payload: []byte("payload"),
			signed:  "nodot",
		},
		{
			name:    "non base64 signature",
			ring:    baseRing,
			payload: []byte("payload"),
			signed:  rsaKID + ".!!!notb64!!!",
		},
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.RSAKeyPair](),
			payload: []byte("payload"),
			signed:  signed,
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:    "unknown kid",
			ring:    baseRing,
			payload: []byte("payload"),
			signed:  "other." + signed[len(rsaKID)+1:],
		},
		{
			name:      "tampered payload returns false",
			ring:      baseRing,
			payload:   []byte("tampered"),
			signed:    signed,
			wantOK:    false,
			wantNoErr: true,
		},
		{
			name:      "wrong public key returns false",
			ring:      newRSARing(t, map[string]keyring.RSAKeyPair{rsaKID: altRSAKey(t)}),
			payload:   []byte("payload"),
			signed:    signed,
			wantOK:    false,
			wantNoErr: true,
		},
		{
			name:      "valid returns true",
			ring:      baseRing,
			payload:   []byte("payload"),
			signed:    signed,
			wantOK:    true,
			wantNoErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := NewRSAPSS(tt.ring, crypto.SHA256, nil)
			ok, err := svc.Verify(tt.payload, tt.signed)
			switch {
			case tt.wantNoErr:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if ok != tt.wantOK {
					t.Errorf("ok = %v, want %v", ok, tt.wantOK)
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
			default:
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			}
		})
	}
}

// ---- managed variant ----

func rsaRecord(t *testing.T, status keyring.KeyStatus) keyring.Record[keyring.RSAKeyPair] {
	t.Helper()
	return keyring.Record[keyring.RSAKeyPair]{
		Key:      sharedRSAKey(t),
		Metadata: keyring.Metadata{KID: rsaKID, Status: status},
	}
}

func newRSARecordRing(
	t *testing.T,
	records map[string]keyring.Record[keyring.RSAKeyPair],
) *keyring.Ring[keyring.Record[keyring.RSAKeyPair]] {
	t.Helper()
	ring := keyring.New[keyring.Record[keyring.RSAKeyPair]]()
	if err := ring.Store(rsaKID, records); err != nil {
		t.Fatalf("store managed rsa ring: %v", err)
	}
	return ring
}

func newManagedRSASvc(
	ring *keyring.Ring[keyring.Record[keyring.RSAKeyPair]],
) *ManagedRSAPSSService {
	svc := NewManagedRSAPSS(ring, crypto.SHA256, nil)
	svc.now = func() time.Time { return sigFixedNow }
	return svc
}

func TestManagedRSAPSSService_RoundTrip(t *testing.T) {
	t.Parallel()

	ring := newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{
		rsaKID: rsaRecord(t, keyring.StatusActive),
	})
	svc := newManagedRSASvc(ring)

	signed, err := svc.Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := svc.Verify([]byte("payload"), signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("verify = false, want true")
	}
}

func TestManagedRSAPSSService_Sign_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[keyring.RSAKeyPair]]
		wantErr error
	}{
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[keyring.RSAKeyPair]](),
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name: "retiring not active for sign",
			ring: newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{
				rsaKID: rsaRecord(t, keyring.StatusRetiring),
			}),
			wantErr: keyring.ErrKeyNotActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedRSASvc(tt.ring)
			_, err := svc.Sign([]byte("x"))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestManagedRSAPSSService_Verify_Errors(t *testing.T) {
	t.Parallel()

	rec := rsaRecord(t, keyring.StatusActive)
	baseRing := newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{
		rsaKID: rec,
	})
	signed, err := newManagedRSASvc(baseRing).Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("setup sign: %v", err)
	}

	expiredRing := newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{
		rsaKID: {
			Key: rec.Key,
			Metadata: keyring.Metadata{
				KID:       rsaKID,
				Status:    keyring.StatusActive,
				ExpiresAt: sigFixedNow.Add(-time.Hour),
			},
		},
	})

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[keyring.RSAKeyPair]]
		signed  string
		wantErr error
	}{
		{name: "invalid signature format", ring: baseRing, signed: "nodot"},
		{name: "non base64 signature", ring: baseRing, signed: rsaKID + ".!!!notb64!!!"},
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[keyring.RSAKeyPair]](),
			signed:  signed,
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:    "kid not found",
			ring:    baseRing,
			signed:  "missing." + signed[len(rsaKID)+1:],
			wantErr: keyring.ErrKIDNotFound,
		},
		{
			name:    "expired rejected on verify",
			ring:    expiredRing,
			signed:  signed,
			wantErr: keyring.ErrKeyExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedRSASvc(tt.ring)
			_, err := svc.Verify([]byte("payload"), tt.signed)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestManagedRSAPSSService_VerifyWith_RetiringAllowed 验证 retiring key 仍可验签。
func TestManagedRSAPSSService_VerifyWith_RetiringAllowed(t *testing.T) {
	t.Parallel()

	rec := rsaRecord(t, keyring.StatusActive)
	signed, err := newManagedRSASvc(
		newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{rsaKID: rec}),
	).Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	retiringRing := newRSARecordRing(t, map[string]keyring.Record[keyring.RSAKeyPair]{
		rsaKID: {Key: rec.Key, Metadata: keyring.Metadata{KID: rsaKID, Status: keyring.StatusRetiring}},
	})
	ok, err := newManagedRSASvc(retiringRing).Verify([]byte("payload"), signed)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("verify with retiring key = false, want true")
	}
}

func TestNewManagedRSAPSS_DefaultNow(t *testing.T) {
	t.Parallel()

	svc := NewManagedRSAPSS(keyring.New[keyring.Record[keyring.RSAKeyPair]](), crypto.SHA256, nil)
	if svc.now == nil {
		t.Fatal("now should default to time.Now")
	}
}
