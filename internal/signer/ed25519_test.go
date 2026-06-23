package signer

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/gtkit/encry/ed"
	"github.com/gtkit/encry/internal/keyring"
)

const sigKID = "k1"

var sigFixedNow = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

func genEd25519(t *testing.T) keyring.Ed25519KeyPair {
	t.Helper()
	pub, priv, err := ed.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return keyring.Ed25519KeyPair{Private: priv, Public: pub}
}

func newEdRing(
	t *testing.T,
	activeKID string,
	keys map[string]keyring.Ed25519KeyPair,
) *keyring.Ring[keyring.Ed25519KeyPair] {
	t.Helper()
	ring := keyring.New[keyring.Ed25519KeyPair]()
	if err := ring.Store(activeKID, keys); err != nil {
		t.Fatalf("store ed ring: %v", err)
	}
	return ring
}

func TestEd25519Service_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "simple", payload: []byte("message")},
		{name: "empty", payload: []byte("")},
		{name: "binary", payload: []byte{0x00, 0x01, 0xff, 0x7f}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring := newEdRing(t, sigKID, map[string]keyring.Ed25519KeyPair{sigKID: genEd25519(t)})
			svc := NewEd25519(ring)

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

func TestEd25519Service_Sign_RingNotInitialized(t *testing.T) {
	t.Parallel()

	svc := NewEd25519(keyring.New[keyring.Ed25519KeyPair]())
	_, err := svc.Sign([]byte("x"))
	if !errors.Is(err, keyring.ErrRingNotInitialized) {
		t.Errorf("error = %v, want ErrRingNotInitialized", err)
	}
}

func TestEd25519Service_Verify(t *testing.T) {
	t.Parallel()

	pair := genEd25519(t)
	baseRing := newEdRing(t, sigKID, map[string]keyring.Ed25519KeyPair{sigKID: pair})
	signed, err := NewEd25519(baseRing).Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("setup sign: %v", err)
	}

	tests := []struct {
		name      string
		ring      *keyring.Ring[keyring.Ed25519KeyPair]
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
			signed:  "no-dot-here",
		},
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Ed25519KeyPair](),
			payload: []byte("payload"),
			signed:  signed,
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:    "unknown kid",
			ring:    baseRing,
			payload: []byte("payload"),
			signed:  "other." + signed[len(sigKID)+1:],
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
			name: "wrong public key returns false",
			ring: newEdRing(t, sigKID, map[string]keyring.Ed25519KeyPair{
				sigKID: genEd25519(t),
			}),
			payload:   []byte("payload"),
			signed:    signed,
			wantOK:    false,
			wantNoErr: true,
		},
		{
			name:      "valid signature returns true",
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

			svc := NewEd25519(tt.ring)
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

func genEdRecord(t *testing.T, status keyring.KeyStatus) keyring.Record[keyring.Ed25519KeyPair] {
	t.Helper()
	return keyring.Record[keyring.Ed25519KeyPair]{
		Key:      genEd25519(t),
		Metadata: keyring.Metadata{KID: sigKID, Status: status},
	}
}

func newEdRecordRing(
	t *testing.T,
	records map[string]keyring.Record[keyring.Ed25519KeyPair],
) *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]] {
	t.Helper()
	ring := keyring.New[keyring.Record[keyring.Ed25519KeyPair]]()
	if err := ring.Store(sigKID, records); err != nil {
		t.Fatalf("store managed ed ring: %v", err)
	}
	return ring
}

func newManagedEdSvc(ring *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]) *ManagedEd25519Service {
	svc := NewManagedEd25519(ring)
	svc.now = func() time.Time { return sigFixedNow }
	return svc
}

func TestManagedEd25519Service_RoundTrip(t *testing.T) {
	t.Parallel()

	ring := newEdRecordRing(t, map[string]keyring.Record[keyring.Ed25519KeyPair]{
		sigKID: genEdRecord(t, keyring.StatusActive),
	})
	svc := newManagedEdSvc(ring)

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

func TestManagedEd25519Service_Sign_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]
		wantErr error
	}{
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[keyring.Ed25519KeyPair]](),
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name: "retiring not active for sign",
			ring: newEdRecordRing(t, map[string]keyring.Record[keyring.Ed25519KeyPair]{
				sigKID: genEdRecord(t, keyring.StatusRetiring),
			}),
			wantErr: keyring.ErrKeyNotActive,
		},
		{
			name: "revoked",
			ring: newEdRecordRing(t, map[string]keyring.Record[keyring.Ed25519KeyPair]{
				sigKID: genEdRecord(t, keyring.StatusRevoked),
			}),
			wantErr: keyring.ErrKeyRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedEdSvc(tt.ring)
			_, err := svc.Sign([]byte("x"))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestManagedEd25519Service_Verify_Errors(t *testing.T) {
	t.Parallel()

	rec := genEdRecord(t, keyring.StatusActive)
	baseRing := newEdRecordRing(t, map[string]keyring.Record[keyring.Ed25519KeyPair]{
		sigKID: rec,
	})
	signed, err := newManagedEdSvc(baseRing).Sign([]byte("payload"))
	if err != nil {
		t.Fatalf("setup sign: %v", err)
	}

	revokedRing := newEdRecordRing(t, map[string]keyring.Record[keyring.Ed25519KeyPair]{
		sigKID: {Key: rec.Key, Metadata: keyring.Metadata{KID: sigKID, Status: keyring.StatusRevoked}},
	})

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[keyring.Ed25519KeyPair]]
		signed  string
		wantErr error
	}{
		{name: "invalid signature format", ring: baseRing, signed: "nodot"},
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[keyring.Ed25519KeyPair]](),
			signed:  signed,
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:    "kid not found",
			ring:    baseRing,
			signed:  "missing." + signed[len(sigKID)+1:],
			wantErr: keyring.ErrKIDNotFound,
		},
		{
			name:    "revoked rejected on verify",
			ring:    revokedRing,
			signed:  signed,
			wantErr: keyring.ErrKeyRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedEdSvc(tt.ring)
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

func TestNewManagedEd25519_DefaultNow(t *testing.T) {
	t.Parallel()

	svc := NewManagedEd25519(keyring.New[keyring.Record[keyring.Ed25519KeyPair]]())
	if svc.now == nil {
		t.Fatal("now should default to time.Now")
	}
}

// 防止 ed25519 包被误判为未使用（显式断言私钥长度）。
func TestEd25519KeyMaterial(t *testing.T) {
	t.Parallel()

	pair := genEd25519(t)
	if len(pair.Private) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(pair.Private), ed25519.PrivateKeySize)
	}
}
