package sealer

import (
	"errors"
	"testing"
	"time"

	"github.com/gtkit/encry/internal/keyring"
)

var fixedNow = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

func newRecordRing(
	t *testing.T,
	records map[string]keyring.Record[string],
) *keyring.Ring[keyring.Record[string]] {
	t.Helper()
	ring := keyring.New[keyring.Record[string]]()
	if err := ring.Store(testKID, records); err != nil {
		t.Fatalf("store managed ring: %v", err)
	}
	return ring
}

func activeRecord(key string) keyring.Record[string] {
	return keyring.Record[string]{
		Key: key,
		Metadata: keyring.Metadata{
			KID:    testKID,
			Status: keyring.StatusActive,
		},
	}
}

func newManagedSvc(ring *keyring.Ring[keyring.Record[string]]) *ManagedAESGCMService {
	svc := NewManagedAESGCM(ring)
	svc.now = func() time.Time { return fixedNow }
	return svc
}

func TestManagedAESGCMService_RoundTrip(t *testing.T) {
	t.Parallel()

	ring := newRecordRing(t, map[string]keyring.Record[string]{
		testKID: activeRecord(testKey),
	})
	svc := newManagedSvc(ring)

	token, err := svc.Encrypt([]byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := svc.Decrypt(token, []byte("aad"))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("round-trip = %q, want %q", got, "payload")
	}
}

func TestManagedAESGCMService_Encrypt_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[string]]
		wantErr error
	}{
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[string]](),
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name: "active key expired",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key: testKey,
					Metadata: keyring.Metadata{
						KID:       testKID,
						Status:    keyring.StatusActive,
						ExpiresAt: fixedNow.Add(-time.Hour),
					},
				},
			}),
			wantErr: keyring.ErrKeyExpired,
		},
		{
			name: "active key not yet valid",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key: testKey,
					Metadata: keyring.Metadata{
						KID:       testKID,
						Status:    keyring.StatusActive,
						NotBefore: fixedNow.Add(time.Hour),
					},
				},
			}),
			wantErr: keyring.ErrKeyNotYetValid,
		},
		{
			name: "active key retiring not allowed for sign",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key:      testKey,
					Metadata: keyring.Metadata{KID: testKID, Status: keyring.StatusRetiring},
				},
			}),
			wantErr: keyring.ErrKeyNotActive,
		},
		{
			name: "active key revoked",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key:      testKey,
					Metadata: keyring.Metadata{KID: testKID, Status: keyring.StatusRevoked},
				},
			}),
			wantErr: keyring.ErrKeyRevoked,
		},
		{
			name: "invalid key length",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: activeRecord(shortKey),
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedSvc(tt.ring)
			_, err := svc.Encrypt([]byte("data"), nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestManagedAESGCMService_Decrypt_Errors(t *testing.T) {
	t.Parallel()

	baseRing := newRecordRing(t, map[string]keyring.Record[string]{
		testKID: activeRecord(testKey),
	})
	validToken, err := newManagedSvc(baseRing).Encrypt([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}

	tests := []struct {
		name    string
		ring    *keyring.Ring[keyring.Record[string]]
		token   string
		aad     []byte
		wantErr error
	}{
		{
			name:  "invalid token format",
			ring:  baseRing,
			token: "no-dot",
			aad:   []byte("aad"),
		},
		{
			name:    "ring not initialized",
			ring:    keyring.New[keyring.Record[string]](),
			token:   validToken,
			aad:     []byte("aad"),
			wantErr: keyring.ErrRingNotInitialized,
		},
		{
			name:    "kid not found",
			ring:    baseRing,
			token:   "missing." + validToken[len(testKID)+1:],
			aad:     []byte("aad"),
			wantErr: keyring.ErrKIDNotFound,
		},
		{
			name: "revoked key rejected on verify",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key:      testKey,
					Metadata: keyring.Metadata{KID: testKID, Status: keyring.StatusRevoked},
				},
			}),
			token:   validToken,
			aad:     []byte("aad"),
			wantErr: keyring.ErrKeyRevoked,
		},
		{
			name: "expired key rejected on verify",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: {
					Key: testKey,
					Metadata: keyring.Metadata{
						KID:       testKID,
						Status:    keyring.StatusActive,
						ExpiresAt: fixedNow.Add(-time.Hour),
					},
				},
			}),
			token:   validToken,
			aad:     []byte("aad"),
			wantErr: keyring.ErrKeyExpired,
		},
		{
			name: "wrong aad",
			ring: newRecordRing(t, map[string]keyring.Record[string]{
				testKID: activeRecord(testKey),
			}),
			token: validToken,
			aad:   []byte("other"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := newManagedSvc(tt.ring)
			_, err := svc.Decrypt(tt.token, tt.aad)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestManagedAESGCMService_Verify_RetiringAllowed 验证 retiring 状态仍可解密（验签放行）。
func TestManagedAESGCMService_Verify_RetiringAllowed(t *testing.T) {
	t.Parallel()

	encRing := newRecordRing(t, map[string]keyring.Record[string]{
		testKID: activeRecord(testKey),
	})
	token, err := newManagedSvc(encRing).Encrypt([]byte("data"), nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	retiringRing := newRecordRing(t, map[string]keyring.Record[string]{
		testKID: {
			Key:      testKey,
			Metadata: keyring.Metadata{KID: testKID, Status: keyring.StatusRetiring},
		},
	})
	got, err := newManagedSvc(retiringRing).Decrypt(token, nil)
	if err != nil {
		t.Fatalf("decrypt with retiring key should succeed: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("decrypt = %q, want %q", got, "data")
	}
}

func TestNewManagedAESGCM_DefaultNow(t *testing.T) {
	t.Parallel()

	svc := NewManagedAESGCM(keyring.New[keyring.Record[string]]())
	if svc.now == nil {
		t.Fatal("now should default to time.Now")
	}
}
