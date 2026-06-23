package keyring

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMetadataNormalize(t *testing.T) {
	t.Parallel()

	created := time.Unix(1_710_000_000, 0).UTC()

	tests := []struct {
		name      string
		in        Metadata
		kid       string
		algorithm string
		use       string
		want      Metadata
	}{
		{
			name:      "fills all defaults",
			in:        Metadata{},
			kid:       "k1",
			algorithm: "EdDSA",
			use:       "sig",
			want: Metadata{
				KID:       "k1",
				Algorithm: "EdDSA",
				Use:       "sig",
				Status:    StatusActive,
			},
		},
		{
			name: "keeps existing values",
			in: Metadata{
				KID:       "explicit",
				Algorithm: "PS512",
				Use:       "enc",
				Status:    StatusRetiring,
				CreatedAt: created,
			},
			kid:       "fallback",
			algorithm: "EdDSA",
			use:       "sig",
			want: Metadata{
				KID:       "explicit",
				Algorithm: "PS512",
				Use:       "enc",
				Status:    StatusRetiring,
				CreatedAt: created,
			},
		},
		{
			name:      "partial fill",
			in:        Metadata{KID: "k1", Status: StatusRetired},
			kid:       "fallback",
			algorithm: "EdDSA",
			use:       "sig",
			want: Metadata{
				KID:       "k1",
				Algorithm: "EdDSA",
				Use:       "sig",
				Status:    StatusRetired,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.in.Normalize(tt.kid, tt.algorithm, tt.use)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMetadataValidation(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_710_000_000, 0).UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name      string
		meta      Metadata
		signErr   error
		verifyErr error
		canSign   bool
		canVerify bool
	}{
		{
			name:      "active valid",
			meta:      Metadata{KID: "k1", Status: StatusActive},
			canSign:   true,
			canVerify: true,
		},
		{
			name:      "retiring can verify not sign",
			meta:      Metadata{KID: "k1", Status: StatusRetiring},
			signErr:   ErrKeyNotActive,
			canVerify: true,
		},
		{
			name:      "retired can verify not sign",
			meta:      Metadata{KID: "k1", Status: StatusRetired},
			signErr:   ErrKeyNotActive,
			canVerify: true,
		},
		{
			name:      "revoked by status",
			meta:      Metadata{KID: "k1", Status: StatusRevoked},
			signErr:   ErrKeyRevoked,
			verifyErr: ErrKeyRevoked,
		},
		{
			name:      "revoked by timestamp at boundary",
			meta:      Metadata{KID: "k1", Status: StatusActive, RevokedAt: now},
			signErr:   ErrKeyRevoked,
			verifyErr: ErrKeyRevoked,
		},
		{
			name:      "revoked timestamp in future still valid",
			meta:      Metadata{KID: "k1", Status: StatusActive, RevokedAt: future},
			canSign:   true,
			canVerify: true,
		},
		{
			name:      "not yet valid",
			meta:      Metadata{KID: "k1", Status: StatusActive, NotBefore: future},
			signErr:   ErrKeyNotYetValid,
			verifyErr: ErrKeyNotYetValid,
		},
		{
			name:      "not before in past is valid",
			meta:      Metadata{KID: "k1", Status: StatusActive, NotBefore: past},
			canSign:   true,
			canVerify: true,
		},
		{
			name:      "expired at boundary",
			meta:      Metadata{KID: "k1", Status: StatusActive, ExpiresAt: now},
			signErr:   ErrKeyExpired,
			verifyErr: ErrKeyExpired,
		},
		{
			name:      "expires in future is valid",
			meta:      Metadata{KID: "k1", Status: StatusActive, ExpiresAt: future},
			canSign:   true,
			canVerify: true,
		},
		{
			name:      "revoked takes precedence over not-yet-valid",
			meta:      Metadata{KID: "k1", Status: StatusRevoked, NotBefore: future},
			signErr:   ErrKeyRevoked,
			verifyErr: ErrKeyRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signErr := tt.meta.ValidateForSign(now)
			verifyErr := tt.meta.ValidateForVerify(now)

			if tt.signErr != nil {
				require.ErrorIs(t, signErr, tt.signErr)
			} else {
				require.NoError(t, signErr)
			}
			if tt.verifyErr != nil {
				require.ErrorIs(t, verifyErr, tt.verifyErr)
			} else {
				require.NoError(t, verifyErr)
			}

			require.Equal(t, tt.canSign, tt.meta.CanSign(now))
			require.Equal(t, tt.canVerify, tt.meta.CanVerify(now))
		})
	}
}

func TestActiveRecord(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_710_000_000, 0).UTC()

	tests := []struct {
		name     string
		snapshot *Snapshot[Record[string]]
		wantKey  string
		wantErr  error
	}{
		{
			name: "active signable",
			snapshot: &Snapshot[Record[string]]{
				ActiveKID: "k1",
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusActive}},
				},
			},
			wantKey: "secret",
		},
		{
			name: "active kid not found",
			snapshot: &Snapshot[Record[string]]{
				ActiveKID: "missing",
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusActive}},
				},
			},
			wantErr: ErrActiveKIDNotFound,
		},
		{
			name: "active but retiring fails sign",
			snapshot: &Snapshot[Record[string]]{
				ActiveKID: "k1",
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusRetiring}},
				},
			},
			wantErr: ErrKeyNotActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			record, err := ActiveRecord(tt.snapshot, now)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, record.Key)
		})
	}
}

func TestVerifyRecord(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_710_000_000, 0).UTC()

	tests := []struct {
		name     string
		kid      string
		snapshot *Snapshot[Record[string]]
		wantKey  string
		wantErr  error
	}{
		{
			name: "verifiable",
			kid:  "k1",
			snapshot: &Snapshot[Record[string]]{
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusRetiring}},
				},
			},
			wantKey: "secret",
		},
		{
			name: "kid not found",
			kid:  "missing",
			snapshot: &Snapshot[Record[string]]{
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusActive}},
				},
			},
			wantErr: ErrKIDNotFound,
		},
		{
			name: "revoked cannot verify",
			kid:  "k1",
			snapshot: &Snapshot[Record[string]]{
				Keys: map[string]Record[string]{
					"k1": {Key: "secret", Metadata: Metadata{KID: "k1", Status: StatusRevoked}},
				},
			},
			wantErr: ErrKeyRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			record, err := VerifyRecord(tt.snapshot, tt.kid, now)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantKey, record.Key)
		})
	}
}
