package keyring

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRingStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		activeKID string
		keys      map[string]string
		wantErr   error
	}{
		{
			name:      "success single key",
			activeKID: "k1",
			keys:      map[string]string{"k1": "v1"},
		},
		{
			name:      "success multiple keys",
			activeKID: "k2",
			keys:      map[string]string{"k1": "v1", "k2": "v2"},
		},
		{
			name:      "empty key set",
			activeKID: "k1",
			keys:      map[string]string{},
			wantErr:   ErrEmptyKeySet,
		},
		{
			name:      "nil key set",
			activeKID: "k1",
			keys:      nil,
			wantErr:   ErrEmptyKeySet,
		},
		{
			name:      "active kid missing",
			activeKID: "missing",
			keys:      map[string]string{"k1": "v1"},
			wantErr:   ErrActiveKIDNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ring := New[string]()
			err := ring.Store(tt.activeKID, tt.keys)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			snap, cerr := ring.Current()
			require.NoError(t, cerr)
			require.Equal(t, tt.activeKID, snap.ActiveKID)
			require.Equal(t, tt.keys, snap.Keys)
		})
	}
}

func TestRingStoreClonesInput(t *testing.T) {
	t.Parallel()

	ring := New[string]()
	keys := map[string]string{"k1": "v1"}
	require.NoError(t, ring.Store("k1", keys))

	// Mutating the original map must not affect the stored snapshot.
	keys["k1"] = "mutated"
	keys["k2"] = "added"

	snap, err := ring.Current()
	require.NoError(t, err)
	require.Equal(t, "v1", snap.Keys["k1"])
	_, ok := snap.Keys["k2"]
	require.False(t, ok)
}

func TestRingCurrentNotInitialized(t *testing.T) {
	t.Parallel()

	ring := New[string]()
	snap, err := ring.Current()
	require.ErrorIs(t, err, ErrRingNotInitialized)
	require.Nil(t, snap)
}

func TestRingRotate(t *testing.T) {
	t.Parallel()

	ring := New[string]()
	require.NoError(t, ring.Store("k1", map[string]string{"k1": "v1"}))

	first, err := ring.Current()
	require.NoError(t, err)
	require.Equal(t, "k1", first.ActiveKID)

	// Rotate: add a new key and switch active kid.
	require.NoError(t, ring.Store("k2", map[string]string{"k1": "v1", "k2": "v2"}))

	second, err := ring.Current()
	require.NoError(t, err)
	require.Equal(t, "k2", second.ActiveKID)
	require.Len(t, second.Keys, 2)

	// The earlier snapshot remains unchanged (immutable view).
	require.Equal(t, "k1", first.ActiveKID)
	require.Len(t, first.Keys, 1)
}

func TestSnapshotActive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		activeKID string
		keys      map[string]string
		want      string
		wantErr   error
	}{
		{
			name:      "active present",
			activeKID: "k1",
			keys:      map[string]string{"k1": "v1"},
			want:      "v1",
		},
		{
			name:      "active absent",
			activeKID: "missing",
			keys:      map[string]string{"k1": "v1"},
			wantErr:   ErrActiveKIDNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			snap := &Snapshot[string]{ActiveKID: tt.activeKID, Keys: tt.keys}
			got, err := snap.Active()
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSnapshotGet(t *testing.T) {
	t.Parallel()

	snap := &Snapshot[string]{
		ActiveKID: "k1",
		Keys:      map[string]string{"k1": "v1"},
	}

	got, ok := snap.Get("k1")
	require.True(t, ok)
	require.Equal(t, "v1", got)

	missing, ok := snap.Get("nope")
	require.False(t, ok)
	require.Empty(t, missing)
}

func TestSnapshotKIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		keys map[string]string
		want []string
	}{
		{
			name: "sorted output",
			keys: map[string]string{"c": "3", "a": "1", "b": "2"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty",
			keys: map[string]string{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			snap := &Snapshot[string]{Keys: tt.keys}
			got := snap.KIDs()
			if len(tt.want) == 0 {
				require.Empty(t, got)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestRingConcurrentStoreAndCurrent(t *testing.T) {
	t.Parallel()

	ring := New[string]()
	require.NoError(t, ring.Store("k0", map[string]string{"k0": "v0"}))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for range goroutines {
		go func() {
			defer wg.Done()
			kid := "k0"
			if err := ring.Store(kid, map[string]string{kid: "v"}); err != nil {
				t.Errorf("concurrent store: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := ring.Current(); err != nil && !errors.Is(err, ErrRingNotInitialized) {
				t.Errorf("concurrent current: %v", err)
			}
		}()
	}
	wg.Wait()
}
