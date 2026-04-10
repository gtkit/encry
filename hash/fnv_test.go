package hash

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDuplicateTrackerExpiresEntries(t *testing.T) {
	now := time.Unix(1_710_000_000, 0)
	tracker := NewDuplicateTracker(DuplicateTrackerOptions{
		TTL:        time.Minute,
		MaxEntries: 8,
		Now: func() time.Time {
			return now
		},
	})

	require.False(t, tracker.IsDuplicate("a"))
	require.True(t, tracker.IsDuplicate("a"))

	now = now.Add(2 * time.Minute)

	require.False(t, tracker.IsDuplicate("a"))
}

func TestDuplicateTrackerEvictsOldestWhenCapacityReached(t *testing.T) {
	now := time.Unix(1_710_000_000, 0)
	tracker := NewDuplicateTracker(DuplicateTrackerOptions{
		TTL:        time.Hour,
		MaxEntries: 2,
		Now: func() time.Time {
			return now
		},
	})

	require.False(t, tracker.IsDuplicate("a"))
	now = now.Add(time.Second)
	require.False(t, tracker.IsDuplicate("b"))
	now = now.Add(time.Second)
	require.False(t, tracker.IsDuplicate("c"))

	require.False(t, tracker.IsDuplicate("a"))
}
