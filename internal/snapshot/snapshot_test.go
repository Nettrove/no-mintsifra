package snapshot

import (
	"testing"

	"github.com/Nettrove/no-mintsifra/internal/pins"
	"github.com/Nettrove/no-mintsifra/internal/trust"
)

func TestEmbeddedSnapshotIsSignedByProjectKey(t *testing.T) {
	b := Bundle()
	set, err := pins.OpenWith(b.Data, b.Sig, trust.PinsKeys())
	if err != nil {
		t.Fatalf("embedded snapshot does not verify: %v", err)
	}
	if len(set.Sites) == 0 {
		t.Fatal("embedded snapshot is empty")
	}
}
