package trust

import "testing"

func TestCurrentKeyComesFirstAndIsOpen(t *testing.T) {
	keys := PinsKeys()
	if len(keys) == 0 || !keys[0].NotAfter.IsZero() {
		t.Fatalf("first key must be the current one: %+v", keys)
	}
}
