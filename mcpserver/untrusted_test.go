package mcpserver

import (
	"context"
	"strings"
	"testing"
)

func TestResultsAreMarkedUntrusted(t *testing.T) {
	cs := connect(t, &HTTPBackend{BaseURL: "http://127.0.0.1:1", Token: "tok"})
	if !strings.Contains(cs.InitializeResult().Instructions, untrustedNote) {
		t.Error("the server instructions do not carry the note")
	}
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if tl.Name != "get_test_address" && !strings.Contains(tl.Description, untrustedNote) {
			t.Errorf("%s does not carry the note", tl.Name)
		}
	}
}
