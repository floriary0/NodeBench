package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteStateUsesPrivatePermissions(t *testing.T) {
	root := t.TempDir()
	current := "performance"
	err := WriteState(root, State{
		ReportID: "nb_test_state_1234", Status: "running",
		CurrentModule: &current, Completed: 1, Total: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "nb_test_state_1234", "state.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != "running" || state.Completed != 1 || state.UpdatedAt.IsZero() {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestLatestStateAndPathValidation(t *testing.T) {
	root := t.TempDir()
	if err := WriteState(root, State{ReportID: "nb_first_state", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(root, State{ReportID: "nb_second_state", Status: "uploaded"}); err != nil {
		t.Fatal(err)
	}
	state, err := LatestState(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.ReportID != "nb_second_state" {
		t.Fatalf("latest report = %q", state.ReportID)
	}
	if _, err := ReadState(root, "../state"); err == nil {
		t.Fatal("path traversal report id accepted")
	}
}
