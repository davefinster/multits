package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestWaitForFileThere(t *testing.T) {
	p := filepath.Join(t.TempDir(), "multits.yaml")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := waitForFile(context.Background(), p, 0, time.Millisecond, quiet); err != nil {
		t.Fatal(err)
	}
}

// The file and the directory it is in appear later, as a sidecar's copy
// does.
func TestWaitForFileAppears(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "flyscale", "vultr", "node")
	p := filepath.Join(dir, "multits.yaml")
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(p, []byte("x"), 0o644)
	}()
	start := time.Now()
	if err := waitForFile(context.Background(), p, 5*time.Second, 5*time.Millisecond, quiet); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("returned before the file was there")
	}
}

func TestWaitForFileLimit(t *testing.T) {
	err := waitForFile(context.Background(), filepath.Join(t.TempDir(), "never"), 30*time.Millisecond, 5*time.Millisecond, quiet)
	if err == nil || !strings.Contains(err.Error(), "no such file after") {
		t.Errorf("err %v", err)
	}
}

// SIGTERM, as the context, ends the wait at once.
func TestWaitForFileCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	err := waitForFile(ctx, filepath.Join(t.TempDir(), "never"), 0, 5*time.Millisecond, quiet)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// A path through a file is not something that will appear.
func TestWaitForFileNotADirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := waitForFile(context.Background(), filepath.Join(f, "multits.yaml"), 0, time.Millisecond, quiet); err == nil {
		t.Error("waited on a path through a file")
	}
	if time.Since(start) > time.Second {
		t.Error("it waited")
	}
}
