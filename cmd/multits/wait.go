package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// waitForFile returns once path exists, waiting while it does not.
//
// A gateway's configuration is often written by something that starts
// beside it -- a configjfs sidecar filling a volume, a node's copy synced
// after a reboot -- and a gateway that exited because it came first would
// only be restarted, with backoff, to find it there. So a missing file, or a
// missing directory on its way, is something to wait out. Anything else
// stat says is the error it would be when loading: a permission, or a path
// through a file.
//
// limit bounds the wait, zero meaning none. It logs once when it starts to
// wait, every minute it goes on, and when the file appears.
func waitForFile(ctx context.Context, path string, limit, poll time.Duration, log *slog.Logger) error {
	start := time.Now()
	nextLog := time.Time{}
	for {
		_, err := os.Stat(path)
		if err == nil {
			if !nextLog.IsZero() {
				log.Info("Configuration file is there", "path", path, "waited", time.Since(start).Round(time.Second).String())
			}
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if limit > 0 && time.Since(start) >= limit {
			return fmt.Errorf("%s: no such file after %v", path, limit)
		}
		if now := time.Now(); now.After(nextLog) {
			if nextLog.IsZero() {
				log.Info("Waiting for the configuration file", "path", path)
			} else {
				log.Info("Still waiting for the configuration file", "path", path, "waited", time.Since(start).Round(time.Second).String())
			}
			nextLog = now.Add(time.Minute)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", path, ctx.Err())
		case <-time.After(poll):
		}
	}
}
