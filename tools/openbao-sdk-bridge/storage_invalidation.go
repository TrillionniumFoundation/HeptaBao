package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/plugin/pb"
	"golang.org/x/sys/unix"
)

const storageInvalidationControl = "storage_key_v1"
const maximumInvalidationKeys = 256
const maximumInvalidationKeyBytes = 64 * 1024

// Control frames have their own schema, including duplicate-field rejection.
// They never decode a logical response or carry caller/storage authority.
func decodeInvalidationControl(raw []byte) (message, error) {
	if len(raw) > maximumFrame {
		return message{}, errors.New("invalidation frame bound")
	}
	decoder := json.NewDecoder(bytesReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return message{}, errors.New("invalid invalidation control")
	}
	var m message
	seen := make(map[string]bool, 6)
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return message{}, errors.New("duplicate or invalid control field")
		}
		seen[name] = true
		switch name {
		case "version":
			err = decoder.Decode(&m.Version)
		case "kind":
			err = decoder.Decode(&m.Kind)
		case "call":
			err = decoder.Decode(&m.Call)
		case "control":
			err = decoder.Decode(&m.Control)
		case "keys":
			err = decoder.Decode(&m.Keys)
		case "deadline_monotonic_ns":
			err = decoder.Decode(&m.DeadlineMonotonicNS)
		default:
			return message{}, errors.New("unknown control field")
		}
		if err != nil {
			return message{}, errors.New("invalid control field type")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || len(seen) != 6 || m.Version != version || m.Kind != "invalidate" || m.Call == 0 || m.Control != storageInvalidationControl || m.DeadlineMonotonicNS == 0 || !validInvalidationKeys(m.Keys) {
		return message{}, errors.New("invalid invalidation control")
	}
	if _, err := monotonicRemaining(m.DeadlineMonotonicNS); err != nil {
		return message{}, err
	}
	return m, nil
}

func monotonicNanoseconds() (uint64, error) {
	var stamp unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &stamp) != nil || stamp.Sec < 0 || stamp.Nsec < 0 || stamp.Nsec >= 1000000000 || uint64(stamp.Sec) > (^uint64(0)-uint64(stamp.Nsec))/1000000000 {
		return 0, errors.New("monotonic clock unavailable")
	}
	return uint64(stamp.Sec)*1000000000 + uint64(stamp.Nsec), nil
}
func monotonicRemaining(deadline uint64) (time.Duration, error) {
	now, err := monotonicNanoseconds()
	if err != nil {
		return 0, err
	}
	if deadline <= now || deadline-now > uint64(30*time.Second) {
		return 0, errors.New("invalidation deadline expired or unbounded")
	}
	return time.Duration(deadline - now), nil
}
func (w *wire) ownerContextMonotonic(deadline uint64) (context.Context, context.CancelFunc, error) {
	// Capture the Go monotonic time before reading CLOCK_MONOTONIC. Mapping
	// the remaining interval to this earlier point is conservative and NTP does
	// not affect the resulting context deadline. IPC delay is already consumed.
	goNow := time.Now()
	remaining, err := monotonicRemaining(deadline)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), goNow.Add(remaining))
	w.cancelOnOwnerClosed(ctx, cancel)
	return ctx, cancel, nil
}

func validInvalidationKeys(keys []string) bool {
	if len(keys) == 0 || len(keys) > maximumInvalidationKeys {
		return false
	}
	bytes := 0
	for index, key := range keys {
		if len(key) == 0 || len(key) > 4096 || strings.ContainsRune(key, 0) || index > 0 && keys[index-1] >= key {
			return false
		}
		bytes += len(key)
		if bytes > maximumInvalidationKeyBytes {
			return false
		}
	}
	return true
}

// The official SDK server invokes backend.InvalidateKey before returning Empty.
// Its logical.Backend client wrapper discards the RPC error, so use this same
// enrolled connection's typed client instead. A failed/late RPC never acks.
func invalidateStorageKeys(ctx context.Context, backend pb.BackendClient, keys []string, ownerClosed <-chan struct{}) error {
	if !validInvalidationKeys(keys) {
		return errors.New("invalid storage keys")
	}
	for _, key := range keys {
		if err := invalidationOwnerLive(ctx, ownerClosed); err != nil {
			return err
		}
		reply, err := backend.InvalidateKey(ctx, &pb.InvalidateKeyArgs{Key: key})
		if err != nil {
			return errors.New("SDK storage invalidation RPC failed")
		}
		if reply == nil {
			return errors.New("missing SDK storage invalidation receipt")
		}
		if err := invalidationOwnerLive(ctx, ownerClosed); err != nil {
			return err
		}
	}
	return nil
}

func invalidationOwnerLive(ctx context.Context, ownerClosed <-chan struct{}) error {
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ownerClosed:
		return errors.New("invalidation owner closed")
	default:
		return nil
	}
}

func (w *wire) sendInvalidationAck(ctx context.Context, call uint64, count int) error {
	// A distinct exact schema has no response, Auth, Secret or Storage fields.
	ack := struct {
		Version int    `json:"version"`
		Kind    string `json:"kind"`
		Call    uint64 `json:"call"`
		Control string `json:"control"`
		Count   int    `json:"count"`
	}{version, "invalidation_ack", call, storageInvalidationControl, count}
	w.writes.Lock()
	defer w.writes.Unlock()
	if err := invalidationOwnerLive(ctx, w.failed); err != nil {
		return err
	}
	raw, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(raw, '\n'))
	return err
}
