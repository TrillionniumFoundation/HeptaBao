package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	sdkplugin "github.com/openbao/openbao/sdk/v2/plugin"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

// This helper serves a genuine official SDK backend in a separate process.
// Cache effects below cross the official AutoMTLS gRPC server's InvalidateKey.
func TestInvalidationSDKPluginProcess(t *testing.T) {
	if os.Getenv("HBP_TEST_INVALIDATION_PLUGIN") != "1" {
		t.Skip("child process helper")
	}
	factory := func(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
		var mu sync.Mutex
		var cached string
		var filled bool
		var invalidated []string
		backend := &framework.Backend{BackendType: logical.TypeLogical}
		backend.Invalidate = func(ctx context.Context, key string) {
			if key == "hold" {
				<-ctx.Done()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			invalidated = append(invalidated, key)
			if key == "cache" {
				filled = false
			}
		}
		backend.Paths = []*framework.Path{{Pattern: "cache", Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if !filled {
					entry, err := request.Storage.Get(ctx, "cache")
					if err != nil || entry == nil {
						return nil, err
					}
					cached, filled = string(entry.Value), true
				}
				return &logical.Response{Data: map[string]any{"value": cached, "invalidated": append([]string(nil), invalidated...)}}, nil
			},
		}}}
		return backend, backend.Setup(ctx, config)
	}
	if err := sdkplugin.Serve(&sdkplugin.ServeOpts{BackendFactoryFunc: factory}); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestActualSDKTypedInvalidationClearsCacheAndPreservesFailures(t *testing.T) {
	dir, err := os.MkdirTemp("", "hb-sdk-inv-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	logger := hclog.New(&hclog.LoggerOptions{Output: io.Discard})
	command := exec.Command(os.Args[0], "-test.run=^TestInvalidationSDKPluginProcess$")
	command.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + dir, "PLUGIN_UNIX_SOCKET_DIR=" + dir, "HBP_TEST_INVALIDATION_PLUGIN=1"}
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  sdkplugin.HandshakeConfig,
		VersionedPlugins: map[int]goplugin.PluginSet{5: {"backend": &sdkplugin.GRPCBackendPlugin{}}},
		Cmd:              command, AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC}, AutoMTLS: true,
		Logger: logger, StartTimeout: 10 * time.Second,
	})
	defer client.Kill()
	protocol, err := client.Client()
	if err != nil {
		t.Fatal(err)
	}
	grpcClient, ok := protocol.(*goplugin.GRPCClient)
	if !ok || grpcClient.Conn == nil {
		t.Fatal("missing actual AutoMTLS connection")
	}
	raw, err := protocol.Dispense("backend")
	if err != nil {
		t.Fatal(err)
	}
	backend := raw.(logical.Backend)
	store := &logical.InmemStorage{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = backend.Setup(ctx, &logical.BackendConfig{StorageView: store, System: &logical.StaticSystemView{}, Logger: logger}); err != nil {
		t.Fatal(err)
	}
	if err = backend.Initialize(ctx, &logical.InitializationRequest{Storage: store}); err != nil {
		t.Fatal(err)
	}
	put := func(value string) {
		t.Helper()
		if err := store.Put(ctx, &logical.StorageEntry{Key: "cache", Value: []byte(value)}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want string, keys []string) {
		t.Helper()
		response, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "cache", Storage: store})
		if err != nil || response == nil || response.Data["value"] != want {
			t.Fatalf("actual cache read failed: %v", err)
		}
		raw, _ := json.Marshal(response.Data["invalidated"])
		var actual []string
		if json.Unmarshal(raw, &actual) != nil || !reflect.DeepEqual(actual, keys) {
			t.Fatal("actual SDK hook sequence differs")
		}
	}
	put("old")
	read("old", nil)
	put("committed-new")
	read("old", nil)
	typed := pb.NewBackendClient(grpcClient.Conn)
	owner := make(chan struct{})
	if err = invalidateStorageKeys(ctx, typed, []string{"cache", "other"}, owner); err != nil {
		t.Fatal(err)
	}
	read("committed-new", []string{"cache", "other"})
	closed := make(chan struct{})
	close(closed)
	if invalidateStorageKeys(ctx, typed, []string{"cache"}, closed) == nil {
		t.Fatal("closed owner accepted")
	}
	read("committed-new", []string{"cache", "other"})
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if invalidateStorageKeys(expired, typed, []string{"cache"}, owner) == nil {
		t.Fatal("expired owner accepted")
	}
	read("committed-new", []string{"cache", "other"})
	short, stopShort := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stopShort()
	if invalidateStorageKeys(short, typed, []string{"hold"}, owner) == nil {
		t.Fatal("timed out real hook accepted")
	}
	client.Kill()
	if invalidateStorageKeys(ctx, typed, []string{"cache"}, owner) == nil {
		t.Fatal("dead real plugin transport accepted")
	}
	// Ensure this test never creates a persistent plugin fixture or credential.
	if !strings.HasPrefix(filepath.Base(dir), "hb-sdk-inv-") {
		t.Fatal("fixture ownership")
	}
}

func TestInvalidationControlRejectsAuthorityDuplicatesAndBounds(t *testing.T) {
	valid := `{"version":1,"kind":"invalidate","call":2,"control":"storage_key_v1","keys":["a","b"],"deadline_monotonic_ns":1000000000}`
	mono, err := monotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	deadline := strconv.FormatUint(mono+uint64(10*time.Second), 10)
	valid = strings.Replace(valid, "1000000000", deadline, 1)
	if _, err := decodeInvalidationControl([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"call":2`, `"call":2,"call":3`, 1),
		strings.Replace(valid, `"deadline_monotonic_ns":`, `"auth":{},"deadline_monotonic_ns":`, 1),
		strings.Replace(valid, `"deadline_monotonic_ns":`, `"response":null,"deadline_monotonic_ns":`, 1),
		strings.Replace(valid, `["a","b"]`, `["b","a"]`, 1),
		strings.Replace(valid, `["a","b"]`, `["a","a"]`, 1),
		strings.Replace(valid, `storage_key_v1`, `future`, 1),
		strings.Replace(valid, deadline, strconv.FormatUint(mono+uint64(31*time.Second), 10), 1),
		strings.Replace(valid, deadline, strconv.FormatUint(mono-uint64(time.Second), 10), 1),
		strings.Replace(valid, deadline, `0`, 1),
		strings.Replace(valid, deadline, `null`, 1),
		valid + `{}`,
	} {
		if _, err := decodeInvalidationControl([]byte(raw)); err == nil {
			t.Fatal("invalid control accepted")
		}
	}
	if validInvalidationKeys([]string{strings.Repeat("x", 4097)}) || validInvalidationKeys(nil) || validInvalidationKeys([]string{"a\x00b"}) {
		t.Fatal("invalid key bound accepted")
	}
}

func TestInvalidationIPCConsumesOriginalMonotonicDeadline(t *testing.T) {
	mono, err := monotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	w := &wire{failed: make(chan struct{})}
	deadline := mono + uint64(20*time.Millisecond)
	ctx, cancel, err := w.ownerContextMonotonic(deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	<-ctx.Done()
	time.Sleep(2 * time.Millisecond)
	if _, _, err = w.ownerContextMonotonic(deadline); err == nil {
		t.Fatal("same absolute deadline gained a fresh IPC window")
	}
}

func TestInvalidationAckCannotOutliveOwnerOrContainLogicalAuthority(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	w := &wire{failed: make(chan struct{})}
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	if w.sendInvalidationAck(expired, 2, 1) == nil {
		t.Fatal("late control acknowledged")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if w.sendInvalidationAck(ctx, 2, 1) != nil {
		t.Fatal("live control receipt failed")
	}
	close(w.failed)
	if w.sendInvalidationAck(ctx, 3, 1) == nil {
		t.Fatal("closed owner acknowledged")
	}
	writer.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if json.Unmarshal(raw, &receipt) != nil || len(receipt) != 5 || receipt["kind"] != "invalidation_ack" || receipt["control"] != storageInvalidationControl || receipt["call"] != float64(2) || receipt["count"] != float64(1) {
		t.Fatal("control receipt includes authority or an extra late receipt")
	}
}
