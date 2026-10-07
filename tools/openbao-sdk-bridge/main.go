// The internal host protocol is separate from the unchanged OpenBao SDK ABI.
// SDK plugin transport, AutoMTLS and storage brokers use the official SDK.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/logical"
	sdkplugin "github.com/openbao/openbao/sdk/v2/plugin"
)

const version = 1
const maximumFrame = 1024 * 1024

type entry struct {
	Key      string `json:"key"`
	ValueHex string `json:"value_hex"`
	SealWrap bool   `json:"seal_wrap"`
}
type ownedImage struct {
	FD     int    `json:"fd"`
	Role   string `json:"role"`
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type message struct {
	OwnedImages       []ownedImage      `json:"owned_images,omitempty"`
	Version           int               `json:"version"`
	Kind              string            `json:"kind"`
	Call              uint64            `json:"call"`
	RPC               uint64            `json:"rpc,omitempty"`
	Plugin            string            `json:"plugin,omitempty"`
	Args              []string          `json:"args,omitempty"`
	SocketDir         string            `json:"socket_dir,omitempty"`
	TimeoutMS         int64             `json:"timeout_ms,omitempty"`
	DefaultTTLSeconds int64             `json:"default_ttl_seconds,omitempty"`
	MaxTTLSeconds     int64             `json:"max_ttl_seconds,omitempty"`
	Operation         string            `json:"operation,omitempty"`
	Path              string            `json:"path,omitempty"`
	Data              map[string]any    `json:"data,omitempty"`
	Secret            *logical.Secret   `json:"secret,omitempty"`
	Auth              *logical.Auth     `json:"auth,omitempty"`
	IssueTimeNS       int64             `json:"issue_time_ns,omitempty"`
	IncrementNS       int64             `json:"increment_ns,omitempty"`
	Method            string            `json:"method,omitempty"`
	Key               string            `json:"key,omitempty"`
	After             string            `json:"after,omitempty"`
	Limit             int               `json:"limit,omitempty"`
	Entry             *entry            `json:"entry,omitempty"`
	Keys              []string          `json:"keys,omitempty"`
	Response          *logical.Response `json:"response"`
	Error             string            `json:"error,omitempty"`
	BackendType       string            `json:"backend_type,omitempty"`
	AuthPaths         *logical.Paths    `json:"auth_paths"`
}
type wire struct {
	writes    sync.Mutex
	pendingMu sync.Mutex
	pending   map[uint64]chan message
	requests  chan message
	failed    chan struct{}
	next      atomic.Uint64
	active    atomic.Uint64
}

func newWire() *wire {
	w := &wire{pending: make(map[uint64]chan message), requests: make(chan message, 1), failed: make(chan struct{})}
	go func() {
		defer close(w.failed)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), maximumFrame+1)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(raw) > maximumFrame {
				return
			}
			var m message
			decoder := json.NewDecoder(bufio.NewReaderSize(bytesReader(raw), len(raw)+1))
			decoder.UseNumber()
			decoder.DisallowUnknownFields()
			if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Version != version || m.Call == 0 {
				return
			}
			switch m.Kind {
			case "storage_reply":
				w.pendingMu.Lock()
				ch := w.pending[m.RPC]
				w.pendingMu.Unlock()
				if ch == nil {
					return
				}
				select {
				case ch <- m:
				default:
					return
				}
			case "setup", "request", "close":
				select {
				case w.requests <- m:
				default:
					return
				}
			default:
				return
			}
		}
	}()
	return w
}

// A tiny immutable reader avoids retaining a scanner-owned byte slice.
type reader struct {
	data     []byte
	position int
}

func bytesReader(data []byte) *reader { return &reader{data: append([]byte(nil), data...)} }
func (r *reader) Read(out []byte) (int, error) {
	if r.position == len(r.data) {
		return 0, io.EOF
	}
	n := copy(out, r.data[r.position:])
	r.position += n
	return n, nil
}
func (w *wire) send(m message) error {
	w.writes.Lock()
	defer w.writes.Unlock()
	return w.sendLocked(m)
}

// Caller owns writes, including assignment of a storage RPC sequence number.
func (w *wire) sendLocked(m message) error {
	m.Version = version
	data, err := json.Marshal(m)
	if err != nil || len(data) > maximumFrame {
		return errors.New("frame encoding or bound")
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}
func (w *wire) nextRequest() (message, error) {
	select {
	case m := <-w.requests:
		return m, nil
	case <-w.failed:
		return message{}, errors.New("host protocol closed")
	}
}
func (w *wire) storage(ctx context.Context, m message) (message, error) {
	w.writes.Lock()
	m.Call = w.active.Load()
	if m.Call == 0 {
		w.writes.Unlock()
		return message{}, errors.New("storage outside active call")
	}
	m.Kind = "storage"
	m.RPC = w.next.Add(1)
	ch := make(chan message, 1)
	w.pendingMu.Lock()
	w.pending[m.RPC] = ch
	w.pendingMu.Unlock()
	defer func() { w.pendingMu.Lock(); delete(w.pending, m.RPC); w.pendingMu.Unlock() }()
	err := w.sendLocked(m)
	w.writes.Unlock()
	if err != nil {
		return message{}, err
	}
	select {
	case reply := <-ch:
		if reply.Call != m.Call || reply.RPC != m.RPC || reply.Kind != "storage_reply" {
			return message{}, errors.New("storage reply binding")
		}
		if reply.Error != "" {
			return message{}, errors.New(reply.Error)
		}
		return reply, nil
	case <-ctx.Done():
		return message{}, ctx.Err()
	case <-w.failed:
		return message{}, errors.New("host storage disconnected")
	}
}

type storage struct{ w *wire }

func (s *storage) List(ctx context.Context, key string) ([]string, error) {
	r, e := s.w.storage(ctx, message{Method: "list", Key: key})
	return r.Keys, e
}
func (s *storage) ListPage(ctx context.Context, key, after string, limit int) ([]string, error) {
	r, e := s.w.storage(ctx, message{Method: "list_page", Key: key, After: after, Limit: limit})
	return r.Keys, e
}
func (s *storage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	r, e := s.w.storage(ctx, message{Method: "get", Key: key})
	if e != nil || r.Entry == nil {
		return nil, e
	}
	if r.Entry.Key != key {
		return nil, errors.New("storage entry key mismatch")
	}
	v, e := hex.DecodeString(r.Entry.ValueHex)
	if e != nil {
		return nil, e
	}
	return &logical.StorageEntry{Key: key, Value: v, SealWrap: r.Entry.SealWrap}, nil
}
func (s *storage) Put(ctx context.Context, e *logical.StorageEntry) error {
	if e == nil {
		return errors.New("nil entry")
	}
	_, err := s.w.storage(ctx, message{Method: "put", Key: e.Key, Entry: &entry{Key: e.Key, ValueHex: hex.EncodeToString(e.Value), SealWrap: e.SealWrap}})
	return err
}
func (s *storage) Delete(ctx context.Context, key string) error {
	_, e := s.w.storage(ctx, message{Method: "delete", Key: key})
	return e
}

// The same owner EOF cancels every outstanding SDK request. No fresh caller
// authority or storage acknowledgement is created by this cancellation.
func (w *wire) ownerContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-w.failed:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func run() (outcome error) {
	admit, cleanup, err := bindLaunchOwnedImages()
	if err != nil {
		return err
	}
	// Original inherited file ownership is held before waiting for any setup.
	defer func() { outcome = errors.Join(outcome, cleanup()) }()
	if len(os.Getenv("HBP_SDK_OWNED_IMAGES")) > 0 {
		if _, err = fmt.Fprintln(os.Stderr, "HBP_SDK_DARWIN_OWNERSHIP_BOUND_V1"); err != nil {
			return err
		}
	}
	w := newWire()
	first, err := w.nextRequest()
	if err != nil {
		return err
	}
	if first.Kind != "setup" || first.Call != 1 || first.Plugin == "" || first.SocketDir == "" || first.TimeoutMS <= 0 || first.TimeoutMS > 30000 || first.DefaultTTLSeconds < 0 || first.MaxTTLSeconds < first.DefaultTTLSeconds {
		return errors.New("invalid setup")
	}
	// Old secret-only callers omit this field. Auth must be explicitly admitted.
	if first.BackendType == "" {
		first.BackendType = "secret"
	}
	if first.BackendType != "secret" && first.BackendType != "auth" {
		return errors.New("invalid admitted SDK backend family")
	}
	if err = admit(first); err != nil {
		return err
	}

	timeout := time.Duration(first.TimeoutMS) * time.Millisecond
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Trace, Output: os.Stderr, JSONFormat: true})
	command := exec.Command(first.Plugin, first.Args...)
	bindPluginOwner(command)
	command.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + first.SocketDir, "PLUGIN_UNIX_SOCKET_DIR=" + first.SocketDir}
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  sdkplugin.HandshakeConfig,
		VersionedPlugins: map[int]goplugin.PluginSet{5: {"backend": &sdkplugin.GRPCBackendPlugin{}}},
		Cmd:              command, AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC}, AutoMTLS: true,
		Logger: logger, StartTimeout: timeout,
	})
	defer client.Kill()
	// Start owns its lock through negotiation. Kill observes that same client;
	// the post-Start EOF gate also covers EOF arriving before its runner exists.
	go func() { <-w.failed; client.Kill() }()
	rpc, err := client.Client()
	if err != nil {
		return err
	}
	select {
	case <-w.failed:
		return io.EOF
	default:
	}
	raw, err := rpc.Dispense("backend")
	if err != nil {
		return err
	}
	backend, ok := raw.(logical.Backend)
	if !ok {
		return errors.New("missing SDK backend")
	}
	actualType := ""
	hostStorage := &storage{w: w}
	ctx, cancel := w.ownerContext(timeout)
	w.active.Store(first.Call)
	err = backend.Setup(ctx, &logical.BackendConfig{StorageView: hostStorage, System: &logical.StaticSystemView{DefaultLeaseTTLVal: time.Duration(first.DefaultTTLSeconds) * time.Second, MaxLeaseTTLVal: time.Duration(first.MaxTTLSeconds) * time.Second}, Logger: logger, Config: map[string]string{"plugin_name": "heptabao-sdk-backend"}})
	if err == nil {
		switch backend.Type() {
		case logical.TypeLogical:
			actualType = "secret"
		case logical.TypeCredential:
			actualType = "auth"
		default:
			return errors.New("unsupported actual SDK backend family")
		}
		if actualType != first.BackendType {
			return errors.New("actual SDK backend family differs from admitted catalog family")
		}
		err = backend.Initialize(ctx, &logical.InitializationRequest{Storage: hostStorage})
	}
	w.active.Store(0)
	cancel()
	if err != nil {
		return err
	}
	var authPaths *logical.Paths
	if actualType == "auth" {
		authPaths = backend.SpecialPaths()
	}
	if err = w.send(message{Kind: "ready", Call: 1, BackendType: actualType, AuthPaths: authPaths}); err != nil {
		return err
	}
	last := uint64(1)
	for {
		m, err := w.nextRequest()
		if err != nil {
			return err
		}
		if m.Call != last+1 {
			return errors.New("call sequence")
		}
		last = m.Call
		if m.Kind == "close" {
			ctx, cancel := w.ownerContext(timeout)
			w.active.Store(m.Call)
			backend.Cleanup(ctx)
			w.active.Store(0)
			cancel()
			client.Kill()
			return w.send(message{Kind: "closed", Call: m.Call})
		}
		if m.Kind != "request" || m.Plugin != "" || m.SocketDir != "" || m.Path == "" {
			return errors.New("invalid request")
		}
		switch logical.Operation(m.Operation) {
		case logical.ReadOperation, logical.UpdateOperation, logical.CreateOperation, logical.DeleteOperation, logical.ListOperation, logical.ScanOperation, logical.PatchOperation:
			if m.Secret != nil || m.Auth != nil || m.IssueTimeNS != 0 || m.IncrementNS != 0 {
				return errors.New("lease metadata on ordinary operation")
			}
		case logical.RenewOperation, logical.RevokeOperation:
			if m.IssueTimeNS <= 0 || m.IncrementNS < 0 {
				return errors.New("missing original issuer metadata")
			}
			if m.Auth != nil {
				if actualType != "auth" || m.Operation != string(logical.RenewOperation) || m.Secret != nil {
					return errors.New("auth callback family mismatch")
				}
				m.Auth.IssueTime = time.Unix(0, m.IssueTimeNS).UTC()
				m.Auth.Increment = time.Duration(m.IncrementNS)
				m.Auth.ClientToken = ""
			} else {
				// Registered Secret callbacks belong to either verified backend family.
				// The Service retains their original typed registration owner.
				if m.Secret == nil || m.Secret.InternalData == nil {
					return errors.New("missing registered secret lease metadata")
				}
				m.Secret.IssueTime = time.Unix(0, m.IssueTimeNS).UTC()
				m.Secret.Increment = time.Duration(m.IncrementNS)
				m.Secret.LeaseID = ""
			}
		default:
			return errors.New("operation outside first bridge")
		}
		ctx, cancel := w.ownerContext(timeout)
		w.active.Store(m.Call)
		response, problem := backend.HandleRequest(ctx, &logical.Request{Operation: logical.Operation(m.Operation), Path: m.Path, Data: m.Data, Secret: m.Secret, Auth: m.Auth, Storage: hostStorage})
		w.active.Store(0)
		cancel()
		result := message{Kind: "result", Call: m.Call, Response: response}
		if problem != nil {
			result.Error = problem.Error()
		}
		if err = w.send(result); err != nil {
			return err
		}
	}
}
func main() {
	// A closed owner pipe must return EPIPE through run's owned terminal cleanup.
	// Go otherwise exits on SIGPIPE for stdout/stderr without executing defers.
	signal.Ignore(syscall.SIGPIPE)
	// Linux parent-death follows the thread that starts the plugin. Retain
	// this ownership thread for the complete companion/plugin lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
