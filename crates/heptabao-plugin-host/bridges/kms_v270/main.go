// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
// Genuine OpenBao 2.7 KMS gRPC adapter. This is not a provider implementation.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	kmsplugin "github.com/openbao/go-kms-wrapping/plugin/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const maxFrame = 1024 * 1024

type request struct {
	Version    uint16         `json:"version"`
	Nonce      string         `json:"nonce"`
	Operation  string         `json:"operation"`
	Config     map[string]any `json:"config"`
	Key        map[string]any `json:"key"`
	Data       []byte         `json:"data"`
	AAD        []byte         `json:"aad"`
	Signature  []byte         `json:"signature"`
	Hash       string         `json:"hash"`
	Prehashed  bool           `json:"prehashed"`
	Scheme     string         `json:"scheme"`
	SaltLength int            `json:"salt_length"`
	EdContext  string         `json:"ed_context"`
	Marshaling string         `json:"marshaling"`
}

type result struct {
	SensitiveKMSFields *[]string `json:"sensitive_kms_fields,omitempty"`
	SensitiveKeyFields *[]string `json:"sensitive_key_fields,omitempty"`
	Ciphertext         *[]byte   `json:"ciphertext,omitempty"`
	Plaintext          *[]byte   `json:"plaintext,omitempty"`
	Signature          *[]byte   `json:"signature,omitempty"`
	PublicKey          *[]byte   `json:"public_key,omitempty"`
	Valid              *bool     `json:"valid,omitempty"`
	Opened             bool      `json:"opened,omitempty"`
	KeyResolved        bool      `json:"key_resolved,omitempty"`
}

type response struct {
	Version   uint16       `json:"version"`
	Nonce     string       `json:"nonce"`
	Operation string       `json:"operation"`
	Status    string       `json:"status"`
	Phase     string       `json:"phase"`
	Result    *result      `json:"result"`
	Lifecycle childReceipt `json:"lifecycle"`
}

type library struct {
	Alias  string `json:"alias"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type darwinBootstrapDeployment struct {
    Image string `json:"image"`
    ImageSHA256 string `json:"image_sha256"`
}
type deployment struct {
    DarwinBootstrap *darwinBootstrapDeployment `json:"darwin_bootstrap,omitempty"`
	Implementation deploymentImplementation `json:"implementation,omitempty"`
	Provider       string                   `json:"provider"`
	Image          string                   `json:"image"`
	ImageSHA256    string                   `json:"image_sha256"`
	Args           []string                 `json:"args"`
	Libraries      []library                `json:"libraries"`
}

// Deployment is read only from an operator-pinned regular file, never request JSON.
func loadDeployment(path, digest string) (deployment, *pinnedFile, error) {
	var d deployment
	pin, err := pinFile(path, digest, false)
	if err != nil {
		return d, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			pin.file.Close()
		}
	}()
	b, err := io.ReadAll(io.LimitReader(pin.file, maxFrame+1))
	if err != nil || len(b) > maxFrame {
		return d, nil, errors.New("deployment invalid")
	}
	defer erase(b)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF ||
		d.Provider == "" || len(d.Provider) > 128 || len(d.Args) > 64 || len(d.Libraries) > 32 {
		return deployment{}, nil, errors.New("deployment invalid")
	}
	for _, arg := range d.Args {
		if len(arg) > 4096 || bytes.IndexByte([]byte(arg), 0) >= 0 {
			return deployment{}, nil, errors.New("deployment invalid")
		}
	}
	implementation, err := implementationPolicy(d)
	if err != nil {
		return deployment{}, nil, err
	}
	d.Implementation = implementation
	if err := validatePlatformDeployment(d); err != nil { return deployment{}, nil, err }
	keep = true
	return d, pin, nil
}

func readRequest(r io.Reader) (request, error) {
	var q request
	var header [11]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return q, err
	}
	n := binary.BigEndian.Uint32(header[7:])
	if string(header[:4]) != "HBP1" || binary.BigEndian.Uint16(header[4:6]) != 1 ||
		header[6] != 1 || n == 0 || n > maxFrame {
		return q, errors.New("invalid frame")
	}
	b := make([]byte, n)
	defer erase(b)
	if _, err := io.ReadFull(r, b); err != nil {
		return q, err
	}
	var extra [1]byte
	if n, err := r.Read(extra[:]); n != 0 || err != io.EOF {
		return q, errors.New("multiple frames")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&q) != nil || dec.Decode(new(any)) != io.EOF {
		return q, errors.New("invalid request")
	}
	nonce, err := hex.DecodeString(q.Nonce)
	if err != nil || len(nonce) != 32 || q.Nonce != hex.EncodeToString(nonce) || q.Version != 1 {
		return q, errors.New("invalid request identity")
	}
	switch q.Operation {
	case "metadata", "validate_config", "validate_key", "encrypt", "decrypt", "sign", "verify", "export_public":
	default:
		return q, errors.New("invalid operation")
	}
	if q.Marshaling != "" && q.Marshaling != "asn1" && q.Marshaling != "jws" {
		return q, errors.New("invalid marshaling")
	}
	if q.Operation != "metadata" && q.Config == nil {
		return q, errors.New("missing config")
	}
	if q.Operation != "metadata" && q.Operation != "validate_config" && q.Key == nil {
		return q, errors.New("missing key")
	}
	return q, nil
}

func signerOptions(q request) (crypto.SignerOpts, error) {
	hashes := map[string]crypto.Hash{
		"none": crypto.Hash(0), "sha1": crypto.SHA1, "sha2-224": crypto.SHA224,
		"sha2-256": crypto.SHA256, "sha2-384": crypto.SHA384, "sha2-512": crypto.SHA512,
		"sha3-224": crypto.SHA3_224, "sha3-256": crypto.SHA3_256,
		"sha3-384": crypto.SHA3_384, "sha3-512": crypto.SHA3_512,
	}
	h, ok := hashes[q.Hash]
	if !ok {
		return nil, errors.New("invalid hash")
	}
	switch q.Scheme {
	case "hash":
		return h, nil
	case "pss":
		if q.SaltLength < -1 {
			return nil, errors.New("invalid salt length")
		}
		return &rsa.PSSOptions{Hash: h, SaltLength: q.SaltLength}, nil
	case "ed25519":
		return &ed25519.Options{Hash: h, Context: q.EdContext}, nil
	default:
		return nil, errors.New("invalid scheme")
	}
}

func jwsPublic(ctx context.Context, key kms.Key) (*ecdsa.PublicKey, error) {
	pub, err := key.ExportPublic(ctx)
	if err != nil {
		return nil, err
	}
	ec, _ := pub.(*ecdsa.PublicKey)
	return ec, nil
}
func jwsSignature(ctx context.Context, key kms.Key, signature []byte, encode bool) ([]byte, error) {
	ec, err := jwsPublic(ctx, key)
	if err != nil {
		return nil, err
	}
	if ec == nil {
		return signature, nil
	}
	size := (ec.Curve.Params().BitSize + 7) / 8
	if encode {
		var sig struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &sig)
		if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 ||
			sig.R.Cmp(ec.Params().N) >= 0 || sig.S.Cmp(ec.Params().N) >= 0 {
			return nil, errors.New("invalid ECDSA signature")
		}
		b := make([]byte, 2*size)
		sig.R.FillBytes(b[:size])
		sig.S.FillBytes(b[size:])
		return b, nil
	}
	if len(signature) != 2*size {
		return nil, errors.New("invalid ECDSA signature")
	}
	r, s := new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(ec.Params().N) >= 0 || s.Cmp(ec.Params().N) >= 0 {
		return nil, kms.ErrInvalidSignature
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func providerFailure(out *response, phase string, err error) {
	out.Phase = phase
	out.Result = nil
	switch {
	case errors.Is(err, kms.ErrNotImplemented):
		out.Status = "not_implemented"
	case errors.Is(err, kmsplugin.ErrPluginShutdown), errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		out.Status = "outcome_unknown"
	default:
		out.Status = "provider_error"
	}
	// Provider error strings may contain credentials. No raw errors leave this boundary.
}

func call(ctx context.Context, q request, d deployment, ownedTemp string, startTimeout time.Duration) (out response) {
	out = response{Version: 1, Nonce: q.Nonce, Operation: q.Operation, Status: "outcome_unknown", Phase: "start"}
	var owned *ownedRunner
	var rpc goplugin.ClientProtocol
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: kmsplugin.HandshakeConfig, VersionedPlugins: kmsplugin.PluginSets,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC}, AutoMTLS: true,
		SkipHostEnv: true, StartTimeout: startTimeout, Logger: hclog.NewNullLogger(),
		UnixSocketConfig: &goplugin.UnixSocketConfig{TempDir: ownedTemp},
		RunnerFunc: func(_ hclog.Logger, spec *execCmd, socketDir string) (runner.Runner, error) {
			// execCmd is the exact os/exec.Cmd alias, retaining go-plugin-generated mTLS env.
			r, err := newOwnedRunner(spec, d, socketDir, ownedTemp, ctx)
			if r != nil {
				owned = r
			} // Custody before any Start call or diagnostic.
			return r, err
		},
	})
	defer func() {
		// The original runner exists independently of client metadata/handshake success.
		// Close always obtains the same original Wait even if go-plugin's waiter never started.
		graceful := false
		if rpc != nil {
			closed := make(chan error, 1)
			go func() { closed <- rpc.Close() }()
			select {
			case err := <-closed:
				graceful = err == nil
			case <-ctx.Done():
				if owned != nil {
					_ = owned.Kill(context.Background())
				}
			}
		}
		if owned != nil {
			out.Lifecycle = owned.closeOriginal(graceful)
		}
		client.Kill()
		if !out.Lifecycle.Qualified {
			out.Status = "outcome_unknown"
			out.Phase = "shutdown"
			out.Result = nil
		}
	}()
	var err error
	rpc, err = client.Client()
	if err != nil {
		providerFailure(&out, "handshake", err)
		return
	}
	if ctx.Err() != nil {
		providerFailure(&out, "handshake", ctx.Err())
		return
	}
	if q.Operation == "metadata" {
		raw, err := rpc.Dispense("metadata")
		if err != nil {
			providerFailure(&out, "metadata", err)
			return
		}
		m, ok := raw.(kmsplugin.Metadata)
		if !ok {
			providerFailure(&out, "metadata", errors.New("metadata type"))
			return
		}
		// Empty arrays are explicit. Duplicate/Unicode field names have exact map-key semantics.
		if m.SensitiveKMSFields == nil {
			m.SensitiveKMSFields = []string{}
		}
		if m.SensitiveKeyFields == nil {
			m.SensitiveKeyFields = []string{}
		}
		out.Status = "completed"
		out.Phase = "metadata"
		out.Result = &result{SensitiveKMSFields: &m.SensitiveKMSFields, SensitiveKeyFields: &m.SensitiveKeyFields}
		return
	}
	raw, err := rpc.Dispense("kms")
	if err != nil {
		providerFailure(&out, "dispense", err)
		return
	}
	provider, ok := raw.(kms.KMS)
	if !ok {
		providerFailure(&out, "dispense", errors.New("KMS type"))
		return
	}
	if err = provider.Open(ctx, &kms.OpenOptions{ConfigMap: q.Config, AllowEnvironment: false}); err != nil {
		providerFailure(&out, "open", err)
		return
	}
	defer func() {
		// Close is required after successful Open; the original operation context is not rearmed.
		if err := provider.Close(ctx); err != nil {
			providerFailure(&out, "close", err)
		}
	}()
	if q.Operation == "validate_config" {
		out.Status = "completed"
		out.Phase = "open"
		out.Result = &result{Opened: true}
		return
	}
	key, err := provider.GetKey(ctx, &kms.KeyOptions{ConfigMap: q.Key})
	if err != nil {
		providerFailure(&out, "key", err)
		return
	}
	if key == nil {
		providerFailure(&out, "key", errors.New("nil key"))
		return
	}
	out.Result = &result{}
	out.Phase = "crypto"
	switch q.Operation {
	case "validate_key":
		out.Result.KeyResolved = true
		out.Phase = "key"
	case "encrypt":
		var b []byte
		b, err = key.Encrypt(ctx, &kms.CipherOptions{Data: q.Data, AAD: q.AAD})
		if b == nil {
			b = []byte{}
		}
		out.Result.Ciphertext = &b
	case "decrypt":
		var b []byte
		b, err = key.Decrypt(ctx, &kms.CipherOptions{Data: q.Data, AAD: q.AAD})
		if b == nil {
			b = []byte{}
		}
		out.Result.Plaintext = &b
	case "sign", "verify":
		var opts crypto.SignerOpts
		opts, err = signerOptions(q)
		if err == nil {
			if q.Operation == "sign" {
				var b []byte
				b, err = key.Sign(ctx, &kms.SignOptions{Data: q.Data, Prehashed: q.Prehashed, SignerOpts: opts})
				if err == nil && q.Marshaling == "jws" {
					b, err = jwsSignature(ctx, key, b, true)
				}
				if b == nil {
					b = []byte{}
				}
				out.Result.Signature = &b
			} else {
				signature := q.Signature
				if q.Marshaling == "jws" {
					signature, err = jwsSignature(ctx, key, q.Signature, false)
				}
				if err == nil {
					err = key.Verify(ctx, &kms.VerifyOptions{Data: q.Data, Signature: signature, Prehashed: q.Prehashed, SignerOpts: opts})
				}
				if errors.Is(err, kms.ErrInvalidSignature) {
					b := false
					out.Result.Valid = &b
					err = nil
				} else if err == nil {
					b := true
					out.Result.Valid = &b
				}
			}
		}
	case "export_public":
		var pub crypto.PublicKey
		pub, err = key.ExportPublic(ctx)
		if err == nil {
			var b []byte
			b, err = x509.MarshalPKIXPublicKey(pub)
			out.Result.PublicKey = &b
		}
	}
	if err != nil {
		providerFailure(&out, "crypto", err)
		return
	}
	out.Status = "completed"
	return
}

func erase(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func writeResponse(w io.Writer, out response) error {
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	defer erase(b)
	if len(b) == 0 || len(b) > maxFrame {
		return errors.New("response bound")
	}
	var header [8]byte
	copy(header[:4], "HBR1")
	binary.BigEndian.PutUint32(header[4:], uint32(len(b)))
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func run() int {
	deploymentPath := flag.String("deployment", os.Getenv("HEPTABAO_KMS_DEPLOYMENT"), "operator deployment file")
	deploymentSHA := flag.String("deployment-sha256", os.Getenv("HEPTABAO_KMS_DEPLOYMENT_SHA256"), "operator deployment SHA256")
	temp := flag.String("owned-temp", os.Getenv("HEPTABAO_KMS_TEMP"), "operator-owned short socket directory")
	operatorTimeout, err := strconv.ParseUint(os.Getenv("HEPTABAO_KMS_TIMEOUT_MS"), 10, 64)
	if err != nil && os.Getenv("HEPTABAO_KMS_TIMEOUT_MS") != "" {
		return 2
	}
	timeoutMS := flag.Uint64("timeout-ms", operatorTimeout, "private host-selected invocation ceiling")
	flag.Parse()
	if *timeoutMS == 0 || *timeoutMS > 3600000 || len(*temp) > 60 {
		return 2
	}
	d, operatorPin, err := loadDeployment(*deploymentPath, *deploymentSHA)
	if err != nil {
		return 2
	}
	defer operatorPin.file.Close()
	if expected := os.Getenv("HEPTABAO_KMS_PROVIDER"); expected != "" && expected != d.Provider {
		return 2
	}
	q, err := readRequest(os.Stdin)
	if err != nil {
		return 2
	}
	defer erase(q.Data)
	defer erase(q.AAD)
	defer erase(q.Signature)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	observedTime := time.Now()
	budget := time.Duration(*timeoutMS) * time.Millisecond
	if stamp := os.Getenv("HEPTABAO_KMS_DEADLINE_MONOTONIC_NS"); stamp != "" {
		absolute, e := strconv.ParseInt(stamp, 10, 64)
		now, e2 := monotonicNanos()
		if e != nil || e2 != nil || absolute <= now {
			return 2
		}
		if remaining := time.Duration(absolute - now); remaining < budget {
			budget = remaining
		}
	}
	ctx, cancelDeadline := context.WithDeadline(ctx, observedTime.Add(budget))
	defer cancelDeadline()
	out := call(ctx, q, d, *temp, time.Duration(*timeoutMS)*time.Millisecond)
	if ctx.Err() != nil || !operatorPin.unchanged() {
		out.Status = "outcome_unknown"
		out.Phase = "deadline"
		out.Result = nil
	}
	if writeResponse(os.Stdout, out) != nil {
		return 1
	}
	return 0
}
func main() {
    if handled, code := platformBootstrap(); handled { os.Exit(code) }
    os.Exit(run())
}
