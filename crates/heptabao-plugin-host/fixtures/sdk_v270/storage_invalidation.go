package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// This cache is deliberately stale after an out-of-band host storage change.
// Only the genuine framework InvalidateKey hook clears it in the live process.
func configureStorageInvalidation(backend *framework.Backend, config *logical.BackendConfig) {
	var mu sync.Mutex
	var cached string
	var filled bool
	count := 0
	storageDenied := false
	backend.Invalidate = func(ctx context.Context, key string) {
		if key == "deadline-blocked" {
			_ = recordFixtureEvent("invalidation_hook_entered")
			<-ctx.Done()
			return
		}
		denied := false
		if key == "storage-attempt" {
			denied = config.StorageView.Put(ctx, &logical.StorageEntry{Key: "invalidation-mutation", Value: []byte("must-not-commit")}) != nil
		}
		mu.Lock()
		defer mu.Unlock()
		count++
		if key == "item" {
			filled = false
		}
		if key == "storage-attempt" {
			storageDenied = denied
		}
	}
	// Only finite qualification keys are exposed by this genuine SDK fixture.
	backend.Paths = append(backend.Paths, &framework.Path{
		Pattern: "invalidation-control/(?P<key>deadline-blocked|storage-attempt|owner-death|invalidation-mutation)",
		Fields: map[string]*framework.FieldSchema{
			"key": {Type: framework.TypeString}, "value": {Type: framework.TypeString},
		}, Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: func(ctx context.Context, request *logical.Request, fields *framework.FieldData) (*logical.Response, error) {
				entry, err := request.Storage.Get(ctx, fields.Get("key").(string))
				if err != nil || entry == nil {
					return nil, err
				}
				return &logical.Response{Data: map[string]any{"value": string(entry.Value)}}, nil
			},
			logical.UpdateOperation: func(ctx context.Context, request *logical.Request, fields *framework.FieldData) (*logical.Response, error) {
				return nil, request.Storage.Put(ctx, &logical.StorageEntry{Key: fields.Get("key").(string), Value: []byte(fields.Get("value").(string))})
			},
		},
	})
	backend.Paths = append(backend.Paths, &framework.Path{Pattern: "cached-item", Callbacks: map[logical.Operation]framework.OperationFunc{
		logical.ReadOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
			mu.Lock()
			defer mu.Unlock()
			if !filled {
				entry, err := request.Storage.Get(ctx, "item")
				if err != nil || entry == nil {
					return nil, err
				}
				cached, filled = string(entry.Value), true
			}
			return &logical.Response{Data: map[string]any{"value": cached, "invalidations": count, "storage_mutation_denied": storageDenied}}, nil
		},
	}})
}

// This fixture-only journal records no request, Storage key/value or token.
// A real SDK callback writes it only AFTER receiving its original Storage ACK.
func recordFixtureEvent(event string) error {
	directory := os.Getenv("TMPDIR")
	if directory == "" {
		return errors.New("private fixture TMPDIR absent")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private fixture directory unavailable")
	}
	path := filepath.Join(directory, "sdk-fixture-events.jsonl")
	if old, err := os.Lstat(path); err == nil && (!old.Mode().IsRegular() || old.Mode().Perm()&0077 != 0 || old.Size() > 65536) {
		return errors.New("fixture journal owner changed")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	body, err := json.Marshal(map[string]any{"event": event, "pid": os.Getpid()})
	if err != nil {
		return err
	}
	_, err = file.Write(append(body, '\n'))
	if err != nil {
		return err
	}
	return file.Sync()
}
