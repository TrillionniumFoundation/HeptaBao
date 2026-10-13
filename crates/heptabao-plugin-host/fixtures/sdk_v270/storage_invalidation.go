package main

import (
	"context"
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
