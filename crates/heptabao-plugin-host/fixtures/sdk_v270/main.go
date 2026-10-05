// A genuine OpenBao SDK backend and its official go-plugin host probe.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
	sdkplugin "github.com/openbao/openbao/sdk/v2/plugin"
)

func factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	backend := &framework.Backend{
		BackendType: logical.TypeLogical, RunningVersion: "v0.0.1",
		Paths: []*framework.Path{{Pattern: "item", Fields: map[string]*framework.FieldSchema{"value": {Type: framework.TypeString}}, Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
				entry, err := request.Storage.Get(ctx, "item")
				if err != nil || entry == nil {
					return nil, err
				}
				return &logical.Response{Data: map[string]any{"value": string(entry.Value), "backend": "genuine-sdk-v2.7.0"}}, nil
			},
			logical.UpdateOperation: func(ctx context.Context, request *logical.Request, fields *framework.FieldData) (*logical.Response, error) {
				value := fields.Get("value").(string)
				return nil, request.Storage.Put(ctx, &logical.StorageEntry{Key: "item", Value: []byte(value)})
			},
			logical.DeleteOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
				return nil, request.Storage.Delete(ctx, "item")
			},
		}}},
	}
	backend.Paths = append(backend.Paths, &framework.Path{Pattern: "parallel", Callbacks: map[logical.Operation]framework.OperationFunc{
		logical.UpdateOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
			var workers sync.WaitGroup
			failures := make(chan error, 16)
			for index := 0; index < 16; index++ {
				workers.Add(1)
				go func(index int) {
					defer workers.Done()
					key := fmt.Sprintf("parallel/%02d", index)
					value := fmt.Sprintf("worker-%02d", index)
					if err := request.Storage.Put(ctx, &logical.StorageEntry{Key: key, Value: []byte(value)}); err != nil {
						failures <- err
						return
					}
					entry, err := request.Storage.Get(ctx, key)
					if err != nil {
						failures <- err
						return
					}
					if entry == nil || string(entry.Value) != value {
						failures <- errors.New("parallel real storage value mismatch")
					}
				}(index)
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				return nil, err
			}
			return &logical.Response{Data: map[string]any{"workers": 16}}, nil
		},
		logical.ReadOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
			keys, err := request.Storage.List(ctx, "parallel/")
			if err != nil {
				return nil, err
			}
			page, err := request.Storage.ListPage(ctx, "parallel/", "", 7)
			if err != nil {
				return nil, err
			}
			next, err := request.Storage.ListPage(ctx, "parallel/", "06", 7)
			if err != nil {
				return nil, err
			}
			return &logical.Response{Data: map[string]any{"keys": keys, "page": page, "next": next}}, nil
		},
		logical.DeleteOperation: func(ctx context.Context, request *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
			var workers sync.WaitGroup
			failures := make(chan error, 16)
			for index := 0; index < 16; index++ {
				workers.Add(1)
				go func(index int) {
					defer workers.Done()
					if err := request.Storage.Delete(ctx, fmt.Sprintf("parallel/%02d", index)); err != nil {
						failures <- err
					}
				}(index)
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				return nil, err
			}
			return nil, nil
		},
	}})
	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}
	return backend, nil
}

func save(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(append(raw, '\n'))
	if err == nil {
		err = file.Sync()
	}
	closed := file.Close()
	if err != nil {
		return err
	}
	return closed
}

func main() {
	serve := flag.Bool("serve", false, "serve the genuine SDK backend")
	out := flag.String("out", "", "fresh private probe directory")
	flag.Parse()
	if *serve {
		if err := sdkplugin.Serve(&sdkplugin.ServeOpts{BackendFactoryFunc: factory}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *out == "" {
		panic("fresh output required")
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		panic(err)
	}
	log, err := os.OpenFile(filepath.Join(*out, "host-and-plugin-log.private.original"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer log.Close()
	logger := hclog.New(&hclog.LoggerOptions{Level: hclog.Trace, Output: log, JSONFormat: true})
	command := exec.Command(os.Args[0], "--serve")
	command.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + *out, "PLUGIN_UNIX_SOCKET_DIR=" + *out}
	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  sdkplugin.HandshakeConfig,
		VersionedPlugins: map[int]goplugin.PluginSet{5: {"backend": &sdkplugin.GRPCBackendPlugin{}}},
		Cmd:              command, AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC}, AutoMTLS: true,
		Logger: logger, StartTimeout: 15 * time.Second,
	})
	defer client.Kill()
	checks := []string{}
	started := time.Now()
	problem := ""
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func() error {
		rpc, err := client.Client()
		if err != nil {
			return err
		}
		checks = append(checks, "actual-owned-SDK-process-and-AutoMTLS-gRPC")
		dispensed, err := rpc.Dispense("backend")
		if err != nil {
			return err
		}
		backend, ok := dispensed.(logical.Backend)
		if !ok {
			return errors.New("actual logical.Backend interface missing")
		}
		checks = append(checks, "actual-official-Backend-Dispense")
		storage := &logical.InmemStorage{}
		if err = backend.Setup(ctx, &logical.BackendConfig{StorageView: storage, System: &logical.StaticSystemView{}, Logger: logger, Config: map[string]string{"plugin_name": "sdk-storage"}}); err != nil {
			return err
		}
		defer backend.Cleanup(ctx)
		checks = append(checks, "actual-Setup-with-brokered-storage-and-system-view")
		if backend.Type() != logical.TypeLogical {
			return errors.New("wrong logical backend type")
		}
		checks = append(checks, "actual-Backend-Type")
		response, err := backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "item", Storage: storage})
		if err != nil || response != nil {
			return errors.New("missing plugin value did not return nil")
		}
		checks = append(checks, "actual-Read-before-write")
		_, err = backend.HandleRequest(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "item", Storage: storage, Data: map[string]any{"value": "genuine-brokered-storage"}})
		if err != nil {
			return err
		}
		entry, err := storage.Get(ctx, "item")
		if err != nil || entry == nil || string(entry.Value) != "genuine-brokered-storage" {
			return errors.New("plugin write did not reach actual host-owned storage")
		}
		checks = append(checks, "actual-Update-crosses-gRPC-broker-to-host-storage")
		response, err = backend.HandleRequest(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "item", Storage: storage})
		if err != nil || response == nil || response.Data["value"] != "genuine-brokered-storage" || response.Data["backend"] != "genuine-sdk-v2.7.0" {
			return errors.New("plugin read did not preserve stored value")
		}
		checks = append(checks, "actual-Read-through-Backend-gRPC")
		_, err = backend.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "item", Storage: storage})
		if err != nil {
			return err
		}
		entry, err = storage.Get(ctx, "item")
		if err != nil || entry != nil {
			return errors.New("plugin delete did not reach actual host storage")
		}
		checks = append(checks, "actual-Delete-crosses-gRPC-broker-to-host-storage")
		return nil
	}
	if err = run(); err != nil {
		problem = err.Error()
	}
	client.Kill()
	log.Sync()
	info, _ := debug.ReadBuildInfo()
	result := map[string]any{"SDK_module": "github.com/openbao/openbao/sdk/v2@v2.7.0", "build_info": info, "checks": checks, "passed": problem == "" && len(checks) == 8, "error": problem, "elapsed_seconds": time.Since(started).Seconds(), "official_SDK_and_go_plugin_process_scope_only": true, "HeptaBao_plugin_ABI_qualified": false, "full_OpenBao_replacement": false}
	if err = save(filepath.Join(*out, "SDK-plugin-probe-result.original.json"), result); err != nil {
		panic(err)
	}
	fmt.Printf("official-SDK-plugin checks=%d passed=%v\n", len(checks), problem == "" && len(checks) == 8)
	if problem != "" || len(checks) != 8 {
		os.Exit(1)
	}
}
