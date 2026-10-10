package main

import (
	"encoding/json"
	"github.com/openbao/openbao/sdk/v2/logical"
	"strings"
	"testing"
)

func TestLogical131ActualSDKConsumerKeepsHeadersSeparateFromTokenAndNamespace(t *testing.T) {
	var m message
	if err := json.Unmarshal([]byte("{\"kind\":\"request\",\"operation\":\"update\",\"path\":\"store\",\"data\":{\"value\":\"synthetic\"},\"headers\":{\"X-Review\":[\"one\",\"two\"],\"X-Vault-Token\":[\"data-only\"]}}"), &m); err != nil {
		t.Fatal("actual IPC decode")
	}
	request, err := logicalRequestFromMessage(&m, nil)
	if err != nil {
		t.Fatal("actual SDK request construction")
	}
	if request.Operation != logical.UpdateOperation || request.Path != "store" ||
		len(request.Headers["X-Review"]) != 2 || request.Headers["X-Review"][1] != "two" ||
		request.Headers["X-Vault-Token"][0] != "data-only" ||
		request.ClientToken != "" || request.Auth != nil || request.Secret != nil ||
		request.Data["value"] != "synthetic" {
		t.Fatal("logical header/data ownership")
	}
	m.Headers["Bad Header"] = []string{"line\r\nlogical\x00value"}
	request, err = logicalRequestFromMessage(&m, nil)
	if err != nil || request.Headers["Bad Header"][0] != "line\r\nlogical\x00value" ||
		request.Headers["X-Vault-Token"][0] != "data-only" || request.ClientToken != "" ||
		request.Auth != nil || request.Secret != nil || request.Path != "store" {
		t.Fatal("logical SDK Header data was confused with HTTP line or authority")
	}
	m.Headers[""] = []string{"empty-map-name"}
	request, err = logicalRequestFromMessage(&m, nil)
	if err != nil || request.Headers[""][0] != "empty-map-name" ||
		request.ClientToken != "" || request.Auth != nil || request.Secret != nil ||
		request.Operation != logical.UpdateOperation || request.Path != "store" {
		t.Fatal("empty map header name changed logical SDK ownership")
	}
	tooMany := make(map[string][]string)
	tooLarge := make(map[string][]string)
	for i := 0; i < 65; i++ {
		tooMany[strings.Repeat("x", i+1)] = []string{}
		if i < 5 {
			tooLarge[strings.Repeat("x", i+1)] = []string{strings.Repeat("x", 16*1024)}
		}
	}
	for _, invalid := range []map[string][]string{
		{"X-Review": {strings.Repeat("x", 16*1024+1)}},
		{"X-Review": make([]string, 65)}, tooMany, tooLarge, {strings.Repeat("x", 257): {"x"}},
	} {
		m.Headers = invalid
		if _, err := logicalRequestFromMessage(&m, nil); err == nil {
			t.Fatal("bounded headers reached SDK")
		}
	}
	m.Headers = nil
	request, err = logicalRequestFromMessage(&m, nil)
	if err != nil || request.Headers != nil || request.ClientToken != "" {
		t.Fatal("legacy absent shape")
	}
}
