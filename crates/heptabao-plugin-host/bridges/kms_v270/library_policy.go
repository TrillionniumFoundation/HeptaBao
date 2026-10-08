// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This is operator-deployment provenance, not provider metadata or a client field.
type deploymentImplementation string

const (
	opaqueKMSImplementation   deploymentImplementation = "opaque-kms-v1"
	pkcs11AliasImplementation deploymentImplementation = "openbao-pkcs11-aliases-v1"
)

func (k *deploymentImplementation) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || s != string(opaqueKMSImplementation) && s != string(pkcs11AliasImplementation) {
		return errors.New("invalid operator implementation")
	}
	*k = deploymentImplementation(s)
	return nil
}

func implementationPolicy(d deployment) (deploymentImplementation, error) {
	k := d.Implementation
	if k == "" {
		// Historical opaque deployments remain supported only without library aliases.
		k = opaqueKMSImplementation
	}
	if k != opaqueKMSImplementation && k != pkcs11AliasImplementation ||
		k == opaqueKMSImplementation && len(d.Libraries) != 0 {
		return "", errors.New("invalid operator library policy")
	}
	return k, nil
}

// The standard FlagSet implements the actual v0.2.0 main's one/two-dash,
// separate/equals, repeat-last-write and first-positional/terminator semantics.
// It deliberately has no provider-supplied flags or global CommandLine access.
func parsePKCS11AliasArguments(args []string) (map[string]string, []string, bool, error) {
	effective := make(map[string]string)
	fs := flag.NewFlagSet("operator PKCS11 aliases", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Func("alias", "", func(s string) error {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return errors.New("invalid alias assignment")
		}
		effective[parts[0]] = parts[1]
		return nil
	})
	if fs.Parse(args) != nil {
		return nil, nil, false, errors.New("invalid PKCS11 provider arguments")
	}
	tail := append([]string(nil), fs.Args()...)
	consumed := len(args) - len(tail)
	// An alias value must contain '=' and cannot equal the bare "--" token.
	terminated := consumed > 0 && args[consumed-1] == "--"
	return effective, tail, terminated, nil
}

// Only the original runner constructs heldAliases after each corresponding
// library has been pinned and appended to the original command's ExtraFiles.
func providerArguments(d deployment, heldAliases map[string]string) ([]string, error) {
	k, err := implementationPolicy(d)
	if err != nil {
		return nil, err
	}
	if len(d.Args) > 64 || len(d.Libraries) > 32 {
		return nil, errors.New("invalid operator argument bound")
	}
	for _, arg := range d.Args {
		if len(arg) > 4096 || strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("invalid operator argument bound")
		}
	}
	if len(heldAliases) != len(d.Libraries) {
		return nil, errors.New("invalid held library owner set")
	}
	if k == opaqueKMSImplementation {
		return append([]string(nil), d.Args...), nil
	}
	declared := make(map[string]string, len(d.Libraries))
	for i, lib := range d.Libraries {
		if lib.Alias == "" || len(lib.Alias) > 128 ||
			strings.ContainsAny(lib.Alias, "=,\x00\r\n") ||
			!filepath.IsAbs(lib.Path) || filepath.Clean(lib.Path) != lib.Path {
			return nil, errors.New("invalid declared library alias")
		}
		if _, exists := declared[lib.Alias]; exists {
			return nil, errors.New("duplicate declared library alias")
		}
		if heldAliases[lib.Alias] != "/proc/self/fd/"+strconv.Itoa(4+i) {
			return nil, errors.New("invalid original held library descriptor")
		}
		declared[lib.Alias] = lib.Path
	}
	effective, tail, terminated, err := parsePKCS11AliasArguments(d.Args)
	if err != nil {
		return nil, err
	}
	for alias, path := range effective {
		declaredPath, exists := declared[alias]
		if !exists || path != declaredPath {
			return nil, errors.New("PKCS11 argument selects an unowned library")
		}
	}
	names := make([]string, 0, len(declared))
	for alias := range declared {
		names = append(names, alias)
	}
	sort.Strings(names)
	prepared := make([]string, 0, len(names)+len(tail)+1)
	for _, alias := range names {
		prepared = append(prepared, "--alias="+alias+"="+heldAliases[alias])
	}
	if terminated {
		prepared = append(prepared, "--")
	}
	return append(prepared, tail...), nil
}
