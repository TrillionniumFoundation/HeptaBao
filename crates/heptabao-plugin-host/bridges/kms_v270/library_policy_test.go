// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func aliasTestDeployment() deployment {
	return deployment{
		Provider:       "transit", // The name cannot imply a library implementation.
		Implementation: pkcs11AliasImplementation,
		Libraries:      []library{{Alias: "token", Path: "/operator/libpkcs11.so"}},
	}
}
func aliasTestHeld() map[string]string { return map[string]string{"token": heldLibraryDescriptor(0)} }

func TestPKCS11AliasFourSpellingsBindOriginalHeldLibrary(t *testing.T) {
	for _, args := range [][]string{
		{"-alias", "token=/operator/libpkcs11.so"},
		{"--alias", "token=/operator/libpkcs11.so"},
		{"-alias=token=/operator/libpkcs11.so"},
		{"--alias=token=/operator/libpkcs11.so"},
	} {
		d := aliasTestDeployment()
		d.Args = args
		got, err := providerArguments(d, aliasTestHeld())
		if err != nil || !reflect.DeepEqual(got, []string{"--alias=token="+heldLibraryDescriptor(0)}) {
			t.Fatal("a standard alias spelling lost its original held owner")
		}
	}
}
func TestPKCS11RepeatedAliasesHonorOnlyFinalAssignment(t *testing.T) {
	d := aliasTestDeployment()
	d.Args = []string{"--alias=token=/foreign.so", "-alias", "token=/operator/libpkcs11.so"}
	got, err := providerArguments(d, aliasTestHeld())
	if err != nil || !reflect.DeepEqual(got, []string{"--alias=token="+heldLibraryDescriptor(0)}) {
		t.Fatal("repeat-last-write semantics changed")
	}
	d.Args = []string{"-alias=token=/operator/libpkcs11.so", "--alias=token=/foreign.so"}
	if _, err = providerArguments(d, aliasTestHeld()); err == nil {
		t.Fatal("a foreign final assignment acquired an owner")
	}
}
func TestPKCS11TerminatorAndPositionalTailsStayLiteral(t *testing.T) {
	cases := []struct {
		args, tail []string
		terminated bool
	}{
		{[]string{"--", "--alias=foreign=/foreign.so"}, []string{"--alias=foreign=/foreign.so"}, true},
		{[]string{"positional", "--alias=foreign=/foreign.so"}, []string{"positional", "--alias=foreign=/foreign.so"}, false},
		{[]string{"-", "--alias=foreign=/foreign.so"}, []string{"-", "--alias=foreign=/foreign.so"}, false},
		{[]string{"", "--alias=foreign=/foreign.so"}, []string{"", "--alias=foreign=/foreign.so"}, false},
		{[]string{"--alias=token=/operator/libpkcs11.so", "--"}, nil, true},
	}
	for _, c := range cases {
		d := aliasTestDeployment()
		d.Args = c.args
		got, err := providerArguments(d, aliasTestHeld())
		if err != nil {
			t.Fatal("an ignored tail was treated as an active alias")
		}
		effective, tail, terminated, err := parsePKCS11AliasArguments(got)
		if err != nil || effective["token"] != heldLibraryDescriptor(0) ||
			!reflect.DeepEqual(tail, c.tail) || terminated != c.terminated {
			t.Fatal("the standard parser observed a changed tail or descriptor")
		}
	}
}
func TestPKCS11UnknownMissingMalformedAndHelpFailBeforeEntry(t *testing.T) {
	for _, args := range [][]string{
		{"-alias"}, {"--alias="}, {"--alias", "without-separator"},
		{"---alias=token=/operator/libpkcs11.so"}, {"-unknown=1"},
		{"-h"}, {"--help"}, {"-alias", "--"},
	} {
		d := aliasTestDeployment()
		d.Args = args
		if _, err := providerArguments(d, aliasTestHeld()); err == nil {
			t.Fatal("a failed standard flag parse was promoted to provider entry")
		}
	}
}
func TestPKCS11EffectiveUnknownAndEscapingPathsFailClosed(t *testing.T) {
	for _, value := range []string{
		"foreign=/operator/libpkcs11.so", "token=/foreign.so",
		"token=/operator/../libpkcs11.so", "token=relative.so",
		"token=/proc/self/fd/4", "token=",
	} {
		d := aliasTestDeployment()
		d.Args = []string{"--alias=" + value}
		if _, err := providerArguments(d, aliasTestHeld()); err == nil {
			t.Fatal("an unowned effective alias was accepted")
		}
	}
}
func TestPKCS11DeclaredAliasesRetainExactOriginalFDOrder(t *testing.T) {
	d := aliasTestDeployment()
	d.Provider = "custom-operator-name"
	d.Libraries = []library{
		{Alias: "z", Path: "/operator/z.so"},
		{Alias: "a", Path: "/operator/a.so"},
	}
	got, err := providerArguments(d, map[string]string{"z": heldLibraryDescriptor(0), "a": heldLibraryDescriptor(1)})
	if err != nil || !reflect.DeepEqual(got, []string{"--alias=a="+heldLibraryDescriptor(1), "--alias=z="+heldLibraryDescriptor(0)}) {
		t.Fatal("sorting changed the corresponding original ExtraFiles owner")
	}
}
func TestOpaqueImplementationPreservesArgsOnlyWithoutAliases(t *testing.T) {
	d := deployment{Args: []string{"--arbitrary-operator-flag", "argument"}}
	got, err := providerArguments(d, nil)
	if err != nil || !reflect.DeepEqual(got, d.Args) {
		t.Fatal("historical opaque argument semantics changed")
	}
	d.Libraries = aliasTestDeployment().Libraries
	if _, err := providerArguments(d, aliasTestHeld()); err == nil {
		t.Fatal("an unclassified library gained PKCS11 authority")
	}
	d.Implementation = opaqueKMSImplementation
	if _, err := providerArguments(d, aliasTestHeld()); err == nil {
		t.Fatal("an opaque provider gained PKCS11 authority")
	}
}
func TestImplementationJSONRejectsNullEmptyUnknownAndNonStrings(t *testing.T) {
	for _, value := range []string{"null", "\"\"", "\"pkcs11\"", "true", "{}"} {
		var k deploymentImplementation
		if err := json.Unmarshal([]byte(value), &k); err == nil {
			t.Fatal("an unsealed implementation value was accepted")
		}
	}
	for _, value := range []string{"\"opaque-kms-v1\"", "\"openbao-pkcs11-aliases-v1\""} {
		var k deploymentImplementation
		if err := json.Unmarshal([]byte(value), &k); err != nil {
			t.Fatal("a closed operator implementation was rejected")
		}
	}
}
func TestPKCS11HeldDescriptorSetCannotGainOrLoseOwners(t *testing.T) {
	for _, held := range []map[string]string{
		nil, {"token": "/proc/self/fd/5"}, {"token": "/operator/libpkcs11.so"},
		{"token": heldLibraryDescriptor(0), "extra": "/proc/self/fd/5"},
	} {
		if _, err := providerArguments(aliasTestDeployment(), held); err == nil {
			t.Fatal("a mismatched descriptor set acquired library authority")
		}
	}
}
func TestPKCS11DeclaredAliasPathAndInputBoundsAreClosed(t *testing.T) {
	for _, bad := range []library{
		{Alias: "", Path: "/operator/lib.so"}, {Alias: "a,b", Path: "/operator/lib.so"},
		{Alias: "a=b", Path: "/operator/lib.so"}, {Alias: "token", Path: "relative.so"},
		{Alias: "token", Path: "/operator/../lib.so"},
	} {
		d := aliasTestDeployment()
		d.Libraries = []library{bad}
		if _, err := providerArguments(d, aliasTestHeld()); err == nil {
			t.Fatal("a malformed declaration became an owner")
		}
	}
	d := aliasTestDeployment()
	d.Args = make([]string, 65)
	if _, err := providerArguments(d, aliasTestHeld()); err == nil {
		t.Fatal("operator raw argument bound changed")
	}
	d.Args = []string{"\x00"}
	if _, err := providerArguments(d, aliasTestHeld()); err == nil {
		t.Fatal("a NUL entered provider arguments")
	}
}
