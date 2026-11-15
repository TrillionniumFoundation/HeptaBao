// Copyright (c) 2026 HeptaBao contributors
// SPDX-License-Identifier: MPL-2.0
package main

import (
    "runtime"
    "strconv"
)
// A platform-selected descriptor spelling, never an operator/request path.
func heldLibraryDescriptor(index int) string {
    if index < 0 || index >= 32 { return "" }
    prefix := "/proc/self/fd/"
    if runtime.GOOS == "darwin" { prefix = "/dev/fd/" }
    return prefix + strconv.Itoa(4+index)
}
