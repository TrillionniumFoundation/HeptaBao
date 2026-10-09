// Copyright (C) 2015-2016 Apple Inc. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// THIS SOFTWARE IS PROVIDED BY APPLE INC. AS IS AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL APPLE INC. OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
// OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Minimal isolated declarations from the pinned official Apple WebKit
// Source/WTF/wtf/spi/darwin/SandboxSPI.h, FULL copy/hash in the source package.
// This SPI is intentionally distinct from public sandbox_init(flags=0).
#ifndef HEPTABAO_DARWIN_SANDBOX_SPI_H
#define HEPTABAO_DARWIN_SANDBOX_SPI_H
#include <stddef.h>
typedef struct { char *builtin; unsigned char *data; size_t size; } *sandbox_profile_t;
typedef struct { const char **params; size_t size; size_t available; } *sandbox_params_t;
sandbox_params_t sandbox_create_params(void);
int sandbox_set_param(sandbox_params_t, const char *, const char *);
void sandbox_free_params(sandbox_params_t);
sandbox_profile_t sandbox_compile_string(const char *, sandbox_params_t, char **);
void sandbox_free_profile(sandbox_profile_t);
int sandbox_apply(sandbox_profile_t);
void sandbox_free_error(char *);
#endif
