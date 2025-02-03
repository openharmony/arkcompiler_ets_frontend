/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef INTEROP_LOGGING_H
#define INTEROP_LOGGING_H

#include <stdio.h>
#include <stdint.h>

// CC-OFFNXT(G.PRE.09) code generation
#define LOG(msg) fprintf(stdout, msg "\n");
// CC-OFFNXT(G.PRE.09) code generation
#define LOGI(msg, ...) fprintf(stdout, msg "\n", __VA_ARGS__);
// CC-OFFNXT(G.PRE.09) code generation
#define LOGE(msg, ...) fprintf(stderr, msg "\n", __VA_ARGS__);
// CC-OFFNXT(G.PRE.09) code generation
#define LOGE0(msg) fprintf(stderr, msg "\n");
#define LOG_PUBLIC ""

#if defined(TS_WINDOWS)
#define INTEROP_API_EXPORT __declspec(dllexport)
#else
#define INTEROP_API_EXPORT __attribute__((visibility("default")))
#endif

// Grouped logs. Keep consistent with type in ServiceGroupLogger
typedef struct GroupLogger {
    // CC-OFFNXT(G.NAM.01) false positive
    void (*StartGroupedLog)(int kind);
    // CC-OFFNXT(G.NAM.01) false positive
    void (*StopGroupedLog)(int kind);
    // CC-OFFNXT(G.NAM.01) false positive
    void (*AppendGroupedLog)(int kind, const char *str);
    // CC-OFFNXT(G.NAM.01) false positive
    const char *(*GetGroupedLog)(int kind);
    // CC-OFFNXT(G.NAM.01) false positive
    int (*NeedGroupedLog)(int kind);
} GroupLogger;

const GroupLogger *GetDefaultLogger();

#endif  // INTEROP_LOGGING_H
