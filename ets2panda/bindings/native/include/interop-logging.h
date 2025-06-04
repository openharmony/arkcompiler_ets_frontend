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

#include <cstdio>
#include <cstdint>

// NOLINTBEGIN

// CC-OFFNXT(G.PRE.09) code generation
#define LOG(msg) fprintf(stdout, msg "\n");
// CC-OFFNXT(G.PRE.09) code generation
#define LOGI(msg, ...) fprintf(stdout, msg "\n", __VA_ARGS__);
// CC-OFFNXT(G.PRE.09) code generation
#define LOGE(msg, ...) fprintf(stderr, msg "\n", __VA_ARGS__);
// CC-OFFNXT(G.PRE.09) code generation
#define LOGE0(msg) fprintf(stderr, msg "\n");
#define LOG_PUBLIC ""

#if defined(PANDA_TARGET_WINDOWS)
#define INTEROP_API_EXPORT __declspec(dllexport)
#else
#define INTEROP_API_EXPORT __attribute__((visibility("default")))
#endif

// NOLINTEND

#endif  // INTEROP_LOGGING_H
