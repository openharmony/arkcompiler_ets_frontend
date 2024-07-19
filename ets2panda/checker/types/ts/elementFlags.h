/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_ELEMENT_FLAGS_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_ELEMENT_FLAGS_H

#include <cstdint>

#include "util/enumbitops.h"

namespace ark::es2panda::checker {

using ENUMBITOPS_OPERATORS;

enum class ElementFlags : uint32_t {
    NO_OPTS = 0U,
    REQUIRED = 1U << 0U,  // T
    OPTIONAL = 1U << 1U,  // T?
    REST = 1U << 2U,      // ...T[]
    VARIADIC = 1U << 3U,  // ...T
    FIXED = REQUIRED | OPTIONAL,
    VARIABLE = REST | VARIADIC,
    NON_REQUIRED = OPTIONAL | REST | VARIADIC,
    NON_REST = REQUIRED | OPTIONAL | VARIADIC,
};

}  // namespace ark::es2panda::checker

template <>
struct enumbitops::IsAllowedType<ark::es2panda::checker::ElementFlags> : std::true_type {
};

#endif /* TYPESCRIPT_TYPES_ELEMENT_FLAGS_H */
