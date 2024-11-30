/*
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

#ifndef ES2PANDA_IR_AST_NODE_FLAGS_H
#define ES2PANDA_IR_AST_NODE_FLAGS_H

#include <cstdint>

#include "util/enumbitops.h"

namespace ark::es2panda::ir {

using ENUMBITOPS_OPERATORS;

enum class AstNodeFlags {
    NO_OPTS = 0,
    CHECKCAST = 1U << 0U,
    CONVERT_TO_STRING = 1U << 1U,
    ALLOW_REQUIRED_INSTANTIATION = 1U << 2U,
    HAS_EXPORT_ALIAS = 1U << 3U,
    GENERATE_VALUE_OF = 1U << 4U,
    GENERATE_GET_NAME = 1U << 5U,  // Transform the Enum[enumVar] MemberExpression to enumVar.getName() call
    RECHECK = 1U << 6U,
    /* do not introduce new flags. all the existing to be removed */
};

enum class ModifierFlags : uint32_t {
    NONE = 0U,
    STATIC = 1U << 0U,
    ASYNC = 1U << 1U,
    PUBLIC = 1U << 2U,
    PROTECTED = 1U << 3U,
    PRIVATE = 1U << 4U,
    DECLARE = 1U << 5U,
    READONLY = 1U << 6U,
    OPTIONAL = 1U << 7U,
    DEFINITE = 1U << 8U,
    ABSTRACT = 1U << 9U,
    CONST = 1U << 10U,
    FINAL = 1U << 11U,
    NATIVE = 1U << 12U,
    OVERRIDE = 1U << 13U,
    CONSTRUCTOR = 1U << 14U,
    SYNCHRONIZED = 1U << 15U,
    FUNCTIONAL = 1U << 16U,
    IN = 1U << 17U,
    OUT = 1U << 18U,
    INTERNAL = 1U << 19U,
    EXPORT = 1U << 20U,
    GETTER = 1U << 21U,
    SETTER = 1U << 22U,
    DEFAULT_EXPORT = 1U << 23U,
    EXPORT_TYPE = 1U << 24U,
    SUPER_OWNER = 1U << 26U,
    ANNOTATION_DECLARATION = 1U << 27U,
    ANNOTATION_USAGE = 1U << 28U,
    READONLY_PARAMETER = 1U << 29U,
    ACCESS = PUBLIC | PROTECTED | PRIVATE | INTERNAL,
    ALL = STATIC | ASYNC | ACCESS | DECLARE | READONLY | ABSTRACT,
    ALLOWED_IN_CTOR_PARAMETER = ACCESS | READONLY,
    INTERNAL_PROTECTED = INTERNAL | PROTECTED,
    ACCESSOR_MODIFIERS = ABSTRACT | FINAL,
    GETTER_SETTER = GETTER | SETTER,
    EXPORTED = EXPORT | DEFAULT_EXPORT | EXPORT_TYPE
};

enum class PrivateFieldKind { FIELD, METHOD, GET, SET, STATIC_FIELD, STATIC_METHOD, STATIC_GET, STATIC_SET };

enum class ScriptFunctionFlags : uint32_t {
    NONE = 0U,
    GENERATOR = 1U << 0U,
    ASYNC = 1U << 1U,
    ARROW = 1U << 2U,
    EXPRESSION = 1U << 3U,
    OVERLOAD = 1U << 4U,
    CONSTRUCTOR = 1U << 5U,
    METHOD = 1U << 6U,
    STATIC_BLOCK = 1U << 7U,
    HIDDEN = 1U << 8U,
    IMPLICIT_SUPER_CALL_NEEDED = 1U << 9U,
    ENUM = 1U << 10U,
    EXTERNAL = 1U << 11U,
    PROXY = 1U << 12U,
    THROWS = 1U << 13U,
    RETHROWS = 1U << 14U,
    GETTER = 1U << 15U,
    SETTER = 1U << 16U,
    ENTRY_POINT = 1U << 17U,
    INSTANCE_EXTENSION_METHOD = 1U << 18U,
    HAS_RETURN = 1U << 19U,
    ASYNC_IMPL = 1U << 20U,
    EXTERNAL_OVERLOAD = 1U << 21U,
    HAS_THROW = 1U << 22U,
};

enum class TSOperatorType { READONLY, KEYOF, UNIQUE };
enum class MappedOption { NO_OPTS, PLUS, MINUS };

enum class BoxingUnboxingFlags : uint32_t {
    NONE = 0U,
    BOX_TO_BOOLEAN = 1U << 0U,
    BOX_TO_BYTE = 1U << 1U,
    BOX_TO_SHORT = 1U << 2U,
    BOX_TO_CHAR = 1U << 3U,
    BOX_TO_INT = 1U << 4U,
    BOX_TO_LONG = 1U << 5U,
    BOX_TO_FLOAT = 1U << 6U,
    BOX_TO_DOUBLE = 1U << 7U,
    BOX_TO_ENUM = 1U << 8U,
    UNBOX_TO_BOOLEAN = 1U << 9U,
    UNBOX_TO_BYTE = 1U << 10U,
    UNBOX_TO_SHORT = 1U << 11U,
    UNBOX_TO_CHAR = 1U << 12U,
    UNBOX_TO_INT = 1U << 13U,
    UNBOX_TO_LONG = 1U << 14U,
    UNBOX_TO_FLOAT = 1U << 15U,
    UNBOX_TO_DOUBLE = 1U << 16U,
    UNBOX_TO_ENUM = 1U << 17U,
    BOXING_FLAG = BOX_TO_BOOLEAN | BOX_TO_BYTE | BOX_TO_SHORT | BOX_TO_CHAR | BOX_TO_INT | BOX_TO_LONG | BOX_TO_FLOAT |
                  BOX_TO_DOUBLE | BOX_TO_ENUM,
    UNBOXING_FLAG = UNBOX_TO_BOOLEAN | UNBOX_TO_BYTE | UNBOX_TO_SHORT | UNBOX_TO_CHAR | UNBOX_TO_INT | UNBOX_TO_LONG |
                    UNBOX_TO_FLOAT | UNBOX_TO_DOUBLE | UNBOX_TO_ENUM,
};
}  // namespace ark::es2panda::ir

namespace enumbitops {

template <>
struct IsAllowedType<ark::es2panda::ir::AstNodeFlags> : std::true_type {
};

template <>
struct IsAllowedType<ark::es2panda::ir::ModifierFlags> : std::true_type {
};

template <>
struct IsAllowedType<ark::es2panda::ir::ScriptFunctionFlags> : std::true_type {
};

template <>
struct IsAllowedType<ark::es2panda::ir::BoxingUnboxingFlags> : std::true_type {
};

}  // namespace enumbitops

#endif
