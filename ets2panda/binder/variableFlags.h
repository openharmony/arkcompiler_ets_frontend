/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_SCOPES_VARIABLE_FLAGS_H
#define ES2PANDA_COMPILER_SCOPES_VARIABLE_FLAGS_H

#include <cstdint>
#include "plugins/ecmascript/es2panda/util/enumbitops.h"

namespace panda::es2panda::binder {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARATION_KINDS(_)             \
    _(VAR, VarDecl)                      \
    _(LET, LetDecl)                      \
    _(CONST, ConstDecl)                  \
    _(FUNC, FunctionDecl)                \
    _(PARAM, ParameterDecl)              \
    _(IMPORT, ImportDecl)                \
    _(DYNAMIC_IMPORT, DynamicImportDecl) \
    _(EXPORT, ExportDecl)                \
    /* TS */                             \
    _(TYPE_ALIAS, TypeAliasDecl)         \
    _(NAMESPACE, NameSpaceDecl)          \
    _(INTERFACE, InterfaceDecl)          \
    _(ENUM_LITERAL, EnumLiteralDecl)     \
    _(TYPE_PARAMETER, TypeParameterDecl) \
    _(PROPERTY, PropertyDecl)            \
    _(CLASS, ClassDecl)                  \
    _(METHOD, MethodDecl)                \
    _(ENUM, EnumDecl)

enum class DeclType {
    NONE,
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_TYPES(decl_kind, class_name) decl_kind,
    DECLARATION_KINDS(DECLARE_TYPES)
#undef DECLARE_TYPES
};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SCOPE_TYPES(_)                    \
    _(PARAM, ParamScope)                  \
    _(CATCH_PARAM, CatchParamScope)       \
    _(FUNCTION_PARAM, FunctionParamScope) \
    _(CATCH, CatchScope)                  \
    _(CLASS, ClassScope)                  \
    _(LOCAL, LocalScope)                  \
    /* Variable Scopes */                 \
    _(LOOP, LoopScope)                    \
    _(LOOP_DECL, LoopDeclarationScope)    \
    _(FUNCTION, FunctionScope)            \
    _(GLOBAL, GlobalScope)                \
    _(MODULE, ModuleScope)

enum class ScopeType {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define GEN_SCOPE_TYPES(type, class_name) type,
    SCOPE_TYPES(GEN_SCOPE_TYPES)
#undef GEN_SCOPE_TYPES
};

enum class ResolveBindingOptions : uint32_t {
    BINDINGS = 1U << 0U,
    INTERFACES = 1U << 1U,
    VARIABLES = 1U << 2U,
    METHODS = 1U << 3U,
    DECLARATION = 1U << 4U,
    STATIC_VARIABLES = 1U << 5U,
    STATIC_METHODS = 1U << 6U,
    STATIC_DECLARATION = 1U << 7U,
    TYPE_ALIASES = 1U << 8U,
    ALL_VARIABLES = VARIABLES | STATIC_VARIABLES,
    ALL_METHOD = METHODS | STATIC_METHODS,
    ALL_DECLARATION = DECLARATION | STATIC_DECLARATION,

    LAST = TYPE_ALIASES,
    ALL = (LAST << 1U) - 1U,
};

DEFINE_BITOPS(ResolveBindingOptions)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VARIABLE_TYPES(_)     \
    _(LOCAL, LocalVariable)   \
    _(GLOBAL, GlobalVariable) \
    _(MODULE, ModuleVariable) \
    _(ENUM, EnumVariable)

enum class VariableType {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define GEN_VARIABLE_TYPES(type, class_name) type,
    VARIABLE_TYPES(GEN_VARIABLE_TYPES)
#undef GEN_VARIABLE_TYPES
};

enum class VariableKind {
    NONE,
    VAR,
    LEXICAL,
    FUNCTION,
    MODULE,
};

enum class VariableFlags : uint64_t {
    NONE = 0U,
    OPTIONAL = 1U << 0U,
    PROPERTY = 1U << 1U,
    METHOD = 1U << 2U,
    TYPE_ALIAS = 1U << 3U,
    INTERFACE = 1U << 4U,
    ENUM_LITERAL = 1U << 5U,
    READONLY = 1U << 6U,
    COMPUTED = 1U << 7U,
    COMPUTED_IDENT = 1U << 8U,  // Remove
    INFERRED_IN_PATTERN = 1U << 9U,
    REST_ARG = 1U << 10U,
    NUMERIC_NAME = 1U << 11U,
    TYPE = 1U << 12U,
    LOCAL_EXPORT = 1U << 13U,
    TYPE_PARAMETER = 1U << 14U,
    STATIC = 1U << 15U,
    CLASS = 1U << 16U,
    EXPLICIT_INIT_REQUIRED = 1U << 17U,
    PUBLIC = 1U << 18U,
    PROTECTED = 1U << 19U,
    PRIVATE = 1U << 20U,
    SYNTHETIC = 1U << 21U,
    METHOD_REFERENCE = 1U << 22U,
    LOCAL = 1U << 23U,

    LEXICAL = 1U << 24U,
    LOOP_DECL = 1U << 25U,
    PER_ITERATION = 1U << 26U,
    LEXICAL_VAR = 1U << 27U,
    HOIST = 1U << 28U,
    VAR = 1U << 29U,
    INITIALIZED = 1U << 30U,
    LEXICAL_BOUND = 1U << 31U,

    BUILTIN_TYPE = 1ULL << 32ULL,

    BOXED = 1ULL << 33ULL,

    HOIST_VAR = HOIST | VAR,
    CLASS_OR_INTERFACE = CLASS | INTERFACE,
    CLASS_OR_INTERFACE_OR_ENUM = CLASS_OR_INTERFACE | ENUM_LITERAL,
};

DEFINE_BITOPS(VariableFlags)

enum class LetOrConstStatus {
    INITIALIZED,
    UNINITIALIZED,
};

enum class ScopeFlags : uint32_t {
    NONE = 0U,
    SET_LEXICAL_FUNCTION = 1U << 0U,
    USE_ARGS = 1U << 2U,
    USE_SUPER = 1U << 3U,
    INNER_ARROW = 1U << 4U,
    NO_REG_STORE = 1U << 5U,
    DECL_SCOPE = 1U << 6U,
    FIELD_SCOPE = 1U << 7U,
    METHOD_SCOPE = 1U << 8U,
    STATIC = 1U << 9U,
    TYPE_ALIAS = 1U << 10U,

    STATIC_DECL_SCOPE = DECL_SCOPE | STATIC,
    STATIC_FIELD_SCOPE = FIELD_SCOPE | STATIC,
    STATIC_METHOD_SCOPE = METHOD_SCOPE | STATIC,
};

DEFINE_BITOPS(ScopeFlags)
}  // namespace panda::es2panda::binder

#endif
