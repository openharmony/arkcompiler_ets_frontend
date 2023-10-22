/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TYPE_FLAG_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TYPE_FLAG_H

#include "util/enumbitops.h"

#include <cinttypes>

namespace panda::es2panda::checker {
enum class TypeFlag : uint64_t {
    NONE = 0,
    NUMBER = 1ULL << 0ULL,               // x: number
    STRING = 1ULL << 1ULL,               // x: string
    BOOLEAN = 1ULL << 2ULL,              // x: boolean
    VOID = 1ULL << 3ULL,                 // x: void
    NULL_TYPE = 1ULL << 4ULL,            // x: null
    UNDEFINED = 1ULL << 5ULL,            // x: undefined
    UNKNOWN = 1ULL << 6ULL,              // x: unknown
    NEVER = 1ULL << 7ULL,                // x: never
    UNION = 1ULL << 8ULL,                // x: a | b
    OBJECT = 1ULL << 9ULL,               // x: object
    BIGINT = 1ULL << 10ULL,              // x: bigint
    BOOLEAN_LITERAL = 1ULL << 11ULL,     // x: true
    NUMBER_LITERAL = 1ULL << 12ULL,      // x: 10
    STRING_LITERAL = 1ULL << 13ULL,      // x: "foo"
    BIGINT_LITERAL = 1ULL << 14ULL,      // x: 10n
    ENUM = 1ULL << 15ULL,                // enum x
    ENUM_LITERAL = 1ULL << 16ULL,        // member of enum
    SYMBOL = 1ULL << 17ULL,              // x: symbol
    UNIQUE_SYMBOL = 1ULL << 18ULL,       // one of JS unique symbols
    TYPE_PARAMETER = 1ULL << 19ULL,      // function<x>
    INTERSECTION = 1ULL << 20ULL,        // x: a & b
    INDEX = 1ULL << 21ULL,               // keyof x
    INDEX_ACCESS = 1ULL << 22ULL,        // x[a]
    CONDITIONAL = 1ULL << 23ULL,         // x extends a ? b : c
    SUBSTITUTION = 1ULL << 24ULL,        // type parameter substitution
    TEMPLATE_LITERAL = 1ULL << 25ULL,    // x: `hello ${World}`
    STRING_MAPPING = 1ULL << 27ULL,      // Uppercase/Lowercase type
    ANY = 1ULL << 28ULL,                 // x: any
    ARRAY = 1ULL << 29ULL,               // x: number[]
    FUNCTION = 1ULL << 30ULL,            // x: (a) => b
    NON_PRIMITIVE = 1ULL << 31ULL,       // x: object
    TYPE_REFERENCE = 1ULL << 32ULL,      // x: A
    READONLY = 1ULL << 33ULL,            // type assigned to a readonly property
    CONSTANT = 1ULL << 34ULL,            // type for constant expressions containing the associated constant value
    BYTE = 1ULL << 35ULL,                // x: byte
    SHORT = 1ULL << 36ULL,               // x: short
    INT = 1ULL << 37ULL,                 // x: int
    LONG = 1ULL << 38ULL,                // x: long
    FLOAT = 1ULL << 39ULL,               // x: float
    DOUBLE = 1ULL << 40ULL,              // x: double
    CHAR = 1ULL << 41ULL,                // x: char
    ETS_BOOLEAN = 1ULL << 42ULL,         // ETS boolean type
    ETS_VOID = 1ULL << 43ULL,            // ETS void type
    ETS_OBJECT = 1ULL << 44ULL,          // ETS class or interface type
    ETS_ARRAY = 1ULL << 45ULL,           // ETS array type
    SYNTHETIC = 1ULL << 46ULL,           // synthetic type created by the checker for specific checks
    WILDCARD = 1ULL << 47ULL,            // new A<?>()
    ETS_TYPE_PARAMETER = 1ULL << 48ULL,  // ETS type parameter
    ETS_TYPE_REFERENCE = 1ULL << 49ULL,  // ETS type reference
    GENERIC = 1ULL << 50ULL,             // ETS Generic
    ETS_ENUM = 1ULL << 51ULL,            // ETS Enum
    ETS_STRING_ENUM = 1ULL << 52ULL,     // ETS string-type Enumeration
    ETS_DYNAMIC_FLAG = 1ULL << 53ULL,    // ETS Dynamic flag
    GETTER = 1ULL << 54ULL,              // ETS Getter
    SETTER = 1ULL << 55ULL,              // ETS Setter
    ETS_EXTENSION_FUNC_HELPER = 1ULL << 56ULL,  // ETS Extension Function Helper
    ETS_DYNAMIC_TYPE = ETS_OBJECT | ETS_DYNAMIC_FLAG,
    ETS_DYNAMIC_FUNCTION_TYPE = FUNCTION | ETS_DYNAMIC_FLAG,
    ETS_TYPE = BYTE | SHORT | INT | LONG | FLOAT | DOUBLE | CHAR | ETS_BOOLEAN | ETS_VOID | ETS_OBJECT | ETS_ARRAY |
               WILDCARD | ETS_TYPE_PARAMETER | ETS_ENUM | ETS_STRING_ENUM | ETS_DYNAMIC_TYPE,
    ETS_PRIMITIVE = BYTE | SHORT | INT | LONG | FLOAT | DOUBLE | CHAR | ETS_BOOLEAN | ETS_VOID,
    ETS_PRIMITIVE_RETURN = BYTE | SHORT | INT | LONG | FLOAT | DOUBLE | CHAR | ETS_BOOLEAN | ETS_ENUM,
    ETS_ARRAY_INDEX = BYTE | SHORT | INT,
    ETS_INTEGRAL = BYTE | CHAR | SHORT | INT | LONG,
    ETS_FLOATING_POINT = FLOAT | DOUBLE,
    ETS_NUMERIC = ETS_INTEGRAL | FLOAT | DOUBLE,
    ETS_ARRAY_OR_OBJECT = ETS_ARRAY | ETS_OBJECT,
    ETS_WIDE_NUMERIC = LONG | DOUBLE,
    ETS_TYPE_TO_DYNAMIC = ETS_NUMERIC,
    VALID_SWITCH_TYPE = BYTE | SHORT | INT | CHAR | LONG | ETS_ENUM | ETS_STRING_ENUM,
    NARROWABLE_TO_FLOAT = DOUBLE,
    NARROWABLE_TO_LONG = FLOAT | NARROWABLE_TO_FLOAT,
    NARROWABLE_TO_INT = LONG | NARROWABLE_TO_LONG,
    NARROWABLE_TO_CHAR = SHORT | INT | NARROWABLE_TO_INT,
    NARROWABLE_TO_SHORT = CHAR | INT | NARROWABLE_TO_INT,
    NARROWABLE_TO_BYTE = CHAR | NARROWABLE_TO_CHAR,
    WIDENABLE_TO_SHORT = BYTE,
    WIDENABLE_TO_INT = CHAR | SHORT | WIDENABLE_TO_SHORT,
    WIDENABLE_TO_LONG = INT | WIDENABLE_TO_INT,
    WIDENABLE_TO_FLOAT = LONG | WIDENABLE_TO_LONG,
    WIDENABLE_TO_DOUBLE = FLOAT | WIDENABLE_TO_FLOAT,
    COMPUTED_TYPE_LITERAL_NAME = STRING_LITERAL | NUMBER_LITERAL | ENUM,
    COMPUTED_NAME = COMPUTED_TYPE_LITERAL_NAME | STRING | NUMBER | ANY | SYMBOL,
    ANY_OR_UNKNOWN = ANY | UNKNOWN,
    ANY_OR_VOID = ANY | VOID,
    NULLABLE = UNDEFINED | NULL_TYPE,
    ANY_OR_NULLABLE = ANY | NULLABLE,
    LITERAL = NUMBER_LITERAL | BOOLEAN_LITERAL | STRING_LITERAL | BIGINT_LITERAL,
    NUMBER_LIKE = NUMBER | NUMBER_LITERAL,
    NUMBER_LIKE_ENUM = NUMBER_LIKE | ENUM,
    STRING_LIKE = STRING | STRING_LITERAL,
    BOOLEAN_LIKE = BOOLEAN | BOOLEAN_LITERAL,
    BIGINT_LIKE = BIGINT | BIGINT_LITERAL,
    VOID_LIKE = VOID | UNDEFINED,
    NUMBER_OR_ANY = NUMBER | ANY,
    PRIMITIVE = STRING | NUMBER | BIGINT | BOOLEAN | ENUM | ENUM_LITERAL | SYMBOL | VOID | UNDEFINED | NULL_TYPE |
                LITERAL | UNIQUE_SYMBOL,
    PRIMITIVE_OR_ANY = PRIMITIVE | ANY,
    UNION_OR_INTERSECTION = UNION | INTERSECTION,
    DEFINITELY_FALSY =
        STRING_LITERAL | NUMBER_LITERAL | BOOLEAN_LITERAL | BIGINT_LITERAL | VOID | UNDEFINED | NULL_TYPE,
    POSSIBLY_FALSY = DEFINITELY_FALSY | STRING | NUMBER | BOOLEAN | BIGINT,
    VALID_ARITHMETIC_TYPE = ANY | NUMBER_LIKE | BIGINT_LIKE | ENUM,
    UNIT = LITERAL | UNIQUE_SYMBOL | NULLABLE,
    GETTER_SETTER = GETTER | SETTER
};

DEFINE_BITOPS(TypeFlag)
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_TYPE_FLAG_H */
