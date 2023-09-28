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

#include "globalTypesHolder.h"

#include "plugins/ecmascript/es2panda/checker/types/ts/numberType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/anyType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/stringType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/booleanType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/voidType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/nullType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/undefinedType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/unknownType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/neverType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/nonPrimitiveType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/bigintType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/booleanLiteralType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/bigintLiteralType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/numberLiteralType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/stringLiteralType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/tupleType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/objectLiteralType.h"
#include "plugins/ecmascript/es2panda/checker/types/ts/unionType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/byteType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/charType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/doubleType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/floatType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/intType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/longType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/shortType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsBooleanType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsStringType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsVoidType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsObjectType.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/wildcardType.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"

namespace panda::es2panda::checker {
GlobalTypesHolder::GlobalTypesHolder(ArenaAllocator *allocator) : builtin_name_mappings_(allocator->Adapter())
{
    // TS specific types
    global_types_[static_cast<size_t>(GlobalTypeId::NUMBER)] = allocator->New<NumberType>();
    global_types_[static_cast<size_t>(GlobalTypeId::ANY)] = allocator->New<AnyType>();
    global_types_[static_cast<size_t>(GlobalTypeId::STRING)] = allocator->New<StringType>();
    global_types_[static_cast<size_t>(GlobalTypeId::BOOLEAN)] = allocator->New<BooleanType>();
    global_types_[static_cast<size_t>(GlobalTypeId::VOID)] = allocator->New<VoidType>();
    global_types_[static_cast<size_t>(GlobalTypeId::NULL_ID)] = allocator->New<NullType>();
    global_types_[static_cast<size_t>(GlobalTypeId::UNDEFINED)] = allocator->New<UndefinedType>();
    global_types_[static_cast<size_t>(GlobalTypeId::UNKNOWN)] = allocator->New<UnknownType>();
    global_types_[static_cast<size_t>(GlobalTypeId::NEVER)] = allocator->New<NeverType>();
    global_types_[static_cast<size_t>(GlobalTypeId::NON_PRIMITIVE)] = allocator->New<NonPrimitiveType>();
    global_types_[static_cast<size_t>(GlobalTypeId::BIGINT)] = allocator->New<BigintType>();
    global_types_[static_cast<size_t>(GlobalTypeId::FALSE_ID)] = allocator->New<BooleanLiteralType>(false);
    global_types_[static_cast<size_t>(GlobalTypeId::TRUE_ID)] = allocator->New<BooleanLiteralType>(true);
    global_types_[static_cast<size_t>(GlobalTypeId::NUMBER_OR_BIGINT)] =
        allocator->New<UnionType>(allocator, std::initializer_list<Type *> {GlobalNumberType(), GlobalBigintType()});
    global_types_[static_cast<size_t>(GlobalTypeId::STRING_OR_NUMBER)] =
        allocator->New<UnionType>(allocator, std::initializer_list<Type *> {GlobalStringType(), GlobalNumberType()});
    global_types_[static_cast<size_t>(GlobalTypeId::ZERO)] = allocator->New<NumberLiteralType>(0);
    global_types_[static_cast<size_t>(GlobalTypeId::EMPTY_STRING)] = allocator->New<StringLiteralType>("");
    global_types_[static_cast<size_t>(GlobalTypeId::ZERO_BIGINT)] = allocator->New<BigintLiteralType>("0n", false);
    global_types_[static_cast<size_t>(GlobalTypeId::PRIMITIVE)] = allocator->New<UnionType>(
        allocator,
        std::initializer_list<Type *> {GlobalNumberType(), GlobalStringType(), GlobalBigintType(), GlobalBooleanType(),
                                       GlobalVoidType(), GlobalUndefinedType(), GlobalNullType()});
    global_types_[static_cast<size_t>(GlobalTypeId::EMPTY_TUPLE)] = allocator->New<TupleType>(allocator);
    global_types_[static_cast<size_t>(GlobalTypeId::EMPTY_OBJECT)] = allocator->New<ObjectLiteralType>();
    global_types_[static_cast<size_t>(GlobalTypeId::RESOLVING_RETURN_TYPE)] = allocator->New<AnyType>();
    global_types_[static_cast<size_t>(GlobalTypeId::ERROR_TYPE)] = allocator->New<AnyType>();

    // ETS specific types
    global_types_[static_cast<size_t>(GlobalTypeId::BYTE)] = allocator->New<ByteType>();
    global_types_[static_cast<size_t>(GlobalTypeId::SHORT)] = allocator->New<ShortType>();
    global_types_[static_cast<size_t>(GlobalTypeId::INT)] = allocator->New<IntType>();
    global_types_[static_cast<size_t>(GlobalTypeId::LONG)] = allocator->New<LongType>();
    global_types_[static_cast<size_t>(GlobalTypeId::FLOAT)] = allocator->New<FloatType>();
    global_types_[static_cast<size_t>(GlobalTypeId::DOUBLE)] = allocator->New<DoubleType>();
    global_types_[static_cast<size_t>(GlobalTypeId::CHAR)] = allocator->New<CharType>();
    global_types_[static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN)] = allocator->New<ETSBooleanType>();
    global_types_[static_cast<size_t>(GlobalTypeId::ETS_VOID)] = allocator->New<ETSVoidType>();
    auto *global_null_type = allocator->New<ETSObjectType>(allocator);
    global_null_type->AsETSObjectType()->AddObjectFlag(ETSObjectFlags::NULL_TYPE);
    global_null_type->AsETSObjectType()->SetName("null");
    global_types_[static_cast<size_t>(GlobalTypeId::ETS_NULL)] = global_null_type;
    global_types_[static_cast<size_t>(GlobalTypeId::ETS_WILDCARD)] = allocator->New<WildcardType>();

    builtin_name_mappings_.emplace("Boolean", GlobalTypeId::ETS_BOOLEAN_BUILTIN);
    builtin_name_mappings_.emplace("Byte", GlobalTypeId::ETS_BYTE_BUILTIN);
    builtin_name_mappings_.emplace("Char", GlobalTypeId::ETS_CHAR_BUILTIN);
    builtin_name_mappings_.emplace("Comparable", GlobalTypeId::ETS_COMPARABLE_BUILTIN);
    builtin_name_mappings_.emplace("Console", GlobalTypeId::ETS_CONSOLE_BUILTIN);
    builtin_name_mappings_.emplace("Double", GlobalTypeId::ETS_DOUBLE_BUILTIN);
    builtin_name_mappings_.emplace("Exception", GlobalTypeId::ETS_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("Float", GlobalTypeId::ETS_FLOAT_BUILTIN);
    builtin_name_mappings_.emplace("Floating", GlobalTypeId::ETS_FLOATING_BUILTIN);
    builtin_name_mappings_.emplace("Int", GlobalTypeId::ETS_INTEGER_BUILTIN);
    builtin_name_mappings_.emplace("Integral", GlobalTypeId::ETS_INTEGRAL_BUILTIN);
    builtin_name_mappings_.emplace("Long", GlobalTypeId::ETS_LONG_BUILTIN);
    builtin_name_mappings_.emplace("Object", GlobalTypeId::ETS_OBJECT_BUILTIN);
    builtin_name_mappings_.emplace("Runtime", GlobalTypeId::ETS_RUNTIME_BUILTIN);
    builtin_name_mappings_.emplace("Short", GlobalTypeId::ETS_SHORT_BUILTIN);
    builtin_name_mappings_.emplace("StackTraceElement", GlobalTypeId::ETS_STACK_TRACE_ELEMENT_BUILTIN);
    builtin_name_mappings_.emplace("StackTrace", GlobalTypeId::ETS_STACK_TRACE_BUILTIN);
    builtin_name_mappings_.emplace("NullPointerException", GlobalTypeId::ETS_NULL_POINTER_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("ArrayIndexOutOfBoundsException",
                                   GlobalTypeId::ETS_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("ArithmeticException", GlobalTypeId::ETS_ARITHMETIC_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("ClassNotFoundException", GlobalTypeId::ETS_CLASS_NOT_FOUND_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("ClassCastException", GlobalTypeId::ETS_CLASS_CAST_EXCEPTION_BUILTIN);
    builtin_name_mappings_.emplace("String", GlobalTypeId::ETS_STRING_BUILTIN);
    builtin_name_mappings_.emplace("StringBuilder", GlobalTypeId::ETS_STRING_BUILDER_BUILTIN);
    builtin_name_mappings_.emplace("Type", GlobalTypeId::ETS_TYPE_BUILTIN);
    builtin_name_mappings_.emplace("Types", GlobalTypeId::ETS_TYPES_BUILTIN);
    builtin_name_mappings_.emplace("Promise", GlobalTypeId::ETS_PROMISE_BUILTIN);
    builtin_name_mappings_.emplace("Box", GlobalTypeId::ETS_BOX_BUILTIN);
    builtin_name_mappings_.emplace("BooleanBox", GlobalTypeId::ETS_BOOLEAN_BOX_BUILTIN);
    builtin_name_mappings_.emplace("ByteBox", GlobalTypeId::ETS_BYTE_BOX_BUILTIN);
    builtin_name_mappings_.emplace("CharBox", GlobalTypeId::ETS_CHAR_BOX_BUILTIN);
    builtin_name_mappings_.emplace("ShortBox", GlobalTypeId::ETS_SHORT_BOX_BUILTIN);
    builtin_name_mappings_.emplace("IntBox", GlobalTypeId::ETS_INT_BOX_BUILTIN);
    builtin_name_mappings_.emplace("LongBox", GlobalTypeId::ETS_LONG_BOX_BUILTIN);
    builtin_name_mappings_.emplace("FloatBox", GlobalTypeId::ETS_FLOAT_BOX_BUILTIN);
    builtin_name_mappings_.emplace("DoubleBox", GlobalTypeId::ETS_DOUBLE_BOX_BUILTIN);
    builtin_name_mappings_.emplace("void", GlobalTypeId::ETS_VOID_BUILTIN);

    // ETS escompat layer
    builtin_name_mappings_.emplace("Array", GlobalTypeId::ETS_ARRAY_BUILTIN);
    builtin_name_mappings_.emplace("Date", GlobalTypeId::ETS_DATE_BUILTIN);
    builtin_name_mappings_.emplace("Error", GlobalTypeId::ETS_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("OutOfMemoryError", GlobalTypeId::ETS_OUT_OF_MEMORY_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("NoSuchMethodError", GlobalTypeId::ETS_NO_SUCH_METHOD_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("AssertionError", GlobalTypeId::ETS_ASSERTION_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("DivideByZeroError", GlobalTypeId::ETS_DIVIDE_BY_ZERO_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("NullPointerError", GlobalTypeId::ETS_NULL_POINTER_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("UncatchedExceptionError", GlobalTypeId::ETS_UNCATCHED_EXCEPTION_ERROR_BUILTIN);
    builtin_name_mappings_.emplace("Map", GlobalTypeId::ETS_MAP_BUILTIN);
    builtin_name_mappings_.emplace("RegExp", GlobalTypeId::ETS_REGEXP_BUILTIN);
    builtin_name_mappings_.emplace("Set", GlobalTypeId::ETS_SET_BUILTIN);

    // ETS interop js specific types
    builtin_name_mappings_.emplace("JSRuntime", GlobalTypeId::ETS_INTEROP_JSRUNTIME_BUILTIN);
    builtin_name_mappings_.emplace("JSValue", GlobalTypeId::ETS_INTEROP_JSVALUE_BUILTIN);
}

Type *GlobalTypesHolder::GlobalNumberType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::NUMBER));
}

Type *GlobalTypesHolder::GlobalAnyType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ANY));
}

Type *GlobalTypesHolder::GlobalStringType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::STRING));
}

Type *GlobalTypesHolder::GlobalBooleanType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::BOOLEAN));
}

Type *GlobalTypesHolder::GlobalVoidType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::VOID));
}

Type *GlobalTypesHolder::GlobalNullType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::NULL_ID));
}

Type *GlobalTypesHolder::GlobalUndefinedType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::UNDEFINED));
}

Type *GlobalTypesHolder::GlobalUnknownType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::UNKNOWN));
}

Type *GlobalTypesHolder::GlobalNeverType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::NEVER));
}

Type *GlobalTypesHolder::GlobalNonPrimitiveType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::NON_PRIMITIVE));
}

Type *GlobalTypesHolder::GlobalBigintType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::BIGINT));
}

Type *GlobalTypesHolder::GlobalFalseType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::FALSE_ID));
}

Type *GlobalTypesHolder::GlobalTrueType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::TRUE_ID));
}

Type *GlobalTypesHolder::GlobalNumberOrBigintType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::NUMBER_OR_BIGINT));
}

Type *GlobalTypesHolder::GlobalStringOrNumberType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::STRING_OR_NUMBER));
}

Type *GlobalTypesHolder::GlobalZeroType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ZERO));
}

Type *GlobalTypesHolder::GlobalEmptyStringType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::EMPTY_STRING));
}

Type *GlobalTypesHolder::GlobalZeroBigintType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ZERO_BIGINT));
}

Type *GlobalTypesHolder::GlobalPrimitiveType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::PRIMITIVE));
}

Type *GlobalTypesHolder::GlobalEmptyTupleType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::EMPTY_TUPLE));
}

Type *GlobalTypesHolder::GlobalEmptyObjectType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::EMPTY_OBJECT));
}

Type *GlobalTypesHolder::GlobalResolvingReturnType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::RESOLVING_RETURN_TYPE));
}

Type *GlobalTypesHolder::GlobalErrorType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ERROR_TYPE));
}

Type *GlobalTypesHolder::GlobalByteType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::BYTE));
}

Type *GlobalTypesHolder::GlobalShortType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::SHORT));
}

Type *GlobalTypesHolder::GlobalIntType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::INT));
}

Type *GlobalTypesHolder::GlobalLongType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::LONG));
}

Type *GlobalTypesHolder::GlobalFloatType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::FLOAT));
}

Type *GlobalTypesHolder::GlobalDoubleType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::DOUBLE));
}

Type *GlobalTypesHolder::GlobalCharType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::CHAR));
}

Type *GlobalTypesHolder::GlobalETSBooleanType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN));
}

Type *GlobalTypesHolder::GlobalETSStringLiteralType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_STRING));
}

Type *GlobalTypesHolder::GlobalETSVoidType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_VOID));
}

Type *GlobalTypesHolder::GlobalBuiltinVoidType()
{
    return global_types_.at(static_cast<std::size_t>(GlobalTypeId::ETS_VOID_BUILTIN));
}

Type *GlobalTypesHolder::GlobalETSObjectType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_OBJECT_BUILTIN));
}

Type *GlobalTypesHolder::GlobalETSNullType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_NULL));
}

Type *GlobalTypesHolder::GlobalWildcardType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_WILDCARD));
}

Type *GlobalTypesHolder::GlobalETSBooleanBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN_BUILTIN));
}

Type *GlobalTypesHolder::GlobalByteBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BYTE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalCharBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_CHAR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalComparableBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_COMPARABLE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalConsoleBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_CONSOLE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalDoubleBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_DOUBLE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalExceptionBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalFloatBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BUILTIN));
}

Type *GlobalTypesHolder::GlobalFloatingBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_FLOATING_BUILTIN));
}

Type *GlobalTypesHolder::GlobalIntegerBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_INTEGER_BUILTIN));
}

Type *GlobalTypesHolder::GlobalIntegralBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_INTEGRAL_BUILTIN));
}

Type *GlobalTypesHolder::GlobalLongBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_LONG_BUILTIN));
}

Type *GlobalTypesHolder::GlobalMapBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_MAP_BUILTIN));
}

Type *GlobalTypesHolder::GlobalErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalRuntimeBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_RUNTIME_BUILTIN));
}

Type *GlobalTypesHolder::GlobalSetBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_SET_BUILTIN));
}

Type *GlobalTypesHolder::GlobalShortBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_SHORT_BUILTIN));
}

Type *GlobalTypesHolder::GlobalStackTraceElementBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_STACK_TRACE_ELEMENT_BUILTIN));
}

Type *GlobalTypesHolder::GlobalStackTraceBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_STACK_TRACE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalNullPointerExceptionBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_NULL_POINTER_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalArrayIndexOutOfBoundsExceptionBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalArithmeticExceptionBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_ARITHMETIC_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalClassNotFoundExceptionBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_CLASS_NOT_FOUND_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalClassCastExceptionBuiltinType() const noexcept
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_CLASS_CAST_EXCEPTION_BUILTIN));
}

Type *GlobalTypesHolder::GlobalClassOutOfMemoryErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_OUT_OF_MEMORY_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalNoSuchMethodErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_NO_SUCH_METHOD_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalAssertionErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_ASSERTION_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalDivideByZeroErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_DIVIDE_BY_ZERO_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalNullPointerErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_NULL_POINTER_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalUncatchedExceptionErrorBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_UNCATCHED_EXCEPTION_ERROR_BUILTIN));
}

Type *GlobalTypesHolder::GlobalETSStringBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_STRING_BUILTIN));
}

Type *GlobalTypesHolder::GlobalStringBuilderBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_STRING_BUILDER_BUILTIN));
}

Type *GlobalTypesHolder::GlobalTypeBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_TYPE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalTypesBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_TYPES_BUILTIN));
}

Type *GlobalTypesHolder::GlobalPromiseBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_PROMISE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalRegExpBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_REGEXP_BUILTIN));
}

Type *GlobalTypesHolder::GlobalArrayBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_ARRAY_BUILTIN));
}

Type *GlobalTypesHolder::GlobalBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalJSRuntimeBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_INTEROP_JSRUNTIME_BUILTIN));
}

Type *GlobalTypesHolder::GlobalJSValueBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_INTEROP_JSVALUE_BUILTIN));
}

Type *GlobalTypesHolder::GlobalBooleanBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalByteBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_BYTE_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalCharBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_CHAR_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalShortBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_SHORT_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalIntBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_INT_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalLongBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_LONG_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalFloatBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BOX_BUILTIN));
}

Type *GlobalTypesHolder::GlobalDoubleBoxBuiltinType()
{
    return global_types_.at(static_cast<size_t>(GlobalTypeId::ETS_DOUBLE_BOX_BUILTIN));
}

void GlobalTypesHolder::InitializeBuiltin(const util::StringView name, Type *type)
{
    const auto type_id = builtin_name_mappings_.find(name);
    if (type_id == builtin_name_mappings_.end()) {
        util::Helpers::LogDebug("Did not find '", name, "' builtin in GlobalTypesHolder, it should be added.");
        return;
    }
    global_types_.at(static_cast<size_t>(type_id->second)) = type;
}
}  // namespace panda::es2panda::checker
