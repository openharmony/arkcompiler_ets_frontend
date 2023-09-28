/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "generated/signatures.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/binder/binder.h"
#include "plugins/ecmascript/es2panda/binder/ETSBinder.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsScript.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumMember.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsInterfaceDeclaration.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"

namespace panda::es2panda::checker {
ByteType *ETSChecker::CreateByteType(int8_t value)
{
    return Allocator()->New<ByteType>(value);
}

ETSBooleanType *ETSChecker::CreateETSBooleanType(bool value)
{
    return Allocator()->New<ETSBooleanType>(value);
}

DoubleType *ETSChecker::CreateDoubleType(double value)
{
    return Allocator()->New<DoubleType>(value);
}

FloatType *ETSChecker::CreateFloatType(float value)
{
    return Allocator()->New<FloatType>(value);
}

IntType *ETSChecker::CreateIntType(int32_t value)
{
    return Allocator()->New<IntType>(value);
}

IntType *ETSChecker::CreateIntTypeFromType(Type *type)
{
    if (!type->HasTypeFlag(TypeFlag::CONSTANT)) {
        return GlobalIntType()->AsIntType();
    }

    if (type->IsIntType()) {
        return type->AsIntType();
    }

    switch (ETSType(type)) {
        case TypeFlag::CHAR: {
            return CreateIntType(static_cast<int32_t>(type->AsCharType()->GetValue()));
        }
        case TypeFlag::BYTE: {
            return CreateIntType(static_cast<int32_t>(type->AsByteType()->GetValue()));
        }
        case TypeFlag::SHORT: {
            return CreateIntType(static_cast<int32_t>(type->AsShortType()->GetValue()));
        }
        default: {
            return nullptr;
        }
    }
}

LongType *ETSChecker::CreateLongType(int64_t value)
{
    return Allocator()->New<LongType>(value);
}

ShortType *ETSChecker::CreateShortType(int16_t value)
{
    return Allocator()->New<ShortType>(value);
}

CharType *ETSChecker::CreateCharType(char16_t value)
{
    return Allocator()->New<CharType>(value);
}

ETSStringType *ETSChecker::CreateETSStringLiteralType(util::StringView value)
{
    return Allocator()->New<ETSStringType>(Allocator(), GlobalBuiltinETSStringType(), value);
}

ETSArrayType *ETSChecker::CreateETSArrayType(Type *element_type)
{
    auto res = array_types_.find(element_type);

    if (res != array_types_.end()) {
        return res->second;
    }

    auto *array_type = Allocator()->New<ETSArrayType>(element_type);
    array_types_.insert({element_type, array_type});

    return array_type;
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(ArenaVector<Signature *> &signatures)
{
    auto *func_type = Allocator()->New<ETSFunctionType>(signatures[0]->Function()->Id()->Name(), Allocator());

    for (auto *it : signatures) {
        func_type->AddCallSignature(it);
    }

    return func_type;
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature)
{
    return Allocator()->New<ETSFunctionType>(signature->Function()->Id()->Name(), signature, Allocator());
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature, util::StringView name)
{
    return Allocator()->New<ETSFunctionType>(name, signature, Allocator());
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *return_type, ir::ScriptFunction *func)
{
    return Allocator()->New<Signature>(info, return_type, func);
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *return_type, util::StringView internal_name)
{
    return Allocator()->New<Signature>(info, return_type, internal_name);
}

SignatureInfo *ETSChecker::CreateSignatureInfo()
{
    return Allocator()->New<SignatureInfo>(Allocator());
}

ETSTypeParameter *ETSChecker::CreateTypeParameter(Type *assembler_type)
{
    return Allocator()->New<ETSTypeParameter>(assembler_type);
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(util::StringView name)
{
    return Allocator()->New<ETSFunctionType>(name, Allocator());
}

ETSObjectType *ETSChecker::CreateETSObjectTypeCheckBuiltins(util::StringView name, ir::AstNode *decl_node,
                                                            ETSObjectFlags flags)
{
    if (name == compiler::Signatures::BUILTIN_STRING_CLASS) {
        if (GlobalBuiltinETSStringType() != nullptr) {
            return GlobalBuiltinETSStringType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING_BUILTIN)] =
            CreateNewETSObjectType(name, decl_node, flags | ETSObjectFlags::BUILTIN_STRING | ETSObjectFlags::STRING);

        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING)] =
            Allocator()->New<ETSStringType>(Allocator(), GlobalBuiltinETSStringType());
        return GlobalBuiltinETSStringType();
    }

    auto *obj_type = CreateNewETSObjectType(name, decl_node, flags);

    if (name == compiler::Signatures::BUILTIN_OBJECT_CLASS) {
        if (GlobalETSObjectType() != nullptr) {
            return GlobalETSObjectType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_OBJECT_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_EXCEPTION_CLASS) {
        if (GlobalBuiltinExceptionType() != nullptr) {
            return GlobalBuiltinExceptionType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_EXCEPTION_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_ERROR_CLASS) {
        if (GlobalBuiltinErrorType() != nullptr) {
            return GlobalBuiltinErrorType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_ERROR_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_TYPE_CLASS) {
        if (GlobalBuiltinTypeType() != nullptr) {
            return GlobalBuiltinTypeType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_TYPE_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_PROMISE_CLASS) {
        if (GlobalBuiltinPromiseType() != nullptr) {
            return GlobalBuiltinPromiseType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_PROMISE_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalETSObjectType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalETSObjectType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_BOOLEAN_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalETSBooleanType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalETSBooleanType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_BYTE_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalByteType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalByteType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BYTE_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_CHAR_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalCharType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalCharType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_CHAR_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_SHORT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalShortType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalShortType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_SHORT_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_INT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalIntType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalIntType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_INT_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_LONG_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalLongType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalLongType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_LONG_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalFloatType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalFloatType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalFloatType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalFloatType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_DOUBLE_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalDoubleType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalDoubleType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_DOUBLE_BOX_BUILTIN)] = obj_type;
    } else if (name == compiler::Signatures::BUILTIN_VOID_CLASS) {
        if (GlobalBuiltinVoidType() != nullptr) {
            return GlobalBuiltinVoidType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<std::size_t>(GlobalTypeId::ETS_VOID_BUILTIN)] = obj_type;
    }

    return obj_type;
}

ETSObjectType *ETSChecker::CreateETSObjectType(util::StringView name, ir::AstNode *decl_node, ETSObjectFlags flags)
{
    auto res = primitive_wrappers_.Wrappers().find(name);
    if (res == primitive_wrappers_.Wrappers().end()) {
        return CreateETSObjectTypeCheckBuiltins(name, decl_node, flags);
    }

    if (res->second.first != nullptr) {
        return res->second.first;
    }

    auto *obj_type = CreateNewETSObjectType(name, decl_node, flags | res->second.second);
    primitive_wrappers_.Wrappers().at(name).first = obj_type;
    return obj_type;
}

ETSEnumType *ETSChecker::CreateETSEnumType(ir::TSEnumDeclaration *const enum_decl)
{
    binder::Variable *enum_var = enum_decl->Key()->Variable();
    ASSERT(enum_var != nullptr);

    ETSEnumType::UType ordinal = -1;
    auto *const enum_type = Allocator()->New<ETSEnumType>(enum_decl, ordinal++);
    enum_type->SetVariable(enum_var);
    enum_var->SetTsType(enum_type);

    for (auto *const member : enum_type->GetMembers()) {
        auto *const member_var = member->AsTSEnumMember()->Key()->AsIdentifier()->Variable();
        auto *const enum_literal_type = Allocator()->New<ETSEnumType>(enum_decl, ordinal++, member->AsTSEnumMember());
        enum_literal_type->SetVariable(member_var);
        member_var->SetTsType(enum_literal_type);
    }

    auto *const names_array_ident = CreateEnumNamesArray(enum_type);

    auto const get_name_method = CreateEnumGetNameMethod(names_array_ident, enum_type);
    enum_type->SetGetNameMethod(get_name_method);

    auto const value_of_method = CreateEnumValueOfMethod(names_array_ident, enum_type);
    enum_type->SetValueOfMethod(value_of_method);

    auto *const values_array_ident = CreateEnumValuesArray(enum_type);

    auto const get_value_method = CreateEnumGetValueMethod(values_array_ident, enum_type);
    enum_type->SetGetValueMethod(get_value_method);

    auto const from_int_method = CreateEnumFromIntMethod(values_array_ident, enum_type);
    enum_type->SetFromIntMethod(from_int_method);

    auto *const string_values_array_ident = CreateEnumStringValuesArray(enum_type);

    auto const to_string_method = CreateEnumToStringMethod(string_values_array_ident, enum_type);
    enum_type->SetToStringMethod(to_string_method);

    auto *const items_array_ident = CreateEnumItemsArray(enum_type);

    auto const values_method = CreateEnumValuesMethod(items_array_ident, enum_type);
    enum_type->SetValuesMethod(values_method);

    for (auto *const member : enum_type->GetMembers()) {
        auto *const enum_literal_type =
            member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType()->AsETSEnumType();
        enum_literal_type->SetGetValueMethod(get_value_method);
        enum_literal_type->SetGetNameMethod(get_name_method);
        enum_literal_type->SetToStringMethod(to_string_method);
    }

    return enum_type;
}

ETSObjectType *ETSChecker::CreateNewETSObjectType(util::StringView name, ir::AstNode *decl_node, ETSObjectFlags flags)
{
    util::StringView assembler_name = name;
    util::StringView prefix {};

    auto *containing_obj_type = util::Helpers::GetContainingObjectType(decl_node->Parent());

    if (containing_obj_type != nullptr) {
        prefix = containing_obj_type->AssemblerName();
    } else if (decl_node->GetTopStatement()->Type() !=
               ir::AstNodeType::BLOCK_STATEMENT) {  // TODO(): should not occur, fix for TS_INTERFACE_DECLARATION
        ASSERT(decl_node->IsTSInterfaceDeclaration());
        assembler_name = decl_node->AsTSInterfaceDeclaration()->InternalName();
    } else {
        auto *program = static_cast<ir::ETSScript *>(decl_node->GetTopStatement())->Program();
        prefix = program->GetPackageName();
    }

    if (!prefix.Empty()) {
        util::UString full_path(prefix, Allocator());
        full_path.Append('.');
        full_path.Append(name);
        assembler_name = full_path.View();
    }

    auto lang = compiler::Signatures::Dynamic::LanguageFromType(assembler_name.Utf8());
    if (lang) {
        return Allocator()->New<ETSDynamicType>(Allocator(), name, assembler_name, decl_node, flags, *lang);
    }

    return Allocator()->New<ETSObjectType>(Allocator(), name, assembler_name, decl_node, flags);
}

std::tuple<util::StringView, SignatureInfo *> ETSChecker::CreateBuiltinArraySignatureInfo(ETSArrayType *array_type,
                                                                                          size_t dim)
{
    std::stringstream ss;
    array_type->ToAssemblerTypeWithRank(ss);
    ss << compiler::Signatures::METHOD_SEPARATOR << compiler::Signatures::CTOR << compiler::Signatures::MANGLE_BEGIN;
    array_type->ToAssemblerTypeWithRank(ss);

    auto *info = CreateSignatureInfo();
    info->min_arg_count = dim;

    for (size_t i = 0; i < dim; i++) {
        util::UString param(std::to_string(i), Allocator());
        auto *param_var = binder::Scope::CreateVar(Allocator(), param.View(), binder::VariableFlags::NONE, nullptr);
        param_var->SetTsType(GlobalIntType());

        info->params.push_back(param_var);

        ss << compiler::Signatures::MANGLE_SEPARATOR << compiler::Signatures::PRIMITIVE_INT;
    }

    ss << compiler::Signatures::MANGLE_SEPARATOR << compiler::Signatures::PRIMITIVE_VOID
       << compiler::Signatures::MANGLE_SEPARATOR;
    auto internal_name = util::UString(ss.str(), Allocator()).View();

    return {internal_name, info};
}

Signature *ETSChecker::CreateBuiltinArraySignature(ETSArrayType *array_type, size_t dim)
{
    auto res = global_array_signatures_.find(array_type);

    if (res != global_array_signatures_.end()) {
        return res->second;
    }

    auto [internalName, info] = CreateBuiltinArraySignatureInfo(array_type, dim);
    auto *signature = CreateSignature(info, GlobalVoidType(), internalName);
    global_array_signatures_.insert({array_type, signature});

    return signature;
}
}  // namespace panda::es2panda::checker
