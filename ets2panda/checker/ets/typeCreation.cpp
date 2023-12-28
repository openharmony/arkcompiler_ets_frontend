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

#include "checker/ETSchecker.h"
#include "checker/ets/boxingConverter.h"
#include "checker/types/ets/byteType.h"
#include "checker/types/ets/charType.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "checker/types/ets/etsDynamicType.h"
#include "checker/types/ets/etsStringType.h"
#include "checker/types/ets/etsUnionType.h"
#include "checker/types/ets/shortType.h"
#include "generated/signatures.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsScript.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "parser/program/program.h"
#include "util/helpers.h"

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

ETSArrayType *ETSChecker::CreateETSArrayType(Type *elementType)
{
    auto res = arrayTypes_.find(elementType);

    if (res != arrayTypes_.end()) {
        return res->second;
    }

    auto *arrayType = Allocator()->New<ETSArrayType>(elementType);
    auto it = arrayTypes_.insert({elementType, arrayType});
    if (it.second && !elementType->IsETSTypeParameter()) {
        CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    return arrayType;
}

Type *ETSChecker::CreateETSUnionType(ArenaVector<Type *> &&constituentTypes)
{
    if (constituentTypes.empty()) {
        return nullptr;
    }

    ArenaVector<Type *> newConstituentTypes(Allocator()->Adapter());

    for (auto *it : constituentTypes) {
        newConstituentTypes.push_back(
            it->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE) ? BoxingConverter::ETSTypeFromSource(this, it) : it);
    }

    ETSUnionType::NormalizeTypes(Relation(), newConstituentTypes);
    if (newConstituentTypes.size() == 1) {
        return newConstituentTypes[0];
    }
    return Allocator()->New<ETSUnionType>(this, std::move(newConstituentTypes));
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(ArenaVector<Signature *> &signatures)
{
    auto *funcType = Allocator()->New<ETSFunctionType>(signatures[0]->Function()->Id()->Name(), Allocator());

    for (auto *it : signatures) {
        funcType->AddCallSignature(it);
    }

    return funcType;
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature)
{
    return Allocator()->New<ETSFunctionType>(signature->Function()->Id()->Name(), signature, Allocator());
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature, util::StringView name)
{
    return Allocator()->New<ETSFunctionType>(name, signature, Allocator());
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(ir::ScriptFunction *func, Signature *signature,
                                                   util::StringView name)
{
    if (func->IsDynamic()) {
        return Allocator()->New<ETSDynamicFunctionType>(name, signature, Allocator(), func->Language());
    }

    return Allocator()->New<ETSFunctionType>(name, signature, Allocator());
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *returnType, ir::ScriptFunction *func)
{
    return Allocator()->New<Signature>(info, returnType, func);
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *returnType, util::StringView internalName)
{
    return Allocator()->New<Signature>(info, returnType, internalName);
}

SignatureInfo *ETSChecker::CreateSignatureInfo()
{
    return Allocator()->New<SignatureInfo>(Allocator());
}

ETSTypeParameter *ETSChecker::CreateTypeParameter()
{
    return Allocator()->New<ETSTypeParameter>();
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(util::StringView name)
{
    return Allocator()->New<ETSFunctionType>(name, Allocator());
}

ETSExtensionFuncHelperType *ETSChecker::CreateETSExtensionFuncHelperType(ETSFunctionType *classMethodType,
                                                                         ETSFunctionType *extensionFunctionType)
{
    return Allocator()->New<ETSExtensionFuncHelperType>(classMethodType, extensionFunctionType);
}

ETSObjectType *ETSChecker::CreateETSObjectTypeCheckBuiltins(util::StringView name, ir::AstNode *declNode,
                                                            ETSObjectFlags flags)
{
    if (name == compiler::Signatures::BUILTIN_STRING_CLASS) {
        if (GlobalBuiltinETSStringType() != nullptr) {
            return GlobalBuiltinETSStringType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING_BUILTIN)] =
            CreateNewETSObjectType(name, declNode, flags | ETSObjectFlags::BUILTIN_STRING | ETSObjectFlags::STRING);

        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING)] =
            Allocator()->New<ETSStringType>(Allocator(), GlobalBuiltinETSStringType());
        return GlobalBuiltinETSStringType();
    }

    auto *objType = CreateNewETSObjectType(name, declNode, flags);

    if (name == compiler::Signatures::BUILTIN_OBJECT_CLASS) {
        if (GlobalETSObjectType() != nullptr) {
            return GlobalETSObjectType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_OBJECT_BUILTIN)] = objType;
        auto *nullish =
            CreateNullishType(objType, checker::TypeFlag::NULLISH, Allocator(), Relation(), GetGlobalTypesHolder());
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_NULLISH_OBJECT)] = nullish;
    } else if (name == compiler::Signatures::BUILTIN_EXCEPTION_CLASS) {
        if (GlobalBuiltinExceptionType() != nullptr) {
            return GlobalBuiltinExceptionType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_EXCEPTION_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_ERROR_CLASS) {
        if (GlobalBuiltinErrorType() != nullptr) {
            return GlobalBuiltinErrorType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_ERROR_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_TYPE_CLASS) {
        if (GlobalBuiltinTypeType() != nullptr) {
            return GlobalBuiltinTypeType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_TYPE_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_PROMISE_CLASS) {
        if (GlobalBuiltinPromiseType() != nullptr) {
            return GlobalBuiltinPromiseType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_PROMISE_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalETSObjectType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalETSObjectType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_BOOLEAN_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalETSBooleanType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalETSBooleanType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BOOLEAN_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_BYTE_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalByteType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalByteType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BYTE_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_CHAR_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalCharType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalCharType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_CHAR_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_SHORT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalShortType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalShortType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_SHORT_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_INT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalIntType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalIntType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_INT_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_LONG_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalLongType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalLongType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_LONG_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalFloatType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalFloatType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalFloatType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalFloatType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_FLOAT_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_DOUBLE_BOX_CLASS) {
        if (GlobalBuiltinBoxType(GlobalDoubleType()) != nullptr) {
            return GlobalBuiltinBoxType(GlobalDoubleType());
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_DOUBLE_BOX_BUILTIN)] = objType;
    } else if (name == compiler::Signatures::BUILTIN_VOID_CLASS) {
        if (GlobalBuiltinVoidType() != nullptr) {
            return GlobalBuiltinVoidType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<std::size_t>(GlobalTypeId::ETS_VOID_BUILTIN)] = objType;
    }

    return objType;
}

ETSObjectType *ETSChecker::CreateETSObjectType(util::StringView name, ir::AstNode *declNode, ETSObjectFlags flags)
{
    auto res = primitiveWrappers_.Wrappers().find(name);
    if (res == primitiveWrappers_.Wrappers().end()) {
        return CreateETSObjectTypeCheckBuiltins(name, declNode, flags);
    }

    if (res->second.first != nullptr) {
        return res->second.first;
    }

    auto *objType = CreateNewETSObjectType(name, declNode, flags | res->second.second);
    primitiveWrappers_.Wrappers().at(name).first = objType;
    return objType;
}

ETSEnumType *ETSChecker::CreateETSEnumType(ir::TSEnumDeclaration const *const enumDecl)
{
    varbinder::Variable *enumVar = enumDecl->Key()->Variable();
    ASSERT(enumVar != nullptr);

    ETSEnumType::UType ordinal = -1;
    auto *const enumType = Allocator()->New<ETSEnumType>(enumDecl, ordinal++);
    enumType->SetVariable(enumVar);
    enumVar->SetTsType(enumType);

    for (auto *const member : enumType->GetMembers()) {
        auto *const memberVar = member->AsTSEnumMember()->Key()->AsIdentifier()->Variable();
        auto *const enumLiteralType = Allocator()->New<ETSEnumType>(enumDecl, ordinal++, member->AsTSEnumMember());
        enumLiteralType->SetVariable(memberVar);
        memberVar->SetTsType(enumLiteralType);
    }

    auto *const namesArrayIdent = CreateEnumNamesArray(enumType);

    auto const getNameMethod = CreateEnumGetNameMethod(namesArrayIdent, enumType);
    enumType->SetGetNameMethod(getNameMethod);

    auto const valueOfMethod = CreateEnumValueOfMethod(namesArrayIdent, enumType);
    enumType->SetValueOfMethod(valueOfMethod);

    auto const fromIntMethod = CreateEnumFromIntMethod(namesArrayIdent, enumType);
    enumType->SetFromIntMethod(fromIntMethod);

    auto *const valuesArrayIdent = CreateEnumValuesArray(enumType);

    auto const getValueMethod = CreateEnumGetValueMethod(valuesArrayIdent, enumType);
    enumType->SetGetValueMethod(getValueMethod);

    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumType);

    auto const toStringMethod = CreateEnumToStringMethod(stringValuesArrayIdent, enumType);
    enumType->SetToStringMethod(toStringMethod);

    auto *const itemsArrayIdent = CreateEnumItemsArray(enumType);

    auto const valuesMethod = CreateEnumValuesMethod(itemsArrayIdent, enumType);
    enumType->SetValuesMethod(valuesMethod);

    for (auto *const member : enumType->GetMembers()) {
        auto *const enumLiteralType =
            member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType()->AsETSEnumType();
        enumLiteralType->SetGetValueMethod(getValueMethod);
        enumLiteralType->SetGetNameMethod(getNameMethod);
        enumLiteralType->SetToStringMethod(toStringMethod);
    }

    return enumType;
}

ETSStringEnumType *ETSChecker::CreateETSStringEnumType(ir::TSEnumDeclaration const *const enumDecl)
{
    varbinder::Variable *enumVar = enumDecl->Key()->Variable();
    ASSERT(enumVar != nullptr);

    ETSEnumType::UType ordinal = -1;
    auto *const enumType = Allocator()->New<ETSStringEnumType>(enumDecl, ordinal++);
    enumType->SetVariable(enumVar);
    enumVar->SetTsType(enumType);

    for (auto *const member : enumType->GetMembers()) {
        auto *const memberVar = member->AsTSEnumMember()->Key()->AsIdentifier()->Variable();
        auto *const enumLiteralType =
            Allocator()->New<ETSStringEnumType>(enumDecl, ordinal++, member->AsTSEnumMember());
        enumLiteralType->SetVariable(memberVar);
        memberVar->SetTsType(enumLiteralType);
    }

    auto *const namesArrayIdent = CreateEnumNamesArray(enumType);

    auto const getNameMethod = CreateEnumGetNameMethod(namesArrayIdent, enumType);
    enumType->SetGetNameMethod(getNameMethod);

    auto const valueOfMethod = CreateEnumValueOfMethod(namesArrayIdent, enumType);
    enumType->SetValueOfMethod(valueOfMethod);

    auto const fromIntMethod = CreateEnumFromIntMethod(namesArrayIdent, enumType);
    enumType->SetFromIntMethod(fromIntMethod);

    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumType);

    auto const toStringMethod = CreateEnumToStringMethod(stringValuesArrayIdent, enumType);
    enumType->SetToStringMethod(toStringMethod);
    enumType->SetGetValueMethod(toStringMethod);

    auto *const itemsArrayIdent = CreateEnumItemsArray(enumType);

    auto const valuesMethod = CreateEnumValuesMethod(itemsArrayIdent, enumType);
    enumType->SetValuesMethod(valuesMethod);

    for (auto *const member : enumType->GetMembers()) {
        auto *const enumLiteralType =
            member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType()->AsETSStringEnumType();
        enumLiteralType->SetGetValueMethod(toStringMethod);
        enumLiteralType->SetGetNameMethod(getNameMethod);
        enumLiteralType->SetToStringMethod(toStringMethod);
    }

    return enumType;
}

ETSObjectType *ETSChecker::CreateNewETSObjectType(util::StringView name, ir::AstNode *declNode, ETSObjectFlags flags)
{
    util::StringView assemblerName = name;
    util::StringView prefix {};

    auto *containingObjType = util::Helpers::GetContainingObjectType(declNode->Parent());

    if (containingObjType != nullptr) {
        prefix = containingObjType->AssemblerName();
    } else if (declNode->GetTopStatement()->Type() !=
               ir::AstNodeType::BLOCK_STATEMENT) {  // NOTE: should not occur, fix for TS_INTERFACE_DECLARATION
        ASSERT(declNode->IsTSInterfaceDeclaration());
        assemblerName = declNode->AsTSInterfaceDeclaration()->InternalName();
    } else {
        auto *program = static_cast<ir::ETSScript *>(declNode->GetTopStatement())->Program();
        prefix = program->GetPackageName();
    }

    if (!prefix.Empty()) {
        util::UString fullPath(prefix, Allocator());
        fullPath.Append('.');
        fullPath.Append(name);
        assemblerName = fullPath.View();
    }

    Language lang(Language::Id::ETS);
    bool hasDecl = false;

    if (declNode->IsClassDefinition()) {
        auto *clsDef = declNode->AsClassDefinition();
        lang = clsDef->Language();
        hasDecl = clsDef->IsDeclare();
    }

    if (declNode->IsTSInterfaceDeclaration()) {
        auto *ifaceDecl = declNode->AsTSInterfaceDeclaration();
        lang = ifaceDecl->Language();
        hasDecl = ifaceDecl->IsDeclare();
    }

    auto res = compiler::Signatures::Dynamic::LanguageFromType(assemblerName.Utf8());
    if (res) {
        lang = *res;
    }

    if (lang.IsDynamic()) {
        return Allocator()->New<ETSDynamicType>(Allocator(), name, assemblerName, declNode, flags, lang, hasDecl);
    }

    return Allocator()->New<ETSObjectType>(Allocator(), name, assemblerName, declNode, flags);
}

std::tuple<util::StringView, SignatureInfo *> ETSChecker::CreateBuiltinArraySignatureInfo(ETSArrayType *arrayType,
                                                                                          size_t dim)
{
    std::stringstream ss;
    arrayType->ToAssemblerTypeWithRank(ss);
    ss << compiler::Signatures::METHOD_SEPARATOR << compiler::Signatures::CTOR << compiler::Signatures::MANGLE_BEGIN;
    arrayType->ToAssemblerTypeWithRank(ss);

    auto *info = CreateSignatureInfo();
    info->minArgCount = dim;

    for (size_t i = 0; i < dim; i++) {
        util::UString param(std::to_string(i), Allocator());
        auto *paramVar =
            varbinder::Scope::CreateVar(Allocator(), param.View(), varbinder::VariableFlags::NONE, nullptr);
        paramVar->SetTsType(GlobalIntType());

        info->params.push_back(paramVar);

        ss << compiler::Signatures::MANGLE_SEPARATOR << compiler::Signatures::PRIMITIVE_INT;
    }

    ss << compiler::Signatures::MANGLE_SEPARATOR << compiler::Signatures::PRIMITIVE_VOID
       << compiler::Signatures::MANGLE_SEPARATOR;
    auto internalName = util::UString(ss.str(), Allocator()).View();

    return {internalName, info};
}

Signature *ETSChecker::CreateBuiltinArraySignature(ETSArrayType *arrayType, size_t dim)
{
    auto res = globalArraySignatures_.find(arrayType);

    if (res != globalArraySignatures_.end()) {
        return res->second;
    }

    auto [internalName, info] = CreateBuiltinArraySignatureInfo(arrayType, dim);
    auto *signature = CreateSignature(info, GlobalVoidType(), internalName);
    globalArraySignatures_.insert({arrayType, signature});

    return signature;
}
}  // namespace panda::es2panda::checker
