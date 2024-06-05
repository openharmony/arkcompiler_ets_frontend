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

#include <functional>
#include "checker/ETSchecker.h"

#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/byteType.h"
#include "checker/types/ets/charType.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "checker/types/ets/etsDynamicType.h"
#include "checker/types/ets/etsStringType.h"
#include "checker/types/ets/etsUnionType.h"
#include "checker/types/ets/shortType.h"
#include "generated/signatures.h"
#include "ir/base/classDefinition.h"
#include "ir/statements/classDeclaration.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsScript.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "checker/ets/boxingConverter.h"
#include "util/helpers.h"
#include "checker/types/ts/bigintType.h"

namespace ark::es2panda::checker {
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

ETSBigIntType *ETSChecker::CreateETSBigIntLiteralType(util::StringView value)
{
    return Allocator()->New<ETSBigIntType>(Allocator(), GlobalBuiltinETSBigIntType(), Relation(), value);
}

ETSStringType *ETSChecker::CreateETSStringLiteralType(util::StringView value)
{
    return Allocator()->New<ETSStringType>(Allocator(), GlobalBuiltinETSStringType(), Relation(), value);
}

ETSArrayType *ETSChecker::CreateETSArrayType(Type *elementType)
{
    auto res = arrayTypes_.find(elementType);
    if (res != arrayTypes_.end()) {
        return res->second;
    }

    auto *arrayType = Allocator()->New<ETSArrayType>(elementType);

    std::stringstream ss;
    arrayType->ToAssemblerTypeWithRank(ss);
    arrayType->SetAssemblerName(util::UString(ss.str(), Allocator()).View());

    auto it = arrayTypes_.insert({elementType, arrayType});
    if (it.second && (!elementType->IsTypeParameter() || !elementType->IsETSTypeParameter())) {
        CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    return arrayType;
}

Type *ETSChecker::CreateETSUnionType(Span<Type *const> constituentTypes)
{
    if (constituentTypes.empty()) {
        return nullptr;
    }

    ArenaVector<Type *> newConstituentTypes(Allocator()->Adapter());
    newConstituentTypes.assign(constituentTypes.begin(), constituentTypes.end());

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

std::map<util::StringView, GlobalTypeId> &GetNameToTypeIdMap()
{
    static std::map<util::StringView, GlobalTypeId> nameToTypeId = {
        {compiler::Signatures::BUILTIN_BIGINT_CLASS, GlobalTypeId::ETS_BIG_INT_BUILTIN},
        {compiler::Signatures::BUILTIN_STRING_CLASS, GlobalTypeId::ETS_STRING_BUILTIN},
        {compiler::Signatures::BUILTIN_OBJECT_CLASS, GlobalTypeId::ETS_OBJECT_BUILTIN},
        {compiler::Signatures::BUILTIN_EXCEPTION_CLASS, GlobalTypeId::ETS_EXCEPTION_BUILTIN},
        {compiler::Signatures::BUILTIN_ERROR_CLASS, GlobalTypeId::ETS_ERROR_BUILTIN},
        {compiler::Signatures::BUILTIN_TYPE_CLASS, GlobalTypeId::ETS_TYPE_BUILTIN},
        {compiler::Signatures::BUILTIN_PROMISE_CLASS, GlobalTypeId::ETS_PROMISE_BUILTIN},
        {compiler::Signatures::BUILTIN_BOX_CLASS, GlobalTypeId::ETS_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_BOOLEAN_BOX_CLASS, GlobalTypeId::ETS_BOOLEAN_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_BYTE_BOX_CLASS, GlobalTypeId::ETS_BYTE_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_CHAR_BOX_CLASS, GlobalTypeId::ETS_CHAR_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_SHORT_BOX_CLASS, GlobalTypeId::ETS_SHORT_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_INT_BOX_CLASS, GlobalTypeId::ETS_INT_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_LONG_BOX_CLASS, GlobalTypeId::ETS_LONG_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS, GlobalTypeId::ETS_FLOAT_BOX_BUILTIN},
        {compiler::Signatures::BUILTIN_DOUBLE_BOX_CLASS, GlobalTypeId::ETS_DOUBLE_BOX_BUILTIN},
    };

    return nameToTypeId;
}

std::map<util::StringView, std::function<ETSObjectType *(const ETSChecker *)>> &GetNameToGlobalTypeMap()
{
    static std::map<util::StringView, std::function<ETSObjectType *(const ETSChecker *)>> nameToGlobalType = {
        {compiler::Signatures::BUILTIN_BIGINT_CLASS, &ETSChecker::GlobalBuiltinETSBigIntType},
        {compiler::Signatures::BUILTIN_STRING_CLASS, &ETSChecker::GlobalBuiltinETSStringType},
        {compiler::Signatures::BUILTIN_OBJECT_CLASS, &ETSChecker::GlobalETSObjectType},
        {compiler::Signatures::BUILTIN_EXCEPTION_CLASS, &ETSChecker::GlobalBuiltinExceptionType},
        {compiler::Signatures::BUILTIN_ERROR_CLASS, &ETSChecker::GlobalBuiltinErrorType},
        {compiler::Signatures::BUILTIN_TYPE_CLASS, &ETSChecker::GlobalBuiltinTypeType},
        {compiler::Signatures::BUILTIN_PROMISE_CLASS, &ETSChecker::GlobalBuiltinPromiseType},
    };

    return nameToGlobalType;
}

std::map<util::StringView, std::function<Type *(const ETSChecker *)>> &GetNameToGlobalBoxTypeMap()
{
    static std::map<util::StringView, std::function<Type *(const ETSChecker *)>> nameToGlobalBoxType = {
        {compiler::Signatures::BUILTIN_BOX_CLASS, &ETSChecker::GlobalETSObjectType},
        {compiler::Signatures::BUILTIN_BOOLEAN_BOX_CLASS, &ETSChecker::GlobalETSBooleanType},
        {compiler::Signatures::BUILTIN_BYTE_BOX_CLASS, &ETSChecker::GlobalByteType},
        {compiler::Signatures::BUILTIN_CHAR_BOX_CLASS, &ETSChecker::GlobalCharType},
        {compiler::Signatures::BUILTIN_SHORT_BOX_CLASS, &ETSChecker::GlobalShortType},
        {compiler::Signatures::BUILTIN_INT_BOX_CLASS, &ETSChecker::GlobalIntType},
        {compiler::Signatures::BUILTIN_LONG_BOX_CLASS, &ETSChecker::GlobalLongType},
        {compiler::Signatures::BUILTIN_FLOAT_BOX_CLASS, &ETSChecker::GlobalFloatType},
        {compiler::Signatures::BUILTIN_DOUBLE_BOX_CLASS, &ETSChecker::GlobalDoubleType},
    };

    return nameToGlobalBoxType;
}

ETSObjectType *ETSChecker::UpdateBoxedGlobalType(ETSObjectType *objType, util::StringView name)
{
    auto nameToGlobalBoxType = GetNameToGlobalBoxTypeMap();
    auto nameToTypeId = GetNameToTypeIdMap();

    if (nameToGlobalBoxType.find(name) != nameToGlobalBoxType.end()) {
        std::function<Type *(const ETSChecker *)> globalType = nameToGlobalBoxType[name];
        if (GlobalBuiltinBoxType(globalType(this)) != nullptr) {
            return GlobalBuiltinBoxType(globalType(this));
        }

        auto id = nameToTypeId.find(name);
        if (id != nameToTypeId.end()) {
            GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(id->second)] = objType;
        }
    }

    return objType;
}

ETSObjectType *ETSChecker::UpdateGlobalType(ETSObjectType *objType, util::StringView name)
{
    auto nameToGlobalType = GetNameToGlobalTypeMap();
    auto nameToTypeId = GetNameToTypeIdMap();

    if (nameToGlobalType.find(name) != nameToGlobalType.end()) {
        std::function<ETSObjectType *(const ETSChecker *)> globalType = nameToGlobalType[name];
        if (globalType(this) != nullptr) {
            return globalType(this);
        }

        auto id = nameToTypeId.find(name);
        if (id != nameToTypeId.end()) {
            GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(id->second)] = objType;
        }

        if (name == compiler::Signatures::BUILTIN_OBJECT_CLASS) {
            auto *nullish = CreateETSUnionType({objType, GlobalETSNullType(), GlobalETSUndefinedType()});
            GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_NULLISH_OBJECT)] = nullish;
            nullish = CreateETSUnionType({GlobalETSNullType(), GlobalETSUndefinedType()});
            GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_NULLISH_TYPE)] = nullish;
        }
    }

    return objType;
}

ETSObjectType *ETSChecker::CreateETSObjectTypeCheckBuiltins(util::StringView name, ir::AstNode *declNode,
                                                            ETSObjectFlags flags)
{
    if (name == compiler::Signatures::BUILTIN_BIGINT_CLASS) {
        if (GlobalBuiltinETSBigIntType() != nullptr) {
            return GlobalBuiltinETSBigIntType();
        }

        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BIG_INT_BUILTIN)] =
            CreateNewETSObjectType(name, declNode, flags | ETSObjectFlags::BUILTIN_BIGINT);
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_BIG_INT)] =
            Allocator()->New<ETSBigIntType>(Allocator(), GlobalBuiltinETSBigIntType());

        return GlobalBuiltinETSBigIntType();
    }

    if (name == compiler::Signatures::BUILTIN_STRING_CLASS) {
        if (GlobalBuiltinETSStringType() != nullptr) {
            return GlobalBuiltinETSStringType();
        }
        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING_BUILTIN)] =
            CreateNewETSObjectType(name, declNode, flags | ETSObjectFlags::BUILTIN_STRING | ETSObjectFlags::STRING);

        GetGlobalTypesHolder()->GlobalTypes()[static_cast<size_t>(GlobalTypeId::ETS_STRING)] =
            Allocator()->New<ETSStringType>(Allocator(), GlobalBuiltinETSStringType(), Relation());
        return GlobalBuiltinETSStringType();
    }

    auto *objType = CreateNewETSObjectType(name, declNode, flags);
    auto nameToGlobalBoxType = GetNameToGlobalBoxTypeMap();
    if (nameToGlobalBoxType.find(name) != nameToGlobalBoxType.end()) {
        return UpdateBoxedGlobalType(objType, name);
    }

    return UpdateGlobalType(objType, name);
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

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const namesArrayIdent = CreateEnumNamesArray(enumType);

    auto *identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const getNameMethod = CreateEnumGetNameMethod(identClone, enumType);
    enumType->SetGetNameMethod(getNameMethod);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const valueOfMethod = CreateEnumValueOfMethod(identClone, enumType);
    enumType->SetValueOfMethod(valueOfMethod);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const fromIntMethod = CreateEnumFromIntMethod(identClone, enumType);
    enumType->SetFromIntMethod(fromIntMethod);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const valuesArrayIdent = CreateEnumValuesArray(enumType);

    identClone = valuesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(valuesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const getValueMethod = CreateEnumGetValueMethod(identClone, enumType);
    enumType->SetGetValueMethod(getValueMethod);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumType);

    identClone = stringValuesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(stringValuesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const toStringMethod = CreateEnumToStringMethod(identClone, enumType);
    enumType->SetToStringMethod(toStringMethod);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumType);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(itemsArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const valuesMethod = CreateEnumValuesMethod(identClone, enumType);
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

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const namesArrayIdent = CreateEnumNamesArray(enumType);

    auto *identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const getNameMethod = CreateEnumGetNameMethod(identClone, enumType);
    enumType->SetGetNameMethod(getNameMethod);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const valueOfMethod = CreateEnumValueOfMethod(identClone, enumType);
    enumType->SetValueOfMethod(valueOfMethod);

    identClone = namesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(namesArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const fromIntMethod = CreateEnumFromIntMethod(identClone, enumType);
    enumType->SetFromIntMethod(fromIntMethod);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const stringValuesArrayIdent = CreateEnumStringValuesArray(enumType);

    identClone = stringValuesArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(stringValuesArrayIdent->TsType());
    auto const toStringMethod = CreateEnumToStringMethod(identClone, enumType);
    enumType->SetToStringMethod(toStringMethod);
    enumType->SetGetValueMethod(toStringMethod);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *const itemsArrayIdent = CreateEnumItemsArray(enumType);

    identClone = itemsArrayIdent->Clone(Allocator(), nullptr);
    identClone->SetTsType(itemsArrayIdent->TsType());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto const valuesMethod = CreateEnumValuesMethod(identClone, enumType);
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

    if (declNode->IsClassDefinition()) {
        if (declNode->AsClassDefinition()->IsLocal()) {
            util::UString localName(declNode->AsClassDefinition()->LocalPrefix(), Allocator());
            localName.Append(name);
            assemblerName = localName.View();
        }
    }

    if (containingObjType != nullptr) {
        prefix = containingObjType->AssemblerName();
    } else if (const auto *topStatement = declNode->GetTopStatement();
               topStatement->Type() !=
               ir::AstNodeType::ETS_SCRIPT) {  // NOTE: should not occur, fix for TS_INTERFACE_DECLARATION
        ASSERT(declNode->IsTSInterfaceDeclaration());
        assemblerName = declNode->AsTSInterfaceDeclaration()->InternalName();
    } else {
        prefix = static_cast<ir::ETSScript *>(declNode->GetTopStatement())->Program()->GetPackageName();
    }

    if (!prefix.Empty()) {
        util::UString fullPath(prefix, Allocator());
        fullPath.Append('.');
        fullPath.Append(assemblerName);
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
        return Allocator()->New<ETSDynamicType>(Allocator(), name, assemblerName, declNode, flags, Relation(), lang,
                                                hasDecl);
        ;
    }

    return Allocator()->New<ETSObjectType>(Allocator(), name, assemblerName, declNode, flags, Relation());
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
}  // namespace ark::es2panda::checker
