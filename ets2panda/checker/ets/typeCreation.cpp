/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "checker/types/globalTypesHolder.h"
#include "checker/types/ets/etsDynamicFunctionType.h"
#include "ir/statements/annotationDeclaration.h"

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

ETSArrayType *ETSChecker::CreateETSArrayType(Type *elementType, bool isCachePolluting)
{
    auto res = arrayTypes_.find({elementType, isCachePolluting});
    if (res != arrayTypes_.end()) {
        return res->second;
    }

    auto *arrayType = Allocator()->New<ETSArrayType>(elementType);

    std::stringstream ss;
    arrayType->ToAssemblerTypeWithRank(ss);
    // arrayType->SetAssemblerName(util::UString(ss.str(), Allocator()).View());

    auto it = arrayTypes_.insert({{elementType, isCachePolluting}, arrayType});
    if (it.second && (!elementType->IsTypeParameter() || !elementType->IsETSTypeParameter())) {
        CreateBuiltinArraySignature(arrayType, arrayType->Rank());
    }

    return arrayType;
}

namespace {
[[nodiscard]] checker::ETSFunctionType *MakeProxyFunctionType(
    checker::ETSChecker *const checker, const util::StringView &name,
    const std::initializer_list<varbinder::LocalVariable *> &params, ir::ScriptFunction *const globalFunction,
    checker::Type *const returnType)
{
    auto *const signatureInfo = checker->CreateSignatureInfo();
    signatureInfo->params.insert(signatureInfo->params.end(), params);
    signatureInfo->minArgCount = signatureInfo->params.size();

    auto *const signature = checker->CreateSignature(signatureInfo, returnType, globalFunction);
    signature->SetInternalName(name);
    signature->AddSignatureFlag(checker::SignatureFlags::PROXY);

    return checker->CreateETSMethodType(name, {{signature}, checker->Allocator()->Adapter()});
}

[[nodiscard]] checker::Signature *MakeGlobalSignature(checker::ETSChecker *const checker,
                                                      ir::ScriptFunction *const function,
                                                      checker::Type *const returnType)
{
    auto *const signatureInfo = checker->CreateSignatureInfo();
    signatureInfo->params.reserve(function->Params().size());
    for (const auto *const param : function->Params()) {
        signatureInfo->params.push_back(param->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }
    signatureInfo->minArgCount = signatureInfo->params.size();

    auto *const signature = checker->CreateSignature(signatureInfo, returnType, function);
    signature->AddSignatureFlag(checker::SignatureFlags::PUBLIC | checker::SignatureFlags::STATIC);
    function->SetSignature(signature);

    return signature;
}

void SetTypesForScriptFunction(checker::ETSChecker *const checker, ir::ScriptFunction *function)
{
    for (auto *const p : function->Params()) {
        auto *const param = p->AsETSParameterExpression();
        auto const paramType = param->TypeAnnotation()->Check(checker);
        param->SetTsType(paramType);
        param->Ident()->SetTsType(paramType);
        param->Ident()->Variable()->SetTsType(paramType);
    }
}

}  // namespace

ETSEnumType::Method ETSChecker::MakeMethod(ir::TSEnumDeclaration const *const enumDecl, const std::string_view &name,
                                           bool buildPorxyParam, Type *returnType, bool buildProxy)
{
    auto function = FindFunction(enumDecl, name);
    if (function == nullptr) {
        return {};
    }

    SetTypesForScriptFunction(this, function);

    if (buildPorxyParam) {
        return {MakeGlobalSignature(this, function, returnType),
                MakeProxyFunctionType(
                    this, name, {function->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable()},
                    function, returnType)};
    }
    return {MakeGlobalSignature(this, function, returnType),
            buildProxy ? MakeProxyFunctionType(this, name, {}, function, returnType) : nullptr};
}

[[nodiscard]] ir::ScriptFunction *ETSChecker::FindFunction(ir::TSEnumDeclaration const *const enumDecl,
                                                           const std::string_view &name)
{
    if (enumDecl->BoxedClass() == nullptr) {
        return nullptr;
    }

    for (auto m : enumDecl->BoxedClass()->Body()) {
        if (m->IsMethodDefinition()) {
            if (m->AsMethodDefinition()->Id()->Name() == name) {
                return m->AsMethodDefinition()->Function();
            }
        }
    }
    return nullptr;
}

template <typename EnumType>
// CC-OFFNXT(huge_method, G.FUN.01-CPP) solid logic
EnumType *ETSChecker::CreateEnumTypeFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl)
{
    static_assert(std::is_same_v<EnumType, ETSIntEnumType> || std::is_same_v<EnumType, ETSStringEnumType>);
    SavedCheckerContext savedContext(this, Context().Status(), Context().ContainingClass(),
                                     Context().ContainingSignature());

    varbinder::Variable *enumVar = enumDecl->Key()->Variable();
    ES2PANDA_ASSERT(enumVar != nullptr);

    checker::ETSEnumType::UType ordinal = -1;
    auto *const enumType = Allocator()->New<EnumType>(enumDecl, ordinal++);
    auto *const boxedEnumType = enumDecl->BoxedClass()->TsType();

    enumType->SetVariable(enumVar);
    enumVar->SetTsType(enumType);

    auto const getNameMethod =
        MakeMethod(enumDecl, ETSEnumType::GET_NAME_METHOD_NAME, false, GlobalETSStringLiteralType());
    enumType->SetGetNameMethod(getNameMethod);

    auto getValueOfMethod = MakeMethod(enumDecl, ETSEnumType::GET_VALUE_OF_METHOD_NAME, true, enumType);
    enumType->SetGetValueOfMethod(getValueOfMethod);

    auto const fromIntMethod = MakeMethod(enumDecl, ETSEnumType::FROM_INT_METHOD_NAME, false, enumType, false);
    enumType->SetFromIntMethod(fromIntMethod);

    auto const boxedFromIntMethod =
        MakeMethod(enumDecl, ETSEnumType::BOXED_FROM_INT_METHOD_NAME, false, boxedEnumType, false);
    enumType->SetBoxedFromIntMethod(boxedFromIntMethod);

    auto const unboxMethod = MakeMethod(enumDecl, ETSEnumType::UNBOX_METHOD_NAME, false, enumType);
    enumType->SetUnboxMethod(unboxMethod);

    auto const toStringMethod =
        MakeMethod(enumDecl, ETSEnumType::TO_STRING_METHOD_NAME, false, GlobalETSStringLiteralType());
    enumType->SetToStringMethod(toStringMethod);

    ETSEnumType::Method valueOfMethod = toStringMethod;
    if constexpr (std::is_same_v<EnumType, ETSIntEnumType>) {
        valueOfMethod = MakeMethod(enumDecl, ETSEnumType::VALUE_OF_METHOD_NAME, false, GlobalIntType());
    }
    enumType->SetValueOfMethod(valueOfMethod);

    auto const valuesMethod =
        MakeMethod(enumDecl, ETSEnumType::VALUES_METHOD_NAME, false, CreateETSArrayType(enumType));
    enumType->SetValuesMethod(valuesMethod);

    for (auto *const member : enumType->GetMembers()) {
        if (auto *const memberVar = member->AsTSEnumMember()->Key()->AsIdentifier()->Variable(); memberVar != nullptr) {
            auto *const enumLiteralType = Allocator()->New<EnumType>(enumDecl, ordinal++, member->AsTSEnumMember());
            enumLiteralType->SetVariable(memberVar);
            memberVar->SetTsType(enumLiteralType);

            enumLiteralType->SetGetNameMethod(getNameMethod);
            enumLiteralType->SetGetValueOfMethod(getValueOfMethod);
            enumLiteralType->SetFromIntMethod(fromIntMethod);
            enumLiteralType->SetBoxedFromIntMethod(boxedFromIntMethod);
            enumLiteralType->SetUnboxMethod(unboxMethod);
            enumLiteralType->SetValueOfMethod(valueOfMethod);
            enumLiteralType->SetToStringMethod(toStringMethod);
            enumLiteralType->SetValuesMethod(valuesMethod);
        } else {
            ASSERT(IsAnyError());
        }
    }
    return enumType;
}

ETSIntEnumType *ETSChecker::CreateEnumIntTypeFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl)
{
    auto etsEnumType = CreateEnumTypeFromEnumDeclaration<ETSIntEnumType>(enumDecl);
    enumDecl->SetTsType(etsEnumType);
    return etsEnumType;
}

ETSStringEnumType *ETSChecker::CreateEnumStringTypeFromEnumDeclaration(ir::TSEnumDeclaration *const enumDecl)
{
    auto etsEnumType = CreateEnumTypeFromEnumDeclaration<ETSStringEnumType>(enumDecl);
    enumDecl->SetTsType(etsEnumType);
    return etsEnumType;
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

ETSTypeAliasType *ETSChecker::CreateETSTypeAliasType(util::StringView name, const ir::AstNode *declNode,
                                                     bool isRecursive)
{
    return Allocator()->New<ETSTypeAliasType>(this, name, declNode, isRecursive);
}

ETSFunctionType *ETSChecker::CreateETSArrowType(Signature *signature)
{
    return Allocator()->New<ETSFunctionType>(this, signature);
}

ETSFunctionType *ETSChecker::CreateETSMethodType(util::StringView name, ArenaVector<Signature *> &&signatures)
{
    return Allocator()->New<ETSFunctionType>(this, name, std::move(signatures));
}

ETSFunctionType *ETSChecker::CreateETSDynamicArrowType(Signature *signature, Language lang)
{
    return Allocator()->New<ETSDynamicFunctionType>(this, signature, lang);
}

ETSFunctionType *ETSChecker::CreateETSDynamicMethodType(util::StringView name, ArenaVector<Signature *> &&signatures,
                                                        Language lang)
{
    return Allocator()->New<ETSDynamicFunctionType>(this, name, std::move(signatures), lang);
}

static SignatureFlags ConvertToSignatureFlags(ir::ModifierFlags inModifiers, ir::ScriptFunctionFlags inFunctionFlags)
{
    SignatureFlags outFlags = SignatureFlags::NO_OPTS;

    const auto convertModifier = [&outFlags, inModifiers](ir::ModifierFlags astFlag, SignatureFlags sigFlag) {
        if (inModifiers & astFlag) {
            outFlags |= sigFlag;
        }
    };
    const auto convertFlag = [&outFlags, inFunctionFlags](ir::ScriptFunctionFlags funcFlag, SignatureFlags sigFlag) {
        if (inFunctionFlags & funcFlag) {
            outFlags |= sigFlag;
        }
    };

    convertFlag(ir::ScriptFunctionFlags::THROWS, SignatureFlags::THROWS);
    convertFlag(ir::ScriptFunctionFlags::RETHROWS, SignatureFlags::RETHROWS);
    convertFlag(ir::ScriptFunctionFlags::INSTANCE_EXTENSION_METHOD, SignatureFlags::EXTENSION_FUNCTION);

    convertFlag(ir::ScriptFunctionFlags::CONSTRUCTOR, SignatureFlags::CONSTRUCTOR);
    convertFlag(ir::ScriptFunctionFlags::SETTER, SignatureFlags::SETTER);
    convertFlag(ir::ScriptFunctionFlags::GETTER, SignatureFlags::GETTER);

    convertModifier(ir::ModifierFlags::ABSTRACT, SignatureFlags::ABSTRACT);
    convertModifier(ir::ModifierFlags::PROTECTED, SignatureFlags::PROTECTED);
    convertModifier(ir::ModifierFlags::FINAL, SignatureFlags::FINAL);
    convertModifier(ir::ModifierFlags::STATIC, SignatureFlags::STATIC);
    convertModifier(ir::ModifierFlags::PUBLIC, SignatureFlags::PUBLIC);
    convertModifier(ir::ModifierFlags::PRIVATE, SignatureFlags::PRIVATE);
    convertModifier(ir::ModifierFlags::INTERNAL, SignatureFlags::INTERNAL);

    return outFlags;
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *returnType, ir::ScriptFunction *func)
{
    if (info == nullptr) {  // #23134
        ASSERT(IsAnyError());
        return nullptr;
    }
    auto signature = Allocator()->New<Signature>(info, returnType, func);
    signature->AddSignatureFlag(ConvertToSignatureFlags(func->Modifiers(), func->Flags()));
    return signature;
}

Signature *ETSChecker::CreateSignature(SignatureInfo *info, Type *returnType, ir::ScriptFunctionFlags sff)
{
    if (info == nullptr) {  // #23134
        ASSERT(IsAnyError());
        return nullptr;
    }
    auto signature = Allocator()->New<Signature>(info, returnType, nullptr);
    signature->AddSignatureFlag(ConvertToSignatureFlags(ir::ModifierFlags::NONE, sff));
    // synthetic arrow type signature flags
    signature->AddSignatureFlag(SignatureFlags::ABSTRACT | SignatureFlags::CALL | SignatureFlags::PUBLIC);
    return signature;
}

SignatureInfo *ETSChecker::CreateSignatureInfo()
{
    return Allocator()->New<SignatureInfo>(Allocator());
}

ETSTypeParameter *ETSChecker::CreateTypeParameter()
{
    return Allocator()->New<ETSTypeParameter>();
}

ETSExtensionFuncHelperType *ETSChecker::CreateETSExtensionFuncHelperType(ETSFunctionType *classMethodType,
                                                                         ETSFunctionType *extensionFunctionType)
{
    return Allocator()->New<ETSExtensionFuncHelperType>(classMethodType, extensionFunctionType);
}

static std::pair<util::StringView, util::StringView> GetObjectTypeDeclNames(ir::AstNode *node)
{
    if (node->IsClassDefinition()) {
        return {node->AsClassDefinition()->Ident()->Name(), node->AsClassDefinition()->InternalName()};
    }
    if (node->IsTSInterfaceDeclaration()) {
        return {node->AsTSInterfaceDeclaration()->Id()->Name(), node->AsTSInterfaceDeclaration()->InternalName()};
    }
    return {node->AsAnnotationDeclaration()->GetBaseName()->Name(), node->AsAnnotationDeclaration()->InternalName()};
}

// CC-OFFNXT(huge_method[C++], G.FUN.01-CPP) solid logic, big switch case
static ETSObjectType *InitializeGlobalBuiltinObjectType(ETSChecker *checker, GlobalTypeId globalId,
                                                        ir::AstNode *declNode, ETSObjectFlags flags)
{
    auto const create = [checker, declNode, flags](ETSObjectFlags addFlags = ETSObjectFlags::NO_OPTS) {
        return checker->CreateETSObjectType(declNode, flags | addFlags);
    };

    auto const setType = [checker](GlobalTypeId slotId, Type *type) {
        auto &slot = checker->GetGlobalTypesHolder()->GlobalTypes()[helpers::ToUnderlying(slotId)];
        if (slot == nullptr) {
            slot = type;
        }
        return slot;
    };

    auto *const allocator = checker->Allocator();

    switch (globalId) {
        case GlobalTypeId::ETS_OBJECT_BUILTIN: {
            auto *objType = setType(GlobalTypeId::ETS_OBJECT_BUILTIN, create())->AsETSObjectType();
            auto null = checker->GlobalETSNullType();
            auto undef = checker->GlobalETSUndefinedType();
            setType(GlobalTypeId::ETS_NULLISH_OBJECT, checker->CreateETSUnionType({objType, null, undef}));
            setType(GlobalTypeId::ETS_NULLISH_TYPE, checker->CreateETSUnionType({null, undef}));
            return objType;
        }
        case GlobalTypeId::ETS_STRING_BUILTIN: {
            auto *stringObj = setType(GlobalTypeId::ETS_STRING_BUILTIN,
                                      create(ETSObjectFlags::BUILTIN_STRING | ETSObjectFlags::STRING))
                                  ->AsETSObjectType();
            setType(GlobalTypeId::ETS_STRING, allocator->New<ETSStringType>(allocator, stringObj, checker->Relation()));
            return stringObj;
        }
        case GlobalTypeId::ETS_BIG_INT_BUILTIN: {
            auto *bigIntObj =
                setType(GlobalTypeId::ETS_BIG_INT_BUILTIN, create(ETSObjectFlags::BUILTIN_BIGINT))->AsETSObjectType();
            setType(GlobalTypeId::ETS_BIG_INT, allocator->New<ETSBigIntType>(allocator, bigIntObj));
            return bigIntObj;
        }
        case GlobalTypeId::ETS_BOOLEAN_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_BOOLEAN);
        case GlobalTypeId::ETS_BYTE_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_BYTE);
        case GlobalTypeId::ETS_CHAR_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_CHAR);
        case GlobalTypeId::ETS_SHORT_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_SHORT);
        case GlobalTypeId::ETS_INT_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_INT);
        case GlobalTypeId::ETS_LONG_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_LONG);
        case GlobalTypeId::ETS_FLOAT_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_FLOAT);
        case GlobalTypeId::ETS_DOUBLE_BUILTIN:
            return create(ETSObjectFlags::BUILTIN_DOUBLE);
        default:
            return create();
    }
}

ETSObjectType *ETSChecker::CreateETSObjectTypeOrBuiltin(ir::AstNode *declNode, ETSObjectFlags flags)
{
    if (LIKELY(HasStatus(CheckerStatus::BUILTINS_INITIALIZED))) {
        return CreateETSObjectType(declNode, flags);
    }
    auto const globalId = GetGlobalTypesHolder()->NameToId(GetObjectTypeDeclNames(declNode).first);
    if (!globalId.has_value()) {
        return CreateETSObjectType(declNode, flags);
    }
    return InitializeGlobalBuiltinObjectType(this, globalId.value(), declNode, flags);
}

std::tuple<Language, bool> ETSChecker::CheckForDynamicLang(ir::AstNode *declNode, util::StringView assemblerName)
{
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

    return std::make_tuple(lang, hasDecl);
}

ETSObjectType *ETSChecker::CreateETSObjectType(ir::AstNode *declNode, ETSObjectFlags flags)
{
    if (declNode->IsClassDefinition() && (declNode->AsClassDefinition()->OrigEnumDecl() != nullptr)) {
        flags |= ETSObjectFlags::BOXED_ENUM;
    }

    auto const [name, internalName] = GetObjectTypeDeclNames(declNode);

    if (auto [lang, hasDecl] = CheckForDynamicLang(declNode, internalName); lang.IsDynamic()) {
        return Allocator()->New<ETSDynamicType>(Allocator(), std::make_tuple(name, internalName, lang),
                                                std::make_tuple(declNode, flags, Relation()), hasDecl);
    }

    return Allocator()->New<ETSObjectType>(Allocator(), name, internalName,
                                           std::make_tuple(declNode, flags, Relation()));
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
    auto *signature = CreateSignature(info, GlobalVoidType(), ir::ScriptFunctionFlags::NONE);
    signature->SetInternalName(internalName);
    globalArraySignatures_.insert({arrayType, signature});

    return signature;
}

ETSObjectType *ETSChecker::CreatePromiseOf(Type *type)
{
    ETSObjectType *const promiseType = GlobalBuiltinPromiseType();
    ES2PANDA_ASSERT(promiseType->TypeArguments().size() == 1U);

    Substitution *substitution = NewSubstitution();
    EmplaceSubstituted(substitution, promiseType->TypeArguments()[0]->AsETSTypeParameter()->GetOriginal(), type);

    return promiseType->Substitute(Relation(), substitution);
}

}  // namespace ark::es2panda::checker
