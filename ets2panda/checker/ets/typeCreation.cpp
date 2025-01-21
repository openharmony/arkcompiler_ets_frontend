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
#include "ir/ets/etsModule.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "util/helpers.h"

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

    auto *const signature = checker->CreateSignature(signatureInfo, returnType, name);
    signature->SetFunction(globalFunction);
    signature->AddSignatureFlag(checker::SignatureFlags::PROXY);

    return checker->CreateETSFunctionType(signature, name);
}

[[nodiscard]] checker::Signature *MakeGlobalSignature(checker::ETSChecker *const checker,
                                                      ir::ScriptFunction *const function,
                                                      checker::Type *const returnType)
{
    auto *const signatureInfo = checker->CreateSignatureInfo();
    signatureInfo->params.reserve(function->Params().size());
    for (const auto *const item : function->Params()) {
        auto const *const param = item->AsETSParameterExpression();
        auto *const var = param->Variable()->AsLocalVariable();
        if (!param->IsDefault()) {
            ++signatureInfo->minArgCount;
        } else {
            var->AddFlag(varbinder::VariableFlags::OPTIONAL);
        }
        signatureInfo->params.emplace_back(var);
    }

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
EnumType *ETSChecker::CreateEnumTypeFromEnumDeclaration(ir::TSEnumDeclaration const *const enumDecl)
{
    static_assert(std::is_same_v<EnumType, ETSIntEnumType> || std::is_same_v<EnumType, ETSStringEnumType>);
    SavedCheckerContext savedContext(this, Context().Status(), Context().ContainingClass(),
                                     Context().ContainingSignature());

    varbinder::Variable *enumVar = enumDecl->Key()->Variable();
    ASSERT(enumVar != nullptr);

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
    if (std::is_same_v<EnumType, ETSIntEnumType>) {
        valueOfMethod = MakeMethod(enumDecl, ETSEnumType::VALUE_OF_METHOD_NAME, false, GlobalIntType());
    }
    enumType->SetValueOfMethod(valueOfMethod);

    auto const valuesMethod =
        MakeMethod(enumDecl, ETSEnumType::VALUES_METHOD_NAME, false, CreateETSArrayType(enumType));
    enumType->SetValuesMethod(valuesMethod);

    for (auto *const member : enumType->GetMembers()) {
        auto *const memberVar = member->AsTSEnumMember()->Key()->AsIdentifier()->Variable();
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

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature)
{
    return Allocator()->New<ETSFunctionType>(this, signature->Function()->Id()->Name(), signature);
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(Signature *signature, util::StringView const &name)
{
    return Allocator()->New<ETSFunctionType>(this, name, signature);
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(ir::ScriptFunction *func, Signature *signature,
                                                   util::StringView const &name)
{
    if (func->IsDynamic()) {
        return Allocator()->New<ETSDynamicFunctionType>(this, name, signature, func->Language());
    }

    return Allocator()->New<ETSFunctionType>(this, name, signature);
}

ETSFunctionType *ETSChecker::CreateETSFunctionType(util::StringView const &name)
{
    return Allocator()->New<ETSFunctionType>(name, Allocator());
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
        ASSERT(slot == nullptr);
        slot = type;
    };

    auto const allocator = checker->Allocator();

    switch (globalId) {
        case GlobalTypeId::ETS_OBJECT_BUILTIN: {
            auto objType = create();
            setType(GlobalTypeId::ETS_OBJECT_BUILTIN, objType);
            auto null = checker->GlobalETSNullType();
            auto undef = checker->GlobalETSUndefinedType();
            setType(GlobalTypeId::ETS_NULLISH_OBJECT, checker->CreateETSUnionType({objType, null, undef}));
            setType(GlobalTypeId::ETS_NULLISH_TYPE, checker->CreateETSUnionType({null, undef}));
            return objType;
        }
        case GlobalTypeId::ETS_STRING_BUILTIN: {
            auto stringObj = create(ETSObjectFlags::BUILTIN_STRING | ETSObjectFlags::STRING);
            setType(GlobalTypeId::ETS_STRING_BUILTIN, stringObj);
            setType(GlobalTypeId::ETS_STRING, allocator->New<ETSStringType>(allocator, stringObj, checker->Relation()));
            return stringObj;
        }
        case GlobalTypeId::ETS_BIG_INT_BUILTIN: {
            auto bigIntObj = create(ETSObjectFlags::BUILTIN_BIGINT);
            setType(GlobalTypeId::ETS_BIG_INT_BUILTIN, bigIntObj);
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
    auto *signature = CreateSignature(info, GlobalVoidType(), internalName);
    globalArraySignatures_.insert({arrayType, signature});

    return signature;
}

void ETSChecker::AddThisReturnTypeFlagForInterfaceInvoke(ETSObjectType *interface)
{
    auto &callSigsOfInvoke0 =
        interface->AsETSObjectType()
            ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME)
            ->TsType()
            ->AsETSFunctionType()
            ->CallSignatures();
    for (auto sig : callSigsOfInvoke0) {
        sig->AddSignatureFlag(SignatureFlags::EXTENSION_FUNCTION_RETURN_THIS);
    }
}

ETSObjectType *ETSChecker::FunctionTypeToFunctionalInterfaceType(Signature *signature)
{
    ir::ScriptFunctionFlags flags = ir::ScriptFunctionFlags::NONE;
    if (signature->Function() != nullptr) {
        flags = signature->Function()->Flags();
    } else {
        if (signature->Throws()) {
            flags |= ir::ScriptFunctionFlags::THROWS;
        } else if (signature->Rethrows()) {
            flags |= ir::ScriptFunctionFlags::RETHROWS;
        }
    }

    auto *retType = signature->ReturnType();
    if (signature->RestVar() != nullptr) {
        auto *functionN =
            GlobalBuiltinFunctionType(GlobalBuiltinFunctionTypeVariadicThreshold(), flags)->AsETSObjectType();
        auto *substitution = NewSubstitution();
        substitution->emplace(functionN->TypeArguments()[0]->AsETSTypeParameter(), MaybeBoxType(retType));
        return functionN->Substitute(Relation(), substitution, signature->Function()->IsExtensionMethod());
    }

    // Note: FunctionN is not supported yet
    if (signature->Params().size() >= GetGlobalTypesHolder()->VariadicFunctionTypeThreshold()) {
        return nullptr;
    }

    auto *funcIface = GlobalBuiltinFunctionType(signature->Params().size(), flags)->AsETSObjectType();
    auto *substitution = NewSubstitution();

    for (size_t i = 0; i < signature->Params().size(); i++) {
        substitution->emplace(funcIface->TypeArguments()[i]->AsETSTypeParameter(),
                              MaybeBoxType(signature->Params()[i]->TsType()));
    }
    substitution->emplace(funcIface->TypeArguments()[signature->Params().size()]->AsETSTypeParameter(),
                          MaybeBoxType(signature->ReturnType()));

    auto *interFaceType =
        funcIface->Substitute(Relation(), substitution, true, signature->Function()->IsExtensionMethod());
    if (signature->HasSignatureFlag(SignatureFlags::EXTENSION_FUNCTION_RETURN_THIS)) {
        AddThisReturnTypeFlagForInterfaceInvoke(interFaceType);
    }
    return interFaceType;
}

ETSObjectType *ETSChecker::CreatePromiseOf(Type *type)
{
    ETSObjectType *const promiseType = GlobalBuiltinPromiseType();
    ASSERT(promiseType->TypeArguments().size() == 1);
    Substitution *substitution = NewSubstitution();
    ETSChecker::EmplaceSubstituted(substitution, promiseType->TypeArguments()[0]->AsETSTypeParameter()->GetOriginal(),
                                   type);

    return promiseType->Substitute(Relation(), substitution);
}

SignatureInfo *ETSChecker::ComposeSignatureInfo(ir::ETSFunctionType *typeNode)
{
    auto *signatureInfo = CreateSignatureInfo();

    if (auto const *const typeParams = typeNode->TypeParams(); typeParams != nullptr) {
        auto [typeParamTypes, ok] = CreateUnconstrainedTypeParameters(typeParams);
        signatureInfo->typeParams = std::move(typeParamTypes);
        if (ok) {
            AssignTypeParameterConstraints(typeParams);
        }
    }

    for (auto *const it : typeNode->Params()) {
        auto *const param = it->AsETSParameterExpression();
        auto *const ident = param->Ident();
        auto *const variable = param->Variable()->AsLocalVariable();
        auto *const typeAnnotation = param->TypeAnnotation();
        ASSERT(variable != nullptr);

        if (LIKELY(!param->IsRestParameter())) {
            if (ident->TsType() == nullptr && typeAnnotation == nullptr) {
                LogTypeError({"The type of parameter '", param->Name(), "' cannot be inferred."}, param->Start());
                variable->SetTsType(GlobalTypeError());
                ident->SetTsType(GlobalTypeError());
            } else if (typeAnnotation != nullptr) {
                variable->SetTsType(typeAnnotation->GetType(this));
                ident->SetTsType(variable->TsType());  // just in case!
            } else {
                variable->SetTsType(ident->TsType());
            }
            if (!param->IsDefault()) {
                ++signatureInfo->minArgCount;
            } else {
                variable->AddFlag(varbinder::VariableFlags::OPTIONAL);
            }
            signatureInfo->params.emplace_back(variable);
        } else {
            ASSERT(typeAnnotation != nullptr);
            variable->SetTsType(typeAnnotation->GetType(this));
            ident->SetTsType(variable->TsType());
            signatureInfo->restVar = variable;

            auto arrayType = signatureInfo->restVar->TsType()->AsETSArrayType();
            CreateBuiltinArraySignature(arrayType, arrayType->Rank());
        }
    }

    return signatureInfo;
}

Type *ETSChecker::ComposeReturnType(ir::ETSFunctionType *typeNode)
{
    auto *const returnTypeAnnotation = typeNode->ReturnType();
    checker::Type *returnType = GlobalVoidType();

    if (UNLIKELY(returnTypeAnnotation == nullptr)) {
        if ((typeNode->Flags() & ir::ScriptFunctionFlags::ASYNC) !=
            std::underlying_type_t<ir::ScriptFunctionFlags>(0U)) {
            auto implicitPromiseVoid = [this]() {
                const auto &promiseGlobal = GlobalBuiltinPromiseType()->AsETSObjectType();
                auto substitution = NewSubstitution();
                ETSChecker::EmplaceSubstituted(substitution, promiseGlobal->TypeArguments()[0]->AsETSTypeParameter(),
                                               GlobalVoidType());
                return promiseGlobal->Substitute(Relation(), substitution);
            };

            returnType = implicitPromiseVoid();
        }
    } else {
        returnType = returnTypeAnnotation->GetType(this);
        returnTypeAnnotation->SetTsType(returnType);
    }

    return returnType;
}

}  // namespace ark::es2panda::checker
