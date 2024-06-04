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

#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/function_helpers.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"
#include "checker/types/ets/etsObjectType.h"
#include "ir/base/catchClause.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/forInStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "parser/program/program.h"
#include "util/helpers.h"
#include "util/language.h"

namespace ark::es2panda::checker {

// NOTE: #14993 merge with InstantiationContext::ValidateTypeArg
bool ETSChecker::IsCompatibleTypeArgument(ETSTypeParameter *typeParam, Type *typeArgument,
                                          const Substitution *substitution)
{
    if (typeArgument->IsWildcardType()) {
        return true;
    }
    ASSERT(IsReferenceType(typeArgument));
    auto *constraint = typeParam->GetConstraintType()->Substitute(Relation(), substitution);
    return Relation()->IsSupertypeOf(constraint, typeArgument);
}

/* A very rough and imprecise partial type inference */
bool ETSChecker::EnhanceSubstitutionForType(const ArenaVector<Type *> &typeParams, Type *paramType, Type *argumentType,
                                            Substitution *substitution)
{
    if (argumentType->HasTypeFlag(TypeFlag::ETS_PRIMITIVE)) {
        argumentType = PrimitiveTypeAsETSBuiltinType(argumentType);
    }
    if (paramType->IsETSTypeParameter()) {
        auto *const tparam = paramType->AsETSTypeParameter();
        auto *const originalTparam = tparam->GetOriginal();
        if (std::find(typeParams.begin(), typeParams.end(), originalTparam) != typeParams.end() &&
            substitution->count(originalTparam) == 0) {
            if (!IsCompatibleTypeArgument(tparam, argumentType, substitution)) {
                return false;
            }
            if (substitution->find(originalTparam) != substitution->end() &&
                substitution->at(originalTparam) != argumentType) {
                ThrowTypeError({"Type parameter already instantiated with another type "},
                               tparam->GetDeclNode()->Start());
            }
            ETSChecker::EmplaceSubstituted(substitution, originalTparam, argumentType);
            return true;
        }
    }

    if (paramType->IsETSUnionType()) {
        return EnhanceSubstitutionForUnion(typeParams, paramType->AsETSUnionType(), argumentType, substitution);
    }
    if (paramType->IsETSObjectType()) {
        return EnhanceSubstitutionForObject(typeParams, paramType->AsETSObjectType(), argumentType, substitution);
    }
    if (paramType->IsETSArrayType()) {
        return EnhanceSubstitutionForArray(typeParams, paramType->AsETSArrayType(), argumentType, substitution);
    }

    return true;
}

bool ETSChecker::EnhanceSubstitutionForUnion(const ArenaVector<Type *> &typeParams, ETSUnionType *paramUn,
                                             Type *argumentType, Substitution *substitution)
{
    if (!argumentType->IsETSUnionType()) {
        for (auto *ctype : paramUn->ConstituentTypes()) {
            if (!EnhanceSubstitutionForType(typeParams, ctype, argumentType, substitution)) {
                return false;
            }
        }
        return true;
    }
    auto *const argUn = argumentType->AsETSUnionType();

    ArenaVector<Type *> paramWlist(Allocator()->Adapter());
    ArenaVector<Type *> argWlist(Allocator()->Adapter());

    for (auto *pc : paramUn->ConstituentTypes()) {
        for (auto *ac : argUn->ConstituentTypes()) {
            if (ETSChecker::GetOriginalBaseType(pc) != ETSChecker::GetOriginalBaseType(ac)) {
                paramWlist.push_back(pc);
                argWlist.push_back(ac);
                continue;
            }
            if (!EnhanceSubstitutionForType(typeParams, pc, ac, substitution)) {
                return false;
            }
        }
    }
    auto *const newArg = CreateETSUnionType(std::move(argWlist));

    for (auto *pc : paramWlist) {
        if (!EnhanceSubstitutionForType(typeParams, pc, newArg, substitution)) {
            return false;
        }
    }
    return true;
}

bool ETSChecker::EnhanceSubstitutionForObject(const ArenaVector<Type *> &typeParams, ETSObjectType *paramType,
                                              Type *argumentType, Substitution *substitution)
{
    auto *paramObjType = paramType->AsETSObjectType();

    auto const enhance = [this, typeParams, substitution](Type *ptype, Type *atype) {
        return EnhanceSubstitutionForType(typeParams, ptype, atype, substitution);
    };

    if (argumentType->IsETSObjectType()) {
        auto *argObjType = argumentType->AsETSObjectType();
        if (GetOriginalBaseType(argObjType) != GetOriginalBaseType(paramObjType)) {
            return true;  // don't attempt anything fancy for now
        }
        bool res = true;
        for (size_t ix = 0; ix < argObjType->TypeArguments().size(); ix++) {
            res &= enhance(paramObjType->TypeArguments()[ix], argObjType->TypeArguments()[ix]);
        }
        return res;
    }

    if (argumentType->IsETSFunctionType() && paramObjType->HasObjectFlag(ETSObjectFlags::FUNCTIONAL_INTERFACE)) {
        auto &parameterSignatures =
            paramObjType
                ->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME)
                ->TsType()
                ->AsETSFunctionType()
                ->CallSignatures();
        auto &argumentSignatures = argumentType->AsETSFunctionType()->CallSignatures();
        ASSERT(argumentSignatures.size() == 1);
        ASSERT(parameterSignatures.size() == 1);
        auto *argumentSignature = argumentSignatures[0];
        auto *parameterSignature = parameterSignatures[0];
        // NOTE(gogabr): handle rest parameter for argumentSignature
        if (parameterSignature->GetSignatureInfo()->params.size() !=
            argumentSignature->GetSignatureInfo()->params.size()) {
            return false;
        }
        bool res = true;
        for (size_t idx = 0; idx < argumentSignature->GetSignatureInfo()->params.size(); idx++) {
            res &= enhance(parameterSignature->GetSignatureInfo()->params[idx]->TsType(),
                           argumentSignature->GetSignatureInfo()->params[idx]->TsType());
        }
        res &= enhance(parameterSignature->ReturnType(), argumentSignature->ReturnType());
        return res;
    }

    return true;
}

bool ETSChecker::EnhanceSubstitutionForArray(const ArenaVector<Type *> &typeParams, ETSArrayType *const paramType,
                                             Type *const argumentType, Substitution *const substitution)
{
    auto *const elementType =
        argumentType->IsETSArrayType() ? argumentType->AsETSArrayType()->ElementType() : argumentType;

    return EnhanceSubstitutionForType(typeParams, paramType->ElementType(), elementType, substitution);
}

Signature *ETSChecker::ValidateParameterlessConstructor(Signature *signature, const lexer::SourcePosition &pos,
                                                        TypeRelationFlag flags)
{
    std::size_t const parameterCount = signature->MinArgCount();
    auto const throwError = (flags & TypeRelationFlag::NO_THROW) == 0;

    if (parameterCount != 0) {
        if (throwError) {
            ThrowTypeError({"No Matching Parameterless Constructor, parameter count ", parameterCount}, pos);
        }
        return nullptr;
    }
    return signature;
}

bool ETSChecker::CheckOptionalLambdaFunction(ir::Expression *argument, Signature *substitutedSig, std::size_t index)
{
    if (argument->IsArrowFunctionExpression()) {
        auto *const arrowFuncExpr = argument->AsArrowFunctionExpression();

        if (ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
            CheckLambdaAssignable(substitutedSig->Function()->Params()[index], lambda)) {
            if (arrowFuncExpr->TsType() != nullptr) {
                arrowFuncExpr->Check(this);
                CreateLambdaObjectForLambdaReference(arrowFuncExpr, arrowFuncExpr->Function()->Signature()->Owner());
                return true;
            }
        }
    }

    return false;
}

bool ETSChecker::ValidateArgumentAsIdentifier(const ir::Identifier *identifier)
{
    auto result = Scope()->Find(identifier->Name());
    return result.variable != nullptr && (result.variable->HasFlag(varbinder::VariableFlags::CLASS_OR_INTERFACE));
}

bool ETSChecker::ValidateSignatureRequiredParams(Signature *substitutedSig,
                                                 const ArenaVector<ir::Expression *> &arguments, TypeRelationFlag flags,
                                                 const std::vector<bool> &argTypeInferenceRequired, bool throwError)
{
    std::size_t const argumentCount = arguments.size();
    std::size_t const parameterCount = substitutedSig->MinArgCount();
    auto count = std::min(parameterCount, argumentCount);
    for (std::size_t index = 0; index < count; ++index) {
        auto &argument = arguments[index];

        if (argument->IsObjectExpression()) {
            if (substitutedSig->Params()[index]->TsType()->IsETSObjectType()) {
                // No chance to check the argument at this point
                continue;
            }
            return false;
        }

        if (argument->IsMemberExpression()) {
            SetArrayPreferredTypeForNestedMemberExpressions(arguments[index]->AsMemberExpression(),
                                                            substitutedSig->Params()[index]->TsType());
        } else if (argument->IsSpreadElement()) {
            if (throwError) {
                ThrowTypeError("Spread argument cannot be passed for ordinary parameter.", argument->Start());
            }
            return false;
        }

        if (argTypeInferenceRequired[index]) {
            ASSERT(argument->IsArrowFunctionExpression());
            auto *const arrowFuncExpr = argument->AsArrowFunctionExpression();
            ir::ScriptFunction *const lambda = arrowFuncExpr->Function();
            if (CheckLambdaAssignable(substitutedSig->Function()->Params()[index], lambda)) {
                continue;
            }
            return false;
        }

        if (argument->IsArrayExpression()) {
            argument->AsArrayExpression()->GetPrefferedTypeFromFuncParam(
                this, substitutedSig->Function()->Params()[index], flags);
        }

        if (!CheckInvokable(substitutedSig, argument, index, flags)) {
            return false;
        }

        if (argument->IsIdentifier() && ValidateArgumentAsIdentifier(argument->AsIdentifier())) {
            ThrowTypeError("Class name can't be the argument of function or method.", argument->Start());
        }

        // clang-format off
        if (!ValidateSignatureInvocationContext(
            substitutedSig, argument,
            TryGettingFunctionTypeFromInvokeFunction(substitutedSig->Params()[index]->TsType()), index, flags)) {
            // clang-format on
            return false;
        }
    }

    return true;
}

bool ETSChecker::CheckInvokable(Signature *substitutedSig, ir::Expression *argument, std::size_t index,
                                TypeRelationFlag flags)
{
    auto *argumentType = argument->Check(this);
    auto *targetType = substitutedSig->Params()[index]->TsType();

    auto const invocationCtx =
        checker::InvocationContext(Relation(), argument, argumentType, targetType, argument->Start(),
                                   {"Type '", argumentType, "' is not compatible with type '",
                                    TryGettingFunctionTypeFromInvokeFunction(targetType), "' at index ", index + 1},
                                   flags);
    return invocationCtx.IsInvocable() || CheckOptionalLambdaFunction(argument, substitutedSig, index);
}

bool ETSChecker::ValidateSignatureInvocationContext(Signature *substitutedSig, ir::Expression *argument,
                                                    const Type *targetType, std::size_t index, TypeRelationFlag flags)
{
    Type *argumentType = argument->Check(this);
    auto const invocationCtx = checker::InvocationContext(
        Relation(), argument, argumentType, substitutedSig->Params()[index]->TsType(), argument->Start(),
        {"Type '", argumentType, "' is not compatible with type '", targetType, "' at index ", index + 1}, flags);
    if (!invocationCtx.IsInvocable()) {
        return CheckOptionalLambdaFunction(argument, substitutedSig, index);
    }

    return true;
}

bool ETSChecker::ValidateSignatureRestParams(Signature *substitutedSig, const ArenaVector<ir::Expression *> &arguments,
                                             TypeRelationFlag flags, bool throwError)
{
    std::size_t const argumentCount = arguments.size();
    std::size_t const parameterCount = substitutedSig->MinArgCount();
    auto count = std::min(parameterCount, argumentCount);
    auto const restCount = argumentCount - count;

    for (std::size_t index = count; index < argumentCount; ++index) {
        auto &argument = arguments[index];

        if (!argument->IsSpreadElement()) {
            auto *const argumentType = argument->Check(this);
            const Type *targetType = TryGettingFunctionTypeFromInvokeFunction(
                substitutedSig->RestVar()->TsType()->AsETSArrayType()->ElementType());
            const Type *sourceType = TryGettingFunctionTypeFromInvokeFunction(argumentType);
            auto const invocationCtx = checker::InvocationContext(
                Relation(), argument, argumentType,
                substitutedSig->RestVar()->TsType()->AsETSArrayType()->ElementType(), argument->Start(),
                {"Type '", sourceType, "' is not compatible with rest parameter type '", targetType, "' at index ",
                 index + 1},
                flags);
            if (!invocationCtx.IsInvocable()) {
                return false;
            }
            continue;
        }

        if (restCount > 1U) {
            if (throwError) {
                ThrowTypeError("Spread argument for the rest parameter can be only one.", argument->Start());
            }
            return false;
        }

        auto *const restArgument = argument->AsSpreadElement()->Argument();
        auto *const argumentType = restArgument->Check(this);
        const Type *targetType = TryGettingFunctionTypeFromInvokeFunction(substitutedSig->RestVar()->TsType());
        const Type *sourceType = TryGettingFunctionTypeFromInvokeFunction(argumentType);

        auto const invocationCtx = checker::InvocationContext(
            Relation(), restArgument, argumentType, substitutedSig->RestVar()->TsType(), argument->Start(),
            {"Type '", sourceType, "' is not compatible with rest parameter type '", targetType, "' at index ",
             index + 1},
            flags);
        if (!invocationCtx.IsInvocable()) {
            return false;
        }
    }

    return true;
}

Signature *ETSChecker::ValidateSignature(Signature *signature, const ir::TSTypeParameterInstantiation *typeArguments,
                                         const ArenaVector<ir::Expression *> &arguments,
                                         const lexer::SourcePosition &pos, TypeRelationFlag flags,
                                         const std::vector<bool> &argTypeInferenceRequired)
{
    Signature *substitutedSig = MaybeSubstituteTypeParameters(this, signature, typeArguments, arguments, pos, flags);
    if (substitutedSig == nullptr) {
        return nullptr;
    }

    auto const hasRestParameter = substitutedSig->RestVar() != nullptr;
    std::size_t const argumentCount = arguments.size();
    std::size_t const parameterCount = substitutedSig->MinArgCount();
    auto const throwError = (flags & TypeRelationFlag::NO_THROW) == 0;

    if (argumentCount < parameterCount || (argumentCount > parameterCount && !hasRestParameter)) {
        if (throwError) {
            ThrowTypeError({"Expected ", parameterCount, " arguments, got ", argumentCount, "."}, pos);
        }
        return nullptr;
    }

    auto count = std::min(parameterCount, argumentCount);
    // Check all required formal parameter(s) first
    if (!ValidateSignatureRequiredParams(substitutedSig, arguments, flags, argTypeInferenceRequired, throwError)) {
        return nullptr;
    }

    // Check rest parameter(s) if any exists
    if (!hasRestParameter || count >= argumentCount) {
        return substitutedSig;
    }
    if (!ValidateSignatureRestParams(substitutedSig, arguments, flags, throwError)) {
        return nullptr;
    }

    return substitutedSig;
}

Signature *ETSChecker::CollectParameterlessConstructor(ArenaVector<Signature *> &signatures,
                                                       const lexer::SourcePosition &pos, TypeRelationFlag resolveFlags)
{
    Signature *compatibleSignature = nullptr;

    auto collectSignatures = [&](TypeRelationFlag relationFlags) {
        for (auto *sig : signatures) {
            if (auto *concreteSig = ValidateParameterlessConstructor(sig, pos, relationFlags); concreteSig != nullptr) {
                compatibleSignature = concreteSig;
                break;
            }
        }
    };

    // We are able to provide more specific error messages.
    if (signatures.size() == 1) {
        collectSignatures(resolveFlags);
    } else {
        collectSignatures(resolveFlags | TypeRelationFlag::NO_THROW);
    }

    if (compatibleSignature == nullptr) {
        if ((resolveFlags & TypeRelationFlag::NO_THROW) == 0) {
            ThrowTypeError({"No matching parameterless constructor"}, pos);
        } else {
            return nullptr;
        }
    }
    return compatibleSignature;
}

bool IsSignatureAccessible(Signature *sig, ETSObjectType *containingClass, TypeRelation *relation)
{
    // NOTE(vivienvoros): this check can be removed if signature is implicitly declared as public according to the spec.
    if (!sig->HasSignatureFlag(SignatureFlags::PUBLIC | SignatureFlags::PROTECTED | SignatureFlags::PRIVATE |
                               SignatureFlags::INTERNAL)) {
        return true;
    }

    // NOTE(vivienvoros): take care of SignatureFlags::INTERNAL and SignatureFlags::INTERNAL_PROTECTED
    if (sig->HasSignatureFlag(SignatureFlags::INTERNAL) && !sig->HasSignatureFlag(SignatureFlags::PROTECTED)) {
        return true;
    }

    if (sig->HasSignatureFlag(SignatureFlags::PUBLIC) || sig->Owner() == containingClass ||
        (sig->HasSignatureFlag(SignatureFlags::PROTECTED) && relation->IsSupertypeOf(sig->Owner(), containingClass))) {
        return true;
    }

    return false;
}

ArenaVector<Signature *> ETSChecker::CollectSignatures(ArenaVector<Signature *> &signatures,
                                                       const ir::TSTypeParameterInstantiation *typeArguments,
                                                       const ArenaVector<ir::Expression *> &arguments,
                                                       const lexer::SourcePosition &pos, TypeRelationFlag resolveFlags)
{
    ArenaVector<Signature *> compatibleSignatures(Allocator()->Adapter());
    std::vector<bool> argTypeInferenceRequired = FindTypeInferenceArguments(arguments);
    Signature *notVisibleSignature = nullptr;

    auto collectSignatures = [&](TypeRelationFlag relationFlags) {
        for (auto *sig : signatures) {
            if (notVisibleSignature != nullptr &&
                !IsSignatureAccessible(sig, Context().ContainingClass(), Relation())) {
                continue;
            }
            auto *concreteSig =
                ValidateSignature(sig, typeArguments, arguments, pos, relationFlags, argTypeInferenceRequired);
            if (concreteSig == nullptr) {
                continue;
            }
            if (notVisibleSignature == nullptr &&
                !IsSignatureAccessible(sig, Context().ContainingClass(), Relation())) {
                notVisibleSignature = concreteSig;
            } else {
                compatibleSignatures.push_back(concreteSig);
            }
        }
    };

    // If there's only one signature, we don't need special checks for boxing/unboxing/widening.
    // We are also able to provide more specific error messages.
    if (signatures.size() == 1) {
        TypeRelationFlag flags = TypeRelationFlag::WIDENING | resolveFlags;
        collectSignatures(flags);
    } else {
        std::array<TypeRelationFlag, 4U> flagVariants {TypeRelationFlag::NO_THROW | TypeRelationFlag::NO_UNBOXING |
                                                           TypeRelationFlag::NO_BOXING,
                                                       TypeRelationFlag::NO_THROW,
                                                       TypeRelationFlag::NO_THROW | TypeRelationFlag::WIDENING |
                                                           TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_BOXING,
                                                       TypeRelationFlag::NO_THROW | TypeRelationFlag::WIDENING};
        for (auto flags : flagVariants) {
            flags = flags | resolveFlags;
            collectSignatures(flags);
            if (!compatibleSignatures.empty()) {
                break;
            }
        }
    }

    if (compatibleSignatures.empty() && notVisibleSignature != nullptr) {
        ThrowTypeError(
            {"Signature ", notVisibleSignature->Function()->Id()->Name(), notVisibleSignature, " is not visible here."},
            pos);
    }
    return compatibleSignatures;
}

Signature *ETSChecker::GetMostSpecificSignature(ArenaVector<Signature *> &compatibleSignatures,
                                                const ArenaVector<ir::Expression *> &arguments,
                                                const lexer::SourcePosition &pos, TypeRelationFlag resolveFlags)
{
    std::vector<bool> argTypeInferenceRequired = FindTypeInferenceArguments(arguments);
    Signature *mostSpecificSignature = ChooseMostSpecificSignature(compatibleSignatures, argTypeInferenceRequired, pos);

    if (mostSpecificSignature == nullptr) {
        ThrowTypeError({"Reference to ", compatibleSignatures.front()->Function()->Id()->Name(), " is ambiguous"}, pos);
    }

    if (!TypeInference(mostSpecificSignature, arguments, resolveFlags)) {
        return nullptr;
    }

    return mostSpecificSignature;
}

Signature *ETSChecker::ValidateSignatures(ArenaVector<Signature *> &signatures,
                                          const ir::TSTypeParameterInstantiation *typeArguments,
                                          const ArenaVector<ir::Expression *> &arguments,
                                          const lexer::SourcePosition &pos, std::string_view signatureKind,
                                          TypeRelationFlag resolveFlags)
{
    auto compatibleSignatures = CollectSignatures(signatures, typeArguments, arguments, pos, resolveFlags);
    if (!compatibleSignatures.empty()) {
        return GetMostSpecificSignature(compatibleSignatures, arguments, pos, resolveFlags);
    }

    if ((resolveFlags & TypeRelationFlag::NO_THROW) == 0 && !arguments.empty() && !signatures.empty()) {
        std::stringstream ss;

        if (signatures[0]->Function()->IsConstructor()) {
            ss << util::Helpers::GetClassDefiniton(signatures[0]->Function())->PrivateId().Mutf8();
        } else {
            ss << signatures[0]->Function()->Id()->Name().Mutf8();
        }

        ss << "(";

        for (uint32_t index = 0; index < arguments.size(); ++index) {
            if (arguments[index]->IsArrowFunctionExpression()) {
                // NOTE(peterseres): Refactor this case and add test case
                break;
            }

            arguments[index]->Check(this);
            arguments[index]->TsType()->ToString(ss);

            if (index == arguments.size() - 1) {
                ss << ")";
                ThrowTypeError({"No matching ", signatureKind, " signature for ", ss.str().c_str()}, pos);
            }

            ss << ", ";
        }
    }

    if ((resolveFlags & TypeRelationFlag::NO_THROW) == 0) {
        ThrowTypeError({"No matching ", signatureKind, " signature"}, pos);
    }

    return nullptr;
}

Signature *ETSChecker::ChooseMostSpecificSignature(ArenaVector<Signature *> &signatures,
                                                   const std::vector<bool> &argTypeInferenceRequired,
                                                   const lexer::SourcePosition &pos, size_t argumentsSize)
{
    ASSERT(signatures.empty() == false);

    if (signatures.size() == 1) {
        return signatures.front();
    }

    size_t paramCount = signatures.front()->Params().size();
    if (argumentsSize != ULONG_MAX) {
        paramCount = argumentsSize;
    }
    // Multiple signatures with zero parameter because of inheritance.
    // Return the closest one in inheritance chain that is defined at the beginning of the vector.
    if (paramCount == 0) {
        return signatures.front();
    }

    // Collect which signatures are most specific for each parameter.
    ArenaMultiMap<size_t /* parameter index */, Signature *> bestSignaturesForParameter(Allocator()->Adapter());

    const checker::SavedTypeRelationFlagsContext savedTypeRelationFlagCtx(Relation(),
                                                                          TypeRelationFlag::ONLY_CHECK_WIDENING);

    for (size_t i = 0; i < paramCount; ++i) {
        if (argTypeInferenceRequired[i]) {
            for (auto *sig : signatures) {
                bestSignaturesForParameter.insert({i, sig});
            }
            continue;
        }
        // 1st step: check which is the most specific parameter type for i. parameter.
        Type *mostSpecificType = signatures.front()->Params().at(i)->TsType();
        Signature *prevSig = signatures.front();

        auto initMostSpecificType = [&mostSpecificType, &prevSig, i](Signature *sig) {
            if (Type *sigType = sig->Params().at(i)->TsType();
                sigType->IsETSObjectType() && !sigType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
                mostSpecificType = sigType;
                prevSig = sig;
                return true;
            }
            return false;
        };

        auto evaluateResult = [this, &mostSpecificType, &prevSig, pos](Signature *sig, Type *sigType) {
            if (Relation()->IsAssignableTo(sigType, mostSpecificType)) {
                mostSpecificType = sigType;
                prevSig = sig;
            } else if (sigType->IsETSObjectType() && mostSpecificType->IsETSObjectType() &&
                       !Relation()->IsAssignableTo(mostSpecificType, sigType)) {
                auto funcName = sig->Function()->Id()->Name();
                ThrowTypeError({"Call to `", funcName, "` is ambiguous as `2` versions of `", funcName,
                                "` are available: `", funcName, prevSig, "` and `", funcName, sig, "`"},
                               pos);
            }
        };

        auto searchAmongTypes = [this, &mostSpecificType, argumentsSize, paramCount, i,
                                 &evaluateResult](Signature *sig, const bool lookForClassType) {
            if (lookForClassType && argumentsSize == ULONG_MAX) {
                [[maybe_unused]] const bool equalParamSize = sig->Params().size() == paramCount;
                ASSERT(equalParamSize);
            }
            Type *sigType = sig->Params().at(i)->TsType();
            const bool isClassType =
                sigType->IsETSObjectType() && !sigType->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE);
            if (isClassType == lookForClassType) {
                if (Relation()->IsIdenticalTo(sigType, mostSpecificType)) {
                    return;
                }
                evaluateResult(sig, sigType);
            }
        };

        std::any_of(signatures.begin(), signatures.end(), initMostSpecificType);
        std::for_each(signatures.begin(), signatures.end(),
                      [&searchAmongTypes](Signature *sig) mutable { searchAmongTypes(sig, true); });
        std::for_each(signatures.begin(), signatures.end(),
                      [&searchAmongTypes](Signature *sig) mutable { searchAmongTypes(sig, false); });

        for (auto *sig : signatures) {
            Type *sigType = sig->Params().at(i)->TsType();
            if (Relation()->IsIdenticalTo(sigType, mostSpecificType)) {
                bestSignaturesForParameter.insert({i, sig});
            }
        }
    }

    // Find the signature that are most specific for all parameters.
    Signature *mostSpecificSignature = nullptr;

    for (auto *sig : signatures) {
        bool mostSpecific = true;

        for (size_t paramIdx = 0; paramIdx < paramCount; ++paramIdx) {
            const auto range = bestSignaturesForParameter.equal_range(paramIdx);
            // Check if signature is most specific for i. parameter type.
            const bool hasSignature =
                std::any_of(range.first, range.second, [&sig](auto entry) { return entry.second == sig; });
            if (!hasSignature) {
                mostSpecific = false;
                break;
            }
        }

        if (!mostSpecific) {
            continue;
        }
        if (mostSpecificSignature == nullptr) {
            mostSpecificSignature = sig;
            continue;
        }
        if (mostSpecificSignature->Owner() == sig->Owner()) {
            // NOTE: audovichenko. Remove this 'if' when #12443 gets resolved
            if (mostSpecificSignature->Function() == sig->Function()) {
                // The same signature
                continue;
            }
            return nullptr;
        }
    }

    return mostSpecificSignature;
}

Signature *ETSChecker::ResolveCallExpression(ArenaVector<Signature *> &signatures,
                                             const ir::TSTypeParameterInstantiation *typeArguments,
                                             const ArenaVector<ir::Expression *> &arguments,
                                             const lexer::SourcePosition &pos)
{
    auto sig = ValidateSignatures(signatures, typeArguments, arguments, pos, "call");
    ASSERT(sig);
    return sig;
}

Signature *ETSChecker::ResolveCallExpressionAndTrailingLambda(ArenaVector<Signature *> &signatures,
                                                              ir::CallExpression *callExpr,
                                                              const lexer::SourcePosition &pos,
                                                              const TypeRelationFlag throwFlag)
{
    Signature *sig = nullptr;

    if (callExpr->TrailingBlock() == nullptr) {
        sig = ValidateSignatures(signatures, callExpr->TypeParams(), callExpr->Arguments(), pos, "call", throwFlag);
        return sig;
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto arguments = ExtendArgumentsWithFakeLamda(callExpr);
    sig = ValidateSignatures(signatures, callExpr->TypeParams(), arguments, pos, "call",
                             TypeRelationFlag::NO_THROW | TypeRelationFlag::NO_CHECK_TRAILING_LAMBDA);
    if (sig != nullptr) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        TransformTraillingLambda(callExpr);
        TypeInference(sig, callExpr->Arguments());
        return sig;
    }

    sig = ValidateSignatures(signatures, callExpr->TypeParams(), callExpr->Arguments(), pos, "call", throwFlag);
    if (sig != nullptr) {
        EnsureValidCurlyBrace(callExpr);
    }

    return sig;
}

Signature *ETSChecker::ResolveConstructExpression(ETSObjectType *type, const ArenaVector<ir::Expression *> &arguments,
                                                  const lexer::SourcePosition &pos)
{
    return ValidateSignatures(type->ConstructSignatures(), nullptr, arguments, pos, "construct");
}

/*
 * Object literals do not get checked in the process of call resolution; we need to check them separately
 * afterwards.
 */
void ETSChecker::CheckObjectLiteralArguments(Signature *signature, ArenaVector<ir::Expression *> const &arguments)
{
    for (uint32_t index = 0; index < arguments.size(); index++) {
        if (!arguments[index]->IsObjectExpression()) {
            continue;
        }

        Type *tp;
        if (index >= signature->MinArgCount()) {
            ASSERT(signature->RestVar());
            tp = signature->RestVar()->TsType();
        } else {
            tp = signature->Params()[index]->TsType();
        }

        arguments[index]->AsObjectExpression()->SetPreferredType(tp);
        arguments[index]->Check(this);
    }
}

checker::ETSFunctionType *ETSChecker::BuildMethodSignature(ir::MethodDefinition *method)
{
    if (method->TsType() != nullptr) {
        return method->TsType()->AsETSFunctionType();
    }

    bool isConstructSig = method->IsConstructor();

    auto *funcType = BuildFunctionSignature(method->Function(), isConstructSig);

    std::vector<checker::ETSFunctionType *> overloads;
    for (ir::MethodDefinition *const currentFunc : method->Overloads()) {
        auto *const overloadType = BuildFunctionSignature(currentFunc->Function(), isConstructSig);
        CheckIdenticalOverloads(funcType, overloadType, currentFunc);
        currentFunc->SetTsType(overloadType);
        funcType->AddCallSignature(currentFunc->Function()->Signature());
        overloads.push_back(overloadType);
    }
    for (size_t baseFuncCounter = 0; baseFuncCounter < overloads.size(); ++baseFuncCounter) {
        auto *overloadType = overloads.at(baseFuncCounter);
        for (size_t compareFuncCounter = baseFuncCounter + 1; compareFuncCounter < overloads.size();
             compareFuncCounter++) {
            auto *compareOverloadType = overloads.at(compareFuncCounter);
            CheckIdenticalOverloads(overloadType, compareOverloadType, method->Overloads()[compareFuncCounter]);
        }
    }

    method->Id()->Variable()->SetTsType(funcType);
    return funcType;
}

void ETSChecker::CheckIdenticalOverloads(ETSFunctionType *func, ETSFunctionType *overload,
                                         const ir::MethodDefinition *const currentFunc)
{
    SavedTypeRelationFlagsContext savedFlagsCtx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);

    Relation()->IsIdenticalTo(func, overload);
    if (Relation()->IsTrue()) {
        ThrowTypeError("Function already declared.", currentFunc->Start());
    }
    if (HasSameAssemblySignature(func, overload)) {
        ThrowTypeError("Function with this assembly signature already declared.", currentFunc->Start());
    }
}

Signature *ETSChecker::ComposeSignature(ir::ScriptFunction *func, SignatureInfo *signatureInfo, Type *returnType,
                                        varbinder::Variable *nameVar)
{
    auto *signature = CreateSignature(signatureInfo, returnType, func);
    signature->SetOwner(Context().ContainingClass());
    signature->SetOwnerVar(nameVar);

    const auto *returnTypeAnnotation = func->ReturnTypeAnnotation();
    if (returnTypeAnnotation == nullptr && ((func->Flags() & ir::ScriptFunctionFlags::HAS_RETURN) != 0)) {
        signature->AddSignatureFlag(SignatureFlags::NEED_RETURN_TYPE);
    }

    if (returnTypeAnnotation != nullptr && returnTypeAnnotation->IsTSThisType()) {
        signature->AddSignatureFlag(SignatureFlags::THIS_RETURN_TYPE);
    }

    if (func->IsAbstract()) {
        signature->AddSignatureFlag(SignatureFlags::ABSTRACT);
        signature->AddSignatureFlag(SignatureFlags::VIRTUAL);
    }

    if (func->IsStatic()) {
        signature->AddSignatureFlag(SignatureFlags::STATIC);
    }

    if (func->IsConstructor()) {
        signature->AddSignatureFlag(SignatureFlags::CONSTRUCTOR);
    }

    if (signature->Owner()->GetDeclNode()->IsFinal() || func->IsFinal()) {
        signature->AddSignatureFlag(SignatureFlags::FINAL);
    }

    if (func->IsPublic()) {
        signature->AddSignatureFlag(SignatureFlags::PUBLIC);
    } else if (func->IsInternal()) {
        if (func->IsProtected()) {
            signature->AddSignatureFlag(SignatureFlags::INTERNAL_PROTECTED);
        } else {
            signature->AddSignatureFlag(SignatureFlags::INTERNAL);
        }
    } else if (func->IsProtected()) {
        signature->AddSignatureFlag(SignatureFlags::PROTECTED);
    } else if (func->IsPrivate()) {
        signature->AddSignatureFlag(SignatureFlags::PRIVATE);
    }

    return signature;
}

Type *ETSChecker::ComposeReturnType(ir::ScriptFunction *func)
{
    auto *const returnTypeAnnotation = func->ReturnTypeAnnotation();
    checker::Type *returnType {};

    if (returnTypeAnnotation == nullptr) {
        // implicit void return type
        returnType = GlobalVoidType();

        if (func->IsAsyncFunc()) {
            auto implicitPromiseVoid = [this]() {
                const auto &promiseGlobal = GlobalBuiltinPromiseType()->AsETSObjectType();
                auto promiseType =
                    promiseGlobal->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsETSObjectType();
                promiseType->AddTypeFlag(checker::TypeFlag::GENERIC);
                promiseType->TypeArguments().clear();
                promiseType->TypeArguments().emplace_back(GlobalVoidType());
                return promiseType;
            };

            returnType = implicitPromiseVoid();
        }
    } else if (func->IsEntryPoint() && returnTypeAnnotation->GetType(this) == GlobalVoidType()) {
        returnType = GlobalVoidType();
    } else {
        returnType = returnTypeAnnotation->GetType(this);
        returnTypeAnnotation->SetTsType(returnType);
    }

    return returnType;
}

SignatureInfo *ETSChecker::ComposeSignatureInfo(ir::ScriptFunction *func)
{
    auto *signatureInfo = CreateSignatureInfo();
    signatureInfo->restVar = nullptr;
    signatureInfo->minArgCount = 0;

    if ((func->IsConstructor() || !func->IsStatic()) && !func->IsArrow()) {
        auto *thisVar = func->Scope()->ParamScope()->Params().front();
        thisVar->SetTsType(Context().ContainingClass());
    }

    if (func->TypeParams() != nullptr) {
        signatureInfo->typeParams = CreateTypeForTypeParameters(func->TypeParams());
    }

    for (auto *const it : func->Params()) {
        auto *const param = it->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            auto const *const restIdent = param->Ident();

            ASSERT(restIdent->Variable());
            signatureInfo->restVar = restIdent->Variable()->AsLocalVariable();

            auto *const restParamTypeAnnotation = param->TypeAnnotation();
            ASSERT(restParamTypeAnnotation);

            signatureInfo->restVar->SetTsType(restParamTypeAnnotation->GetType(this));
            auto arrayType = signatureInfo->restVar->TsType()->AsETSArrayType();
            CreateBuiltinArraySignature(arrayType, arrayType->Rank());
        } else {
            auto *const paramIdent = param->Ident();

            varbinder::Variable *const paramVar = paramIdent->Variable();
            ASSERT(paramVar);

            auto *const paramTypeAnnotation = param->TypeAnnotation();
            if (paramIdent->TsType() == nullptr) {
                ASSERT(paramTypeAnnotation);

                paramVar->SetTsType(paramTypeAnnotation->GetType(this));
            } else {
                paramVar->SetTsType(paramIdent->TsType());
            }
            signatureInfo->params.push_back(paramVar->AsLocalVariable());
            ++signatureInfo->minArgCount;
        }
    }

    return signatureInfo;
}

void ETSChecker::ValidateMainSignature(ir::ScriptFunction *func)
{
    if (func->Params().size() >= 2U) {
        ThrowTypeError("0 or 1 argument are allowed", func->Start());
    }

    if (func->Params().size() == 1) {
        auto const *const param = func->Params()[0]->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            ThrowTypeError("Rest parameter is not allowed in the 'main' function.", param->Start());
        }

        const auto paramType = param->Variable()->TsType();
        if (!paramType->IsETSArrayType() || !paramType->AsETSArrayType()->ElementType()->IsETSStringType()) {
            ThrowTypeError("Only 'string[]' type argument is allowed.", param->Start());
        }
    }
}

checker::ETSFunctionType *ETSChecker::BuildFunctionSignature(ir::ScriptFunction *func, bool isConstructSig)
{
    bool isArrow = func->IsArrow();
    auto *nameVar = isArrow ? nullptr : func->Id()->Variable();
    auto funcName = nameVar == nullptr ? util::StringView() : nameVar->Name();

    auto *signatureInfo = ComposeSignatureInfo(func);

    if (funcName.Is(compiler::Signatures::MAIN) &&
        func->Scope()->Name().Utf8().find(compiler::Signatures::ETS_GLOBAL) != std::string::npos) {
        func->AddFlag(ir::ScriptFunctionFlags::ENTRY_POINT);
    }
    if (func->IsEntryPoint()) {
        ValidateMainSignature(func);
    }

    auto *returnType = ComposeReturnType(func);
    auto *signature = ComposeSignature(func, signatureInfo, returnType, nameVar);
    if (isConstructSig) {
        signature->AddSignatureFlag(SignatureFlags::CONSTRUCT);
    } else {
        signature->AddSignatureFlag(SignatureFlags::CALL);
    }

    auto *funcType = CreateETSFunctionType(func, signature, funcName);
    func->SetSignature(signature);
    funcType->SetVariable(nameVar);
    VarBinder()->AsETSBinder()->BuildFunctionName(func);

    if (func->IsAbstract()) {
        signature->AddSignatureFlag(SignatureFlags::ABSTRACT);
        signature->AddSignatureFlag(SignatureFlags::VIRTUAL);
    }

    if (func->IsStatic()) {
        signature->AddSignatureFlag(SignatureFlags::STATIC);
    }

    if (func->IsConstructor()) {
        signature->AddSignatureFlag(SignatureFlags::CONSTRUCTOR);
    }

    if (func->Signature()->Owner()->GetDeclNode()->IsFinal() || func->IsFinal()) {
        signature->AddSignatureFlag(SignatureFlags::FINAL);
    }

    if (func->IsPublic()) {
        signature->AddSignatureFlag(SignatureFlags::PUBLIC);
    } else if (func->IsInternal()) {
        if (func->IsProtected()) {
            signature->AddSignatureFlag(SignatureFlags::INTERNAL_PROTECTED);
        } else {
            signature->AddSignatureFlag(SignatureFlags::INTERNAL);
        }
    } else if (func->IsProtected()) {
        signature->AddSignatureFlag(SignatureFlags::PROTECTED);
    } else if (func->IsPrivate()) {
        signature->AddSignatureFlag(SignatureFlags::PRIVATE);
    }

    if (func->IsSetter()) {
        signature->AddSignatureFlag(SignatureFlags::SETTER);
    } else if (func->IsGetter()) {
        signature->AddSignatureFlag(SignatureFlags::GETTER);
    }

    if (!isArrow) {
        nameVar->SetTsType(funcType);
    }

    return funcType;
}

Signature *ETSChecker::CheckEveryAbstractSignatureIsOverridden(ETSFunctionType *target, ETSFunctionType *source)
{
    for (auto targetSig = target->CallSignatures().begin(); targetSig != target->CallSignatures().end();) {
        if (!(*targetSig)->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            continue;
        }

        bool isOverridden = false;
        for (auto sourceSig : source->CallSignatures()) {
            Relation()->IsCompatibleTo(*targetSig, sourceSig);
            if (Relation()->IsTrue() && (*targetSig)->Function()->Id()->Name() == sourceSig->Function()->Id()->Name()) {
                target->CallSignatures().erase(targetSig);
                isOverridden = true;
                break;
            }
            sourceSig++;
        }

        if (!isOverridden) {
            return *targetSig;
        }
    }

    return nullptr;
}

bool ETSChecker::IsOverridableIn(Signature *signature)
{
    if (signature->HasSignatureFlag(SignatureFlags::PRIVATE)) {
        return false;
    }

    // NOTE: #15095 workaround, separate internal visibility check
    if (signature->HasSignatureFlag(SignatureFlags::PUBLIC | SignatureFlags::INTERNAL)) {
        return true;
    }

    return signature->HasSignatureFlag(SignatureFlags::PROTECTED);
}

bool ETSChecker::IsMethodOverridesOther(Signature *base, Signature *derived)
{
    if (derived->Function()->IsConstructor()) {
        return false;
    }

    if (base == derived) {
        return true;
    }

    if (derived->HasSignatureFlag(SignatureFlags::STATIC) != base->HasSignatureFlag(SignatureFlags::STATIC)) {
        return false;
    }

    if (IsOverridableIn(base)) {
        SavedTypeRelationFlagsContext savedFlagsCtx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK |
                                                                    TypeRelationFlag::OVERRIDING_CONTEXT);
        Relation()->IsCompatibleTo(base, derived);
        if (Relation()->IsTrue()) {
            CheckThrowMarkers(derived, base);

            if (derived->HasSignatureFlag(SignatureFlags::STATIC)) {
                return false;
            }

            derived->Function()->SetOverride();
            return true;
        }
    }

    return false;
}

void ETSChecker::CheckThrowMarkers(Signature *source, Signature *target)
{
    ir::ScriptFunctionFlags throwMarkers = ir::ScriptFunctionFlags::THROWS | ir::ScriptFunctionFlags::RETHROWS;
    auto sourceThrowMarkers = source->Function()->Flags() & throwMarkers;
    auto targetThrowMarkers = target->Function()->Flags() & throwMarkers;
    if (sourceThrowMarkers != targetThrowMarkers) {
        ThrowTypeError(
            "A method that overrides or hides another method cannot change throw or rethrow clauses of the "
            "overridden "
            "or hidden method.",
            target->Function()->Body()->Start());
    }
}

OverrideErrorCode ETSChecker::CheckOverride(Signature *signature, Signature *other)
{
    if (other->HasSignatureFlag(SignatureFlags::STATIC)) {
        ASSERT(signature->HasSignatureFlag(SignatureFlags::STATIC));
        return OverrideErrorCode::NO_ERROR;
    }

    if (other->IsFinal()) {
        return OverrideErrorCode::OVERRIDDEN_FINAL;
    }

    if (!IsReturnTypeSubstitutable(signature, other)) {
        return OverrideErrorCode::INCOMPATIBLE_RETURN;
    }

    if (signature->ProtectionFlag() > other->ProtectionFlag()) {
        return OverrideErrorCode::OVERRIDDEN_WEAKER;
    }

    return OverrideErrorCode::NO_ERROR;
}

Signature *ETSChecker::AdjustForTypeParameters(Signature *source, Signature *target)
{
    auto &sourceTypeParams = source->GetSignatureInfo()->typeParams;
    auto &targetTypeParams = target->GetSignatureInfo()->typeParams;
    if (sourceTypeParams.size() != targetTypeParams.size()) {
        return nullptr;
    }
    if (sourceTypeParams.empty()) {
        return target;
    }
    auto *substitution = NewSubstitution();
    for (size_t ix = 0; ix < sourceTypeParams.size(); ix++) {
        if (!targetTypeParams[ix]->IsETSTypeParameter()) {
            continue;
        }
        ETSChecker::EmplaceSubstituted(substitution, targetTypeParams[ix]->AsETSTypeParameter(), sourceTypeParams[ix]);
    }
    return target->Substitute(Relation(), substitution);
}

void ETSChecker::ThrowOverrideError(Signature *signature, Signature *overriddenSignature,
                                    const OverrideErrorCode &errorCode)
{
    const char *reason {};
    switch (errorCode) {
        case OverrideErrorCode::OVERRIDDEN_FINAL: {
            reason = "overridden method is final.";
            break;
        }
        case OverrideErrorCode::INCOMPATIBLE_RETURN: {
            reason = "overriding return type is not compatible with the other return type.";
            break;
        }
        case OverrideErrorCode::OVERRIDDEN_WEAKER: {
            reason = "overridden method has weaker access privilege.";
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    ThrowTypeError({signature->Function()->Id()->Name(), signature, " in ", signature->Owner(), " cannot override ",
                    overriddenSignature->Function()->Id()->Name(), overriddenSignature, " in ",
                    overriddenSignature->Owner(), " because ", reason},
                   signature->Function()->Start());
}

bool ETSChecker::CheckOverride(Signature *signature, ETSObjectType *site)
{
    auto *target = site->GetProperty(signature->Function()->Id()->Name(), PropertySearchFlags::SEARCH_METHOD);
    bool isOverridingAnySignature = false;

    if (target == nullptr) {
        return isOverridingAnySignature;
    }

    bool suitableSignatureFound = false;
    for (auto *it : target->TsType()->AsETSFunctionType()->CallSignatures()) {
        auto *itSubst = AdjustForTypeParameters(signature, it);

        if (itSubst == nullptr) {
            continue;
        }

        if (itSubst->HasSignatureFlag(SignatureFlags::ABSTRACT) || site->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
            if (site->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
                CheckThrowMarkers(itSubst, signature);
            }
            if ((itSubst->Function()->IsSetter() && !signature->Function()->IsSetter()) ||
                (itSubst->Function()->IsGetter() && !signature->Function()->IsGetter())) {
                continue;
            }
        }
        if (!IsMethodOverridesOther(itSubst, signature)) {
            continue;
        }

        auto errorCode = CheckOverride(signature, itSubst);
        if (errorCode == OverrideErrorCode::NO_ERROR) {
            suitableSignatureFound = true;
        } else if (!suitableSignatureFound) {
            ThrowOverrideError(signature, it, errorCode);
        }

        if (signature->Owner()->HasObjectFlag(ETSObjectFlags::INTERFACE) &&
            Relation()->IsIdenticalTo(itSubst->Owner(), GlobalETSObjectType()) &&
            !itSubst->HasSignatureFlag(SignatureFlags::PRIVATE)) {
            ThrowTypeError("Cannot override non-private method of the class Object from an interface.",
                           signature->Function()->Start());
        }

        isOverridingAnySignature = true;
        it->AddSignatureFlag(SignatureFlags::VIRTUAL);
    }

    return isOverridingAnySignature;
}

void ETSChecker::CheckOverride(Signature *signature)
{
    auto *owner = signature->Owner();
    bool isOverriding = false;

    if (!owner->HasObjectFlag(ETSObjectFlags::CLASS | ETSObjectFlags::INTERFACE)) {
        return;
    }

    for (auto *const interface : owner->Interfaces()) {
        isOverriding |= CheckInterfaceOverride(this, interface, signature);
    }

    ETSObjectType *iter = owner->SuperType();
    while (iter != nullptr) {
        isOverriding |= CheckOverride(signature, iter);

        for (auto *const interface : iter->Interfaces()) {
            isOverriding |= CheckInterfaceOverride(this, interface, signature);
        }

        iter = iter->SuperType();
    }

    if (!isOverriding && signature->Function()->IsOverride()) {
        ThrowTypeError({"Method ", signature->Function()->Id()->Name(), signature, " in ", signature->Owner(),
                        " not overriding any method"},
                       signature->Function()->Start());
    }
}

Signature *ETSChecker::GetSignatureFromMethodDefinition(const ir::MethodDefinition *methodDef)
{
    ASSERT(methodDef->TsType() && methodDef->TsType()->IsETSFunctionType());

    for (auto *it : methodDef->TsType()->AsETSFunctionType()->CallSignatures()) {
        if (it->Function() == methodDef->Function()) {
            return it;
        }
    }

    return nullptr;
}

void ETSChecker::ValidateSignatureAccessibility(ETSObjectType *callee, const ir::CallExpression *callExpr,
                                                Signature *signature, const lexer::SourcePosition &pos,
                                                char const *errorMessage)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U ||
        (!signature->HasSignatureFlag(SignatureFlags::PRIVATE) &&
         !signature->HasSignatureFlag(SignatureFlags::PROTECTED))) {
        return;
    }
    const auto *declNode = callee->GetDeclNode();
    auto *containingClass = Context().ContainingClass();
    bool isContainingSignatureInherited = containingClass->IsSignatureInherited(signature);
    ASSERT(declNode && (declNode->IsClassDefinition() || declNode->IsTSInterfaceDeclaration()));

    if (declNode->IsTSInterfaceDeclaration()) {
        const auto *enclosingFunc =
            util::Helpers::FindAncestorGivenByType(callExpr, ir::AstNodeType::SCRIPT_FUNCTION)->AsScriptFunction();
        if (callExpr->Callee()->IsMemberExpression() &&
            callExpr->Callee()->AsMemberExpression()->Object()->IsThisExpression() &&
            signature->Function()->IsPrivate() && !enclosingFunc->IsPrivate()) {
            ThrowTypeError({"Cannot reference 'this' in this context."}, enclosingFunc->Start());
        }

        if (containingClass == declNode->AsTSInterfaceDeclaration()->TsType() && isContainingSignatureInherited) {
            return;
        }
    }
    if (containingClass == declNode->AsClassDefinition()->TsType() && isContainingSignatureInherited) {
        return;
    }

    bool isSignatureInherited = callee->IsSignatureInherited(signature);
    const auto *currentOutermost = containingClass->OutermostClass();
    if (!signature->HasSignatureFlag(SignatureFlags::PRIVATE) &&
        ((signature->HasSignatureFlag(SignatureFlags::PROTECTED) && containingClass->IsDescendantOf(callee)) ||
         (currentOutermost != nullptr && currentOutermost == callee->OutermostClass())) &&
        isSignatureInherited) {
        return;
    }

    if (errorMessage == nullptr) {
        ThrowTypeError({"Signature ", signature->Function()->Id()->Name(), signature, " is not visible here."}, pos);
    }
    ThrowTypeError(errorMessage, pos);
}

void ETSChecker::CheckCapturedVariable(ir::AstNode *const node, varbinder::Variable *const var)
{
    if (node->IsIdentifier()) {
        const auto *const parent = node->Parent();

        if (parent->IsUpdateExpression() ||
            (parent->IsAssignmentExpression() && parent->AsAssignmentExpression()->Left() == node)) {
            const auto *const identNode = node->AsIdentifier();

            const auto *resolved = identNode->Variable();

            if (resolved == nullptr) {
                resolved = FindVariableInFunctionScope(identNode->Name());
            }

            if (resolved == nullptr) {
                resolved = FindVariableInGlobal(identNode);
            }

            if (resolved == var) {
                var->AddFlag(varbinder::VariableFlags::BOXED);
                // For mutable captured variable [possible] smart-cast is senseless (or even erroneous)
                Context().RemoveSmartCast(var);
            }
        }
    }

    CheckCapturedVariableInSubnodes(node, var);
}

void ETSChecker::CheckCapturedVariableInSubnodes(ir::AstNode *node, varbinder::Variable *var)
{
    if (!node->IsClassDefinition()) {
        node->Iterate([this, var](ir::AstNode *childNode) { CheckCapturedVariable(childNode, var); });
    }
}

void ETSChecker::CheckCapturedVariables()
{
    // If we want to capture non constant local variables, we should wrap them in a generic reference class
    for (auto [var, _] : Context().CapturedVars()) {
        (void)_;
        if ((var->Declaration() == nullptr) || var->Declaration()->IsConstDecl() ||
            !var->HasFlag(varbinder::VariableFlags::LOCAL) || var->GetScope()->Node()->IsArrowFunctionExpression()) {
            continue;
        }

        auto *searchNode = var->Declaration()->Node()->Parent();

        if (searchNode->IsVariableDeclarator()) {
            searchNode = searchNode->Parent()->Parent();
        }

        CheckCapturedVariableInSubnodes(searchNode, var);
    }
}

// Lambda creation for Lambda expressions

// Chunk pulled out of CreateLambdaObjectForLambdaReference to appease Chinese code checker
static std::pair<ArenaVector<ir::AstNode *>, bool> CreateLambdaObjectPropertiesForLambdaReference(
    ETSChecker *checker, ir::ArrowFunctionExpression *lambda, varbinder::ClassScope *classScope)
{
    bool saveThis = false;
    size_t idx = 0;
    const auto &capturedVars = lambda->CapturedVars();

    // Create the synthetic class property nodes for the captured variables
    ArenaVector<ir::AstNode *> properties(checker->Allocator()->Adapter());
    for (const auto *it : capturedVars) {
        if (it->HasFlag(varbinder::VariableFlags::LOCAL)) {
            properties.push_back(checker->CreateLambdaCapturedField(it, classScope, idx, lambda->Start()));
            idx++;
        } else if (!it->HasFlag(varbinder::VariableFlags::STATIC) &&
                   !checker->Context().ContainingClass()->HasObjectFlag(ETSObjectFlags::GLOBAL) &&
                   !(checker->Context().ContainingSignature() != nullptr &&
                     checker->Context().ContainingSignature()->HasSignatureFlag(SignatureFlags::STATIC))) {
            saveThis = true;
        }
    }

    // If the lambda captured a property in the current class, we have to make a synthetic class property to store
    // 'this' in it
    if (saveThis) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        properties.push_back(checker->CreateLambdaCapturedThis(classScope, idx, lambda->Start()));
        idx++;
    }

    return {properties, saveThis};
}

static void HandleAsyncFuncInLambda(ETSChecker *checker, ir::ArrowFunctionExpression *lambda,
                                    ir::MethodDefinition *proxyMethod, ir::ClassDefinition *currentClassDef)
{
    ir::MethodDefinition *asyncImpl = checker->CreateAsyncProxy(proxyMethod, currentClassDef);
    ir::ScriptFunction *asyncImplFunc = asyncImpl->Function();
    currentClassDef->Body().push_back(asyncImpl);
    asyncImpl->SetParent(currentClassDef);
    checker->ReplaceIdentifierReferencesInProxyMethod(asyncImplFunc->Body(), asyncImplFunc->Params(), lambda);
    Signature *implSig = checker->CreateSignature(proxyMethod->Function()->Signature()->GetSignatureInfo(),
                                                  checker->GlobalETSObjectType(), asyncImplFunc);
    asyncImplFunc->SetSignature(implSig);
    checker->VarBinder()->AsETSBinder()->BuildFunctionName(asyncImpl->Function());
}

void ETSChecker::CreateLambdaObjectForLambdaReference(ir::ArrowFunctionExpression *lambda,
                                                      ETSObjectType *functionalInterface)
{
    if (VarBinder()->AsETSBinder()->LambdaObjects().count(lambda) != 0) {
        return;
    }

    // Create the class scope for the synthetic lambda class node
    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *classScope = classCtx.GetScope();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto [properties, saveThis] = CreateLambdaObjectPropertiesForLambdaReference(this, lambda, classScope);
    auto *currentClassDef = Context().ContainingClass()->GetDeclNode()->AsClassDefinition();

    // Create the synthetic proxy method node for the current class definiton, which we will use in the lambda
    // 'invoke' method to propagate the function call to the current class
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *proxyMethod = CreateProxyMethodForLambda(currentClassDef, lambda, properties, !saveThis);

    // Create the synthetic constructor node for the lambda class, to be able to save captured variables
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *ctor = CreateLambdaImplicitCtor(properties);
    properties.push_back(ctor);

    // Create the synthetic invoke node for the lambda class, which will propagate the call to the proxy method
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *invoke0Func = CreateLambdaInvokeProto(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *invokeFunc = CreateLambdaInvokeProto("invoke");

    properties.push_back(invoke0Func);
    properties.push_back(invokeFunc);

    // Create the declarations for the synthetic constructor and invoke method
    CreateLambdaFuncDecl(ctor, classScope->StaticMethodScope());
    CreateLambdaFuncDecl(invoke0Func, classScope->InstanceMethodScope());
    CreateLambdaFuncDecl(invokeFunc, classScope->InstanceMethodScope());

    // Create the synthetic lambda class node
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *identNode = AllocNode<ir::Identifier>(util::StringView("LambdaObject"), Allocator());
    auto *lambdaObject =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::ClassDefinition>(Allocator(), identNode, std::move(properties),
                                       ir::ClassDefinitionModifiers::DECLARATION, Language(Language::Id::ETS));
    lambda->SetResolvedLambda(lambdaObject);
    lambda->SetTsType(functionalInterface);
    lambdaObject->SetScope(classScope);
    lambdaObject->SetParent(currentClassDef);

    for (auto prop : lambdaObject->Body()) {
        prop->SetParent(lambdaObject);
    }

    // if we should save 'this', then propagate this information to the lambda node, so when we are compiling it,
    // and calling the lambda object ctor, we can pass the 'this' as argument
    if (saveThis) {
        lambda->SetPropagateThis();
    }

    // Set the parent nodes
    ctor->SetParent(lambdaObject);
    invoke0Func->SetParent(lambdaObject);
    invokeFunc->SetParent(lambdaObject);
    classScope->BindNode(lambdaObject);

    // Build the lambda object in the binder
    VarBinder()->AsETSBinder()->BuildLambdaObject(lambda, lambdaObject, proxyMethod->Function()->Signature(),
                                                  lambda->Function()->IsExternal());

    // Resolve the proxy method
    ResolveProxyMethod(currentClassDef, proxyMethod, lambda);
    if (lambda->Function()->IsAsyncFunc()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        HandleAsyncFuncInLambda(this, lambda, proxyMethod, currentClassDef);
    }

    // Resolve the lambda object
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObject(lambdaObject, functionalInterface, lambda, proxyMethod, saveThis);
}

void ETSChecker::ResolveLambdaObject(ir::ClassDefinition *lambdaObject, ETSObjectType *functionalInterface,
                                     ir::ArrowFunctionExpression *lambda, ir::MethodDefinition *proxyMethod,
                                     bool saveThis)
{
    // Create the class type for the lambda
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *lambdaObjectType = Allocator()->New<checker::ETSObjectType>(Allocator(), lambdaObject->Ident()->Name(),
                                                                      lambdaObject->Ident()->Name(), lambdaObject,
                                                                      checker::ETSObjectFlags::CLASS, Relation());

    // Add the target function type to the implementing interfaces, this way, we can call the functional interface
    // virtual 'invoke' method and it will propagate the call to the currently stored lambda class 'invoke' function
    // which was assigned to the variable
    lambdaObjectType->AddInterface(functionalInterface);
    lambdaObject->SetTsType(lambdaObjectType);

    // Add the captured fields to the lambda class type
    for (auto *it : lambdaObject->Body()) {
        if (!it->IsClassProperty()) {
            continue;
        }

        auto *prop = it->AsClassProperty();
        lambdaObjectType->AddProperty<checker::PropertyType::INSTANCE_FIELD>(
            prop->Key()->AsIdentifier()->Variable()->AsLocalVariable());
    }
    VarBinder()->AsETSBinder()->BuildLambdaObjectName(lambda);

    // Resolve the constructor
    ResolveLambdaObjectCtor(lambdaObject);

    // Resolve the invoke function
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObjectInvoke(lambdaObject, lambda, proxyMethod, !saveThis, true);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObjectInvoke(lambdaObject, lambda, proxyMethod, !saveThis, false);
}

static void CreateParametersForInvokeSignature(ETSChecker *checker, ir::ArrowFunctionExpression *lambda,
                                               ir::ScriptFunction *invokeFunc, SignatureInfo *invokeSignatureInfo,
                                               bool ifaceOverride)
{
    auto *allocator = checker->Allocator();
    for (auto *it : lambda->Function()->Params()) {
        auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            checker->VarBinder(), invokeFunc->Scope()->ParamScope(), false);
        auto *const param = it->Clone(allocator, it->Parent())->AsETSParameterExpression();
        auto [_, var] = checker->VarBinder()->AddParamDecl(param);
        (void)_;
        if (!ifaceOverride) {
            var->SetTsType(param->Variable()->TsType());
        } else if (param->IsRestParameter()) {
            var->SetTsType(checker->CreateETSArrayType(checker->GlobalETSNullishObjectType()));
        } else {
            var->SetTsType(checker->GlobalETSNullishObjectType());
        }
        param->Ident()->SetVariable(var);
        param->Ident()->SetTsType(var->TsType());
        param->SetTsType(var->TsType());
        invokeFunc->Params().push_back(param);
        if (param->IsRestParameter()) {
            invokeSignatureInfo->restVar = var->AsLocalVariable();
        } else {
            invokeSignatureInfo->minArgCount++;
            invokeSignatureInfo->params.push_back(var->AsLocalVariable());
        }
    }
}

static Signature *CreateInvokeSignature(ETSChecker *checker, ir::ArrowFunctionExpression *lambda,
                                        ir::ScriptFunction *invokeFunc, ETSObjectType *lambdaObjectType,
                                        bool ifaceOverride)
{
    auto *allocator = checker->Allocator();

    // Create the signature for the invoke function type
    auto *invokeSignatureInfo = checker->CreateSignatureInfo();
    invokeSignatureInfo->restVar = nullptr;

    // Create the parameters for the invoke function, based on the lambda function's parameters
    auto maxParamsNum = checker->GlobalBuiltinFunctionTypeVariadicThreshold();
    auto paramsNum = lambda->Function()->Params().size();
    if (paramsNum < maxParamsNum || !ifaceOverride) {
        CreateParametersForInvokeSignature(checker, lambda, invokeFunc, invokeSignatureInfo, ifaceOverride);
    } else {
        auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            checker->VarBinder(), invokeFunc->Scope()->ParamScope(), false);

        auto *id = checker->AllocNode<ir::Identifier>("p", allocator);
        auto *restElement = checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, allocator, id);
        auto *const param = checker->AllocNode<ir::ETSParameterExpression>(restElement, nullptr);
        auto [_, var] = checker->VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(checker->CreateETSArrayType(checker->GlobalETSNullishObjectType()));
        var->SetScope(paramCtx.GetScope());
        param->Ident()->SetVariable(var);
        param->SetParent(lambda->Function());
        invokeFunc->Params().push_back(param);
        invokeSignatureInfo->restVar = var->AsLocalVariable();
    }

    // Create the function type for the invoke method
    auto *invokeSignature = checker->CreateSignature(invokeSignatureInfo,
                                                     ifaceOverride ? checker->GlobalETSNullishObjectType()
                                                                   : lambda->Function()->Signature()->ReturnType(),
                                                     invokeFunc);
    invokeSignature->SetOwner(lambdaObjectType);
    invokeSignature->AddSignatureFlag(checker::SignatureFlags::CALL);

    return invokeSignature;
}

void ETSChecker::ResolveLambdaObjectInvoke(ir::ClassDefinition *lambdaObject, ir::ArrowFunctionExpression *lambda,
                                           ir::MethodDefinition *proxyMethod, bool isStatic, bool ifaceOverride)
{
    const auto &lambdaBody = lambdaObject->Body();
    auto *invokeFunc = lambdaBody[lambdaBody.size() - (ifaceOverride ? 2 : 1)]->AsMethodDefinition()->Function();
    ETSObjectType *lambdaObjectType = lambdaObject->TsType()->AsETSObjectType();

    // Set the implicit 'this' parameters type to the lambda object
    auto *thisVar = invokeFunc->Scope()->ParamScope()->Params().front();
    thisVar->SetTsType(lambdaObjectType);

    // Create the function type for the invoke method
    auto *invokeSignature = CreateInvokeSignature(this, lambda, invokeFunc, lambdaObjectType, ifaceOverride);
    auto *invokeType = CreateETSFunctionType(invokeSignature);
    invokeFunc->SetSignature(invokeSignature);
    invokeFunc->Id()->Variable()->SetTsType(invokeType);
    VarBinder()->AsETSBinder()->BuildFunctionName(invokeFunc);
    lambdaObjectType->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invokeFunc->Id()->Variable()->AsLocalVariable());

    if (invokeFunc->IsAsyncFunc()) {
        return;
    }

    // Fill out the type information for the body of the invoke function
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObjectInvokeFuncBody(lambdaObject, lambda, proxyMethod, isStatic, ifaceOverride);
}

/* Pulled out to appease the Chinese checker */

static void AddFieldRefsToCallParameters(ETSChecker *checker, ir::ClassDefinition *lambdaObject, bool isStatic,
                                         ArenaVector<ir::Expression *> &callParams)
{
    auto *allocator = checker->Allocator();
    auto &lambdaBody = lambdaObject->Body();
    size_t counter = isStatic ? lambdaBody.size() - 3 : lambdaBody.size() - 4;
    for (size_t i = 0; i < counter; i++) {
        if (lambdaBody[i]->IsMethodDefinition()) {
            break;
        }

        auto *classProp = lambdaBody[i]->AsClassProperty();
        auto *param = allocator->New<ir::Identifier>(classProp->Key()->AsIdentifier()->Name(), allocator);
        param->SetVariable(classProp->Key()->AsIdentifier()->Variable());
        param->SetIgnoreBox();
        param->SetTsType(checker->MaybeBoxedType(param->Variable()));
        callParams.push_back(param);
    }
}

static ir::TSAsExpression *BuildNarrowingToType(ETSChecker *checker, ir::Expression *arg, Type *target)
{
    auto *boxedTarget = checker->MaybePromotedBuiltinType(target);
    auto *paramAsExpr =
        checker->AllocNode<ir::TSAsExpression>(arg, checker->AllocNode<ir::OpaqueTypeNode>(boxedTarget), false);
    if (boxedTarget != target) {
        paramAsExpr =
            checker->AllocNode<ir::TSAsExpression>(paramAsExpr, checker->AllocNode<ir::OpaqueTypeNode>(target), false);
    }
    return paramAsExpr;
}

static void AddLambdaFunctionParameters(ETSChecker *checker, ir::ScriptFunction *invokeFunc,
                                        ir::ArrowFunctionExpression *lambda, ArenaVector<ir::Expression *> &callParams)
{
    auto *allocator = checker->Allocator();
    auto nargs = invokeFunc->Params().size();
    for (size_t i = 0; i < nargs; i++) {
        auto const *const param = invokeFunc->Params()[i]->AsETSParameterExpression();
        auto *const paramIdent = allocator->New<ir::Identifier>(param->Ident()->Name(), allocator);
        paramIdent->SetVariable(param->Variable());
        paramIdent->SetTsType(param->Variable()->TsType());
        if (param->IsRestParameter()) {
            auto *spread =
                checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, allocator, paramIdent);
            spread->SetTsType(param->Variable()->TsType());
            callParams.push_back(spread);
        } else {
            auto *lambdaParam = lambda->Function()->Params()[i]->AsETSParameterExpression();
            auto *const paramCast =
                BuildNarrowingToType(checker, paramIdent, lambdaParam->TypeAnnotation()->GetType(checker));
            paramCast->Check(checker);
            callParams.push_back(paramCast);
        }
    }
}

ArenaVector<ir::Expression *> ETSChecker::ResolveCallParametersForLambdaFuncBody(ir::ClassDefinition *lambdaObject,
                                                                                 ir::ArrowFunctionExpression *lambda,
                                                                                 ir::ScriptFunction *invokeFunc,
                                                                                 bool isStatic, bool ifaceOverride)
{
    auto *allocator = Allocator();
    ArenaVector<ir::Expression *> callParams(allocator->Adapter());

    AddFieldRefsToCallParameters(this, lambdaObject, isStatic, callParams);

    auto maxParamsNum = GlobalBuiltinFunctionTypeVariadicThreshold();
    auto paramsNum = lambda->Function()->Params().size();
    if (!ifaceOverride) {
        for (auto const *const it : invokeFunc->Params()) {
            auto const *const param = it->AsETSParameterExpression();
            auto *const paramIdent = allocator->New<ir::Identifier>(param->Ident()->Name(), allocator);
            paramIdent->SetVariable(param->Variable());
            paramIdent->SetTsType(param->Variable()->TsType());
            if (param->IsRestParameter()) {
                auto *spread = AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, allocator, paramIdent);
                spread->SetTsType(param->Variable()->TsType());
                callParams.push_back(spread);
            } else {
                callParams.push_back(paramIdent);
            }
        }
    } else if (paramsNum < maxParamsNum) {
        // Then we add the lambda functions parameters to the call
        AddLambdaFunctionParameters(this, invokeFunc, lambda, callParams);
    } else {
        ASSERT(invokeFunc->Params().size() == 1);
        auto const *const param = invokeFunc->Params()[0]->AsETSParameterExpression();
        auto *const paramIdent = allocator->New<ir::Identifier>(param->Ident()->Name(), allocator);
        paramIdent->SetVariable(param->Variable());
        paramIdent->SetTsType(param->Variable()->TsType());

        for (size_t i = 0; i < paramsNum; i++) {
            auto *idx = allocator->New<ir::NumberLiteral>(lexer::Number(static_cast<int>(i)));
            auto *arg = allocator->New<ir::MemberExpression>(paramIdent, idx, ir::MemberExpressionKind::ELEMENT_ACCESS,
                                                             true, false);

            auto *lambdaParam = lambda->Function()->Params()[i]->AsETSParameterExpression();
            auto *const paramCast = BuildNarrowingToType(this, arg, lambdaParam->TypeAnnotation()->GetType(this));
            paramCast->Check(this);
            callParams.push_back(paramCast);
        }
    }

    return callParams;
}

void ETSChecker::ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambdaObject,
                                                   ir::ArrowFunctionExpression *lambda,
                                                   ir::MethodDefinition *proxyMethod, bool isStatic, bool ifaceOverride)
{
    const auto &lambdaBody = lambdaObject->Body();
    auto *proxySignature = proxyMethod->Function()->Signature();
    ir::Identifier *fieldIdent {};
    ETSObjectType *fieldPropType {};

    // If the proxy method is static, we should call it through the owner class itself
    if (isStatic) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        fieldIdent = AllocNode<ir::Identifier>(proxySignature->Owner()->Name(), Allocator());
        fieldPropType = proxySignature->Owner();
        fieldIdent->SetVariable(proxySignature->Owner()->Variable());
    } else {
        // Otherwise, we call the proxy method through the saved 'this' field
        auto *savedThis = lambdaBody[lambdaBody.size() - 4]->AsClassProperty();
        auto *fieldProp = savedThis->Key()->AsIdentifier()->Variable();
        fieldPropType = fieldProp->TsType()->AsETSObjectType();
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        fieldIdent = Allocator()->New<ir::Identifier>(savedThis->Key()->AsIdentifier()->Name(), Allocator());
        fieldIdent->SetVariable(fieldProp);
    }
    fieldIdent->SetTsType(fieldPropType);

    // Set the type information for the proxy function call
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcIdent = AllocNode<ir::Identifier>(proxyMethod->Function()->Id()->Name(), Allocator());
    auto *callee =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::MemberExpression>(fieldIdent, funcIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, false, false);
    callee->SetPropVar(proxySignature->OwnerVar()->AsLocalVariable());
    callee->SetObjectType(fieldPropType);
    callee->SetTsType(proxySignature->OwnerVar()->TsType());

    // Resolve the proxy method call arguments, first we add the captured fields to the call
    auto *invokeFunc = lambdaBody[lambdaBody.size() - (ifaceOverride ? 2 : 1)]->AsMethodDefinition()->Function();
    ArenaVector<ir::Expression *> callParams =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        ResolveCallParametersForLambdaFuncBody(lambdaObject, lambda, invokeFunc, isStatic, ifaceOverride);

    // Create the synthetic call expression to the proxy method
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *resolvedCall = AllocNode<ir::CallExpression>(callee, std::move(callParams), nullptr, false);
    resolvedCall->SetTsType(proxySignature->ReturnType());
    resolvedCall->SetSignature(proxySignature);

    ir::Expression *returnExpression = nullptr;
    if (proxySignature->ReturnType()->IsETSVoidType()) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *expressionStatementNode = AllocNode<ir::ExpressionStatement>(resolvedCall);
        expressionStatementNode->SetParent(invokeFunc->Body());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        invokeFunc->Body()->AsBlockStatement()->Statements().push_back(expressionStatementNode);
        if (ifaceOverride) {
            returnExpression = Allocator()->New<ir::UndefinedLiteral>();
            returnExpression->Check(this);
        }
    } else {
        if (ifaceOverride && resolvedCall->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            resolvedCall->AddBoxingUnboxingFlags(GetBoxingFlag(resolvedCall->TsType()));
        }
        returnExpression = resolvedCall;
    }

    auto *returnStatement = Allocator()->New<ir::ReturnStatement>(returnExpression);
    returnStatement->SetParent(invokeFunc->Body());
    invokeFunc->Body()->AsBlockStatement()->Statements().push_back(returnStatement);
}

void ETSChecker::ResolveLambdaObjectCtor(ir::ClassDefinition *lambdaObject)
{
    const auto &lambdaBody = lambdaObject->Body();
    auto *lambdaObjectType = lambdaObject->TsType()->AsETSObjectType();
    auto *ctorFunc = lambdaBody[lambdaBody.size() - 3]->AsMethodDefinition()->Function();

    // Set the implicit 'this' parameters type to the lambda object
    auto *thisVar = ctorFunc->Scope()->ParamScope()->Params().front();
    thisVar->SetTsType(lambdaObjectType);

    // Create the signature for the constructor function type
    auto *ctorSignatureInfo = CreateSignatureInfo();
    ctorSignatureInfo->restVar = nullptr;

    for (auto const *const it : ctorFunc->Params()) {
        ++ctorSignatureInfo->minArgCount;
        ctorSignatureInfo->params.push_back(it->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }

    // Create the function type for the constructor
    auto *ctorSignature = CreateSignature(ctorSignatureInfo, GlobalVoidType(), ctorFunc);
    ctorSignature->SetOwner(lambdaObjectType);
    ctorSignature->AddSignatureFlag(checker::SignatureFlags::CONSTRUCTOR | checker::SignatureFlags::CONSTRUCT);
    lambdaObjectType->AddConstructSignature(ctorSignature);

    auto *ctorType = CreateETSFunctionType(ctorSignature);
    ctorFunc->SetSignature(ctorSignature);
    ctorFunc->Id()->Variable()->SetTsType(ctorType);
    VarBinder()->AsETSBinder()->BuildFunctionName(ctorFunc);

    // Add the type information for the lambda field initializers in the constructor
    auto &initializers = ctorFunc->Body()->AsBlockStatement()->Statements();
    for (size_t i = 0; i < initializers.size(); i++) {
        auto *fieldinit = initializers[i]->AsExpressionStatement()->GetExpression()->AsAssignmentExpression();
        auto *ctorParamVar = ctorFunc->Params()[i]->AsETSParameterExpression()->Variable();
        auto *fieldVar = lambdaBody[i]->AsClassProperty()->Key()->AsIdentifier()->Variable();
        auto *leftHandSide = fieldinit->Left();
        leftHandSide->AsMemberExpression()->SetObjectType(lambdaObjectType);
        leftHandSide->AsMemberExpression()->SetPropVar(fieldVar->AsLocalVariable());
        leftHandSide->AsMemberExpression()->SetIgnoreBox();
        leftHandSide->AsMemberExpression()->SetTsType(fieldVar->TsType());
        leftHandSide->AsMemberExpression()->Object()->SetTsType(lambdaObjectType);
        fieldinit->Right()->AsIdentifier()->SetVariable(ctorParamVar);
        fieldinit->Right()->SetTsType(ctorParamVar->TsType());
    }
}

void ETSChecker::ResolveProxyMethod(ir::ClassDefinition *const classDefinition, ir::MethodDefinition *proxyMethod,
                                    ir::ArrowFunctionExpression *lambda)
{
    auto *const varbinder = VarBinder()->AsETSBinder();
    auto *func = proxyMethod->Function();
    bool isStatic = func->IsStatic();
    auto *currentClassType = Context().ContainingClass();

    // Build the proxy method in the binder
    varbinder->BuildProxyMethod(func, currentClassType->GetDeclNode()->AsClassDefinition()->InternalName(), isStatic,
                                lambda->Function()->IsExternal());

    // If the proxy method is not static, set the implicit 'this' parameters type to the current class
    if (!isStatic) {
        auto *thisVar = func->Scope()->ParamScope()->Params().front();
        thisVar->SetTsType(currentClassType);
    }

    // Fill out the type information for the proxy method
    auto *signature = func->Signature();
    auto *signatureInfo = signature->GetSignatureInfo();
    signatureInfo->restVar = nullptr;

    for (auto const *const it : proxyMethod->Function()->Params()) {
        auto *param = it->AsETSParameterExpression();
        if (param->IsRestParameter()) {
            signatureInfo->restVar = param->Variable()->AsLocalVariable();
        } else {
            signatureInfo->params.push_back(param->Variable()->AsLocalVariable());
            ++signatureInfo->minArgCount;
        }
    }

    signature->SetReturnType(lambda->Function()->Signature()->ReturnType());
    signature->SetOwner(currentClassType);

    // Add the proxy method to the current class methods
    auto *const variable = func->Id()->Variable()->AsLocalVariable();
    if (isStatic) {
        currentClassType->AddProperty<checker::PropertyType::STATIC_METHOD>(variable);
    } else {
        currentClassType->AddProperty<checker::PropertyType::INSTANCE_METHOD>(variable);
    }
    varbinder->BuildFunctionName(func);

    if (lambda->Function()->IsAsyncFunc()) {
        ir::MethodDefinition *asyncImpl = CreateAsyncProxy(proxyMethod, classDefinition);
        ir::ScriptFunction *asyncImplFunc = asyncImpl->Function();

        classDefinition->Body().emplace_back(asyncImpl);
        asyncImpl->SetParent(classDefinition);

        ReplaceIdentifierReferencesInProxyMethod(asyncImplFunc->Body(), asyncImplFunc->Params(), lambda);
        Signature *implSig = CreateSignature(proxyMethod->Function()->Signature()->GetSignatureInfo(),
                                             GlobalETSObjectType(), asyncImplFunc);
        asyncImplFunc->SetSignature(implSig);
        varbinder->BuildFunctionName(asyncImplFunc);
    }
}

size_t ETSChecker::ComputeProxyMethods(ir::ClassDefinition *klass)
{
    // Compute how many proxy methods are present in the current class, to be able to create a name for the proxy
    // method which doesn't conflict with any of the other ones
    size_t idx = 0;
    for (auto *it : klass->Body()) {
        if (!it->IsMethodDefinition()) {
            continue;
        }

        if (it->AsMethodDefinition()->Function()->IsProxy()) {
            idx++;
        }
    }
    return idx;
}

ir::ModifierFlags ETSChecker::GetFlagsForProxyLambda(bool isStatic)
{
    // If every captured variable in the lambda is local variable, the proxy method can be 'static' since it doesn't
    // use any of the classes properties
    ir::ModifierFlags flags = ir::ModifierFlags::PUBLIC;

    if (isStatic) {
        flags |= ir::ModifierFlags::STATIC;
    }

    return flags;
}

ir::ScriptFunction *ETSChecker::CreateProxyFunc(ir::ArrowFunctionExpression *lambda,
                                                ArenaVector<ir::AstNode *> &captured, bool isStatic)
{
    // Create the synthetic parameters for the proxy method
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcParamScope = CreateProxyMethodParams(lambda, params, captured, isStatic);

    // Create the scopes for the proxy method
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), funcParamScope);
    auto *body = lambda->Function()->Body();
    body->AsBlockStatement()->SetScope(scope);

    ir::ScriptFunctionFlags funcFlags = ir::ScriptFunctionFlags::METHOD | ir::ScriptFunctionFlags::PROXY;
    if (lambda->Function()->IsAsyncFunc()) {
        funcFlags |= ir::ScriptFunctionFlags::ASYNC;
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = Allocator()->New<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {
            body, ir::FunctionSignature(nullptr, std::move(params), lambda->Function()->ReturnTypeAnnotation()),
            funcFlags, GetFlagsForProxyLambda(isStatic)});

    func->SetScope(scope);
    if (!func->IsAsyncFunc()) {
        // Replace the variable binding in the lambda body where an identifier refers to a lambda parameter or a
        // captured variable to the newly created proxy parameters
        ReplaceIdentifierReferencesInProxyMethod(body, func->Params(), lambda);
    }

    for (auto param : func->Params()) {
        param->SetParent(func);
    }

    // Bind the scopes
    scope->BindNode(func);
    funcParamScope->BindNode(func);
    scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(scope);

    // Copy the bindings from the original function scope
    for (const auto &binding : lambda->Function()->Scope()->Bindings()) {
        scope->InsertBinding(binding.first, binding.second);
    }

    ReplaceScope(body, lambda->Function(), scope);
    return func;
}

ir::MethodDefinition *ETSChecker::CreateProxyMethodForLambda(ir::ClassDefinition *klass,
                                                             ir::ArrowFunctionExpression *lambda,
                                                             ArenaVector<ir::AstNode *> &captured, bool isStatic)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = CreateProxyFunc(lambda, captured, isStatic);

    // Create the synthetic proxy method
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    util::UString funcName(util::StringView("lambda$invoke$"), Allocator());
    funcName.Append(std::to_string(ComputeProxyMethods(klass)));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *identNode = AllocNode<ir::Identifier>(funcName.View(), Allocator());
    func->SetIdent(identNode);

    auto *identClone = identNode->Clone(Allocator(), nullptr);
    identClone->SetReference();
    auto *proxy = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, identClone, funcExpr,
                                                  GetFlagsForProxyLambda(isStatic), Allocator(), false);

    klass->Body().push_back(proxy);
    proxy->SetParent(klass);

    // Add the proxy method to the current class declarations
    CreateLambdaFuncDecl(proxy, klass->Scope()->AsClassScope()->InstanceMethodScope());

    // Create the signature template for the proxy method to be able to save this signatures pointer in the binder
    // lambdaObjects_ to be able to compute the lambda object invoke functions internal name later
    auto *proxySignatureInfo = CreateSignatureInfo();
    auto *proxySignature = CreateSignature(proxySignatureInfo, GlobalVoidType(), func);

    SignatureFlags signatureFlags = SignatureFlags::CALL;
    if (isStatic) {
        signatureFlags |= SignatureFlags::STATIC;
    }

    proxySignature->AddSignatureFlag(signatureFlags | SignatureFlags::PROXY);
    proxySignature->SetOwnerVar(func->Id()->Variable());
    auto *proxyType = CreateETSFunctionType(proxySignature);
    func->SetSignature(proxySignature);
    func->Id()->Variable()->SetTsType(proxyType);

    return proxy;
}

static std::unordered_map<varbinder::Variable *, size_t> MergeTargetReferences(
    const ArenaVector<ir::Expression *> &lambdaParams, const ArenaVector<varbinder::Variable *> &captured)
{
    // First, create a merged list of all of the potential references which we will replace. These references are
    // the original lambda expression parameters and the references to the captured variables inside the lambda
    // expression body. The order is crucial, thats why we save the index, because in the synthetic proxy method,
    // the first n number of parameters are which came from the lambda expression parameter list, and the last
    // parameters are which came from the captured variables
    std::unordered_map<varbinder::Variable *, size_t> mergedTargetReferences;
    size_t idx = 0;

    for (auto *it : captured) {
        if (it->HasFlag(varbinder::VariableFlags::LOCAL)) {
            mergedTargetReferences.insert({it, idx});
            idx++;
        }
    }

    for (auto const *const it : lambdaParams) {
        mergedTargetReferences.insert({it->AsETSParameterExpression()->Variable(), idx});
        idx++;
    }
    return mergedTargetReferences;
}

static void PropagateParamsForTransitiveCapturedVars(
    const ArenaVector<ir::Expression *> &proxyParams,
    const std::unordered_map<varbinder::Variable *, size_t> &mergedTargetReferences,
    ir::ArrowFunctionExpression *lambda)
{
    for (auto child : lambda->ChildLambdas()) {
        auto &vars = child->CapturedVars();
        for (auto &vp : vars) {
            auto ref = mergedTargetReferences.find(vp);
            if (ref != mergedTargetReferences.end()) {
                vp = proxyParams[ref->second]->AsETSParameterExpression()->Variable();
            }
        }
        PropagateParamsForTransitiveCapturedVars(proxyParams, mergedTargetReferences, child);
    }
}

void ETSChecker::ReplaceIdentifierReferencesInProxyMethod(ir::AstNode *body,
                                                          const ArenaVector<ir::Expression *> &proxyParams,
                                                          ir::ArrowFunctionExpression *lambda)
{
    const auto lambdaParams = lambda->Function()->Params();
    const auto captured = lambda->CapturedVars();
    if (proxyParams.empty()) {
        return;
    }

    const auto mergedTargetReferences = MergeTargetReferences(lambdaParams, captured);
    PropagateParamsForTransitiveCapturedVars(proxyParams, mergedTargetReferences, lambda);
    ReplaceIdentifierReferencesInProxyMethod(body, proxyParams, mergedTargetReferences);
}

void ETSChecker::ReplaceIdentifierReferencesInProxyMethod(
    ir::AstNode *node, const ArenaVector<ir::Expression *> &proxyParams,
    const std::unordered_map<varbinder::Variable *, size_t> &mergedTargetReferences)
{
    if (node != nullptr) {
        if (node->IsMemberExpression()) {
            auto *memberExpr = node->AsMemberExpression();
            if (memberExpr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS) {
                ReplaceIdentifierReferenceInProxyMethod(memberExpr->Object(), proxyParams, mergedTargetReferences);
                return;
            }
        }
        node->Iterate([this, &proxyParams, &mergedTargetReferences](ir::AstNode *childNode) {
            ReplaceIdentifierReferenceInProxyMethod(childNode, proxyParams, mergedTargetReferences);
        });
    }
}

void ETSChecker::ReplaceIdentifierReferenceInProxyMethod(
    ir::AstNode *node, const ArenaVector<ir::Expression *> &proxyParams,
    const std::unordered_map<varbinder::Variable *, size_t> &mergedTargetReferences)
{
    // If we see an identifier reference that is not a type reference part (ETS is not a dependently typed language...
    // yet)
    if (node->IsIdentifier() && !node->Parent()->IsETSTypeReferencePart()) {
        auto *identNode = node->AsIdentifier();
        ASSERT(identNode->Variable());

        // Then check if that reference is present in the target references which we want to replace
        auto found = mergedTargetReferences.find(identNode->Variable());
        if (found != mergedTargetReferences.end()) {
            // If it is present in the target references, replace it with the proper proxy parameter reference
            identNode->SetVariable(proxyParams[found->second]->AsETSParameterExpression()->Variable());
        }
    }

    ReplaceIdentifierReferencesInProxyMethod(node, proxyParams, mergedTargetReferences);
}

varbinder::FunctionParamScope *ETSChecker::CreateProxyMethodParams(ir::ArrowFunctionExpression *lambda,
                                                                   ArenaVector<ir::Expression *> &proxyParams,
                                                                   ArenaVector<ir::AstNode *> &captured, bool isStatic)
{
    const auto &params = lambda->Function()->Params();
    // Create a param scope for the proxy method parameters
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // First add the parameters to the proxy method, based on how many variables have been captured, if this
    // is NOT a static method, we doesn't need the last captured parameter, which is the 'this' reference, because
    // this proxy method is bound to the class itself which the 'this' capture is referred to
    if (!captured.empty()) {
        size_t counter = isStatic ? captured.size() : (captured.size() - 1);
        for (size_t i = 0; i < counter; i++) {
            auto *capturedVar = captured[i]->AsClassProperty()->Key()->AsIdentifier()->Variable();
            ir::Identifier *paramIdent = nullptr;

            // When a lambda is defined inside an instance extension function, if "this" is captured inside the lambda,
            // "this" should be binded with the parameter of the proxy method
            if (this->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD) &&
                lambda->CapturedVars()[i]->Name() == varbinder::VarBinder::MANDATORY_PARAM_THIS) {
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                paramIdent = AllocNode<ir::Identifier>(varbinder::VarBinder::MANDATORY_PARAM_THIS, Allocator());
            } else {
                // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
                paramIdent = AllocNode<ir::Identifier>(capturedVar->Name(), Allocator());
            }

            auto *param = AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
            auto [_, var] = VarBinder()->AddParamDecl(param);
            (void)_;
            var->SetTsType(capturedVar->TsType());
            if (capturedVar->HasFlag(varbinder::VariableFlags::BOXED)) {
                var->AddFlag(varbinder::VariableFlags::BOXED);
            }
            param->SetTsType(capturedVar->TsType());
            var->SetScope(paramCtx.GetScope());
            param->SetVariable(var);
            proxyParams.push_back(param);
        }
    }

    // Then add the lambda function parameters to the proxy method's parameter vector, and set the type from the
    // already computed types for the lambda parameters
    for (auto *const it : params) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const oldParameter = it->AsETSParameterExpression();
        auto *newParameter = oldParameter->Clone(Allocator(), nullptr);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto [_, var] = VarBinder()->AddParamDecl(newParameter);
        (void)_;
        var->SetTsType(oldParameter->Variable()->TsType());
        newParameter->SetVariable(var);
        newParameter->SetTsType(oldParameter->Variable()->TsType());
        proxyParams.push_back(newParameter);
    }

    return paramCtx.GetScope();
}

ir::ClassProperty *ETSChecker::CreateLambdaCapturedThis(varbinder::ClassScope *scope, size_t &idx,
                                                        const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the name for the synthetic property node
    util::UString fieldName(util::StringView("field"), Allocator());
    fieldName.Append(std::to_string(idx));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldIdent = Allocator()->New<ir::Identifier>(fieldName.View(), Allocator());

    // Create the synthetic class property node
    auto *field =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        Allocator()->New<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);

    // Add the declaration to the scope, and set the type based on the current class type, to be able to store the
    // 'this' reference
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, fieldIdent->Name());
    var->SetScope(scope->InstanceFieldScope());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(Context().ContainingClass());
    fieldIdent->SetVariable(var);
    field->SetTsType(Context().ContainingClass());
    decl->BindNode(field);
    return field;
}

ir::ClassProperty *ETSChecker::CreateLambdaCapturedField(const varbinder::Variable *capturedVar,
                                                         varbinder::ClassScope *scope, size_t &idx,
                                                         const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the name for the synthetic property node
    util::UString fieldName(util::StringView("field#"), Allocator());
    fieldName.Append(std::to_string(idx));
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldIdent = Allocator()->New<ir::Identifier>(fieldName.View(), Allocator());

    // Create the synthetic class property node
    auto *field =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        Allocator()->New<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);
    fieldIdent->SetParent(field);

    // Add the declaration to the scope, and set the type based on the captured variable's scope
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, fieldIdent->Name());
    var->SetScope(scope->InstanceFieldScope());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(capturedVar->TsType());
    if (capturedVar->HasFlag(varbinder::VariableFlags::BOXED)) {
        var->AddFlag(varbinder::VariableFlags::BOXED);
    }
    fieldIdent->SetVariable(var);
    field->SetTsType(MaybeBoxedType(capturedVar));
    decl->BindNode(field);
    return field;
}

ir::MethodDefinition *ETSChecker::CreateLambdaImplicitCtor(ArenaVector<ir::AstNode *> &properties)
{
    // Create the parameters for the synthetic constructor node for the lambda class
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcParamScope = CreateLambdaCtorImplicitParams(params, properties);

    // Create the scopes for the synthetic constructor node
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), funcParamScope);

    // Complete the synthetic constructor node's body, to be able to initialize every field by copying every
    // captured variables value
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    for (auto *it : properties) {
        auto *field = it->AsClassProperty()->Key()->AsIdentifier();
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        statements.push_back(CreateLambdaCtorFieldInit(field->Name(), field->Variable()));
    }

    // Create the synthetic constructor node
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::CONSTRUCTOR});
    func->SetScope(scope);

    // Set the scopes
    scope->BindNode(func);
    funcParamScope->BindNode(func);
    scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(scope);

    for (auto *param : func->Params()) {
        param->SetParent(func);
    }

    // Create the name for the synthetic constructor
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *key = AllocNode<ir::Identifier>("constructor", Allocator());
    func->SetIdent(key);

    auto *keyClone = key->Clone(Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, keyClone, funcExpr,
                                                 ir::ModifierFlags::NONE, Allocator(), false);

    return ctor;
}

varbinder::FunctionParamScope *ETSChecker::CreateLambdaCtorImplicitParams(ArenaVector<ir::Expression *> &params,
                                                                          ArenaVector<ir::AstNode *> &properties)
{
    // Create the scope for the synthetic constructor parameters
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // Create every parameter based on the synthetic field which was created for the lambda class to store the
    // captured variables
    for (auto *it : properties) {
        auto *field = it->AsClassProperty()->Key()->AsIdentifier();
        auto *paramField = field->Clone(Allocator(), nullptr);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *param = AllocNode<ir::ETSParameterExpression>(paramField, nullptr);
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        auto *type = MaybeBoxedType(field->Variable());
        var->SetTsType(type);
        param->Ident()->SetTsType(type);
        var->SetScope(paramCtx.GetScope());
        param->Ident()->SetVariable(var);
        params.push_back(param);
    }

    return paramCtx.GetScope();
}

ir::Statement *ETSChecker::CreateLambdaCtorFieldInit(util::StringView name, varbinder::Variable *var)
{
    // Create synthetic field initializers for the lambda class fields
    // The node structure is the following: this.field0 = field0, where the left hand side refers to the lambda
    // classes field, and the right hand side is refers to the constructors parameter
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *thisExpr = AllocNode<ir::ThisExpression>();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldAccessExpr = AllocNode<ir::Identifier>(name, Allocator());
    fieldAccessExpr->SetReference();
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *leftHandSide = AllocNode<ir::MemberExpression>(thisExpr, fieldAccessExpr,
                                                         ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *rightHandSide = AllocNode<ir::Identifier>(name, Allocator());
    rightHandSide->SetVariable(var);
    auto *initializer =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::AssignmentExpression>(leftHandSide, rightHandSide, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    return AllocNode<ir::ExpressionStatement>(initializer);
}

// Lambda creation for Function references

void ETSChecker::CreateLambdaObjectForFunctionReference(ir::AstNode *refNode, Signature *signature,
                                                        ETSObjectType *functionalInterface)
{
    if (VarBinder()->AsETSBinder()->LambdaObjects().count(refNode) != 0) {
        return;
    }

    /* signature has been converted through BpxPrimitives, we need to call the original one */
    auto *trueSignature = signature->Function()->Signature();

    // Create the class scope for the synthetic lambda class node
    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *classScope = classCtx.GetScope();
    bool isStaticReference = trueSignature->HasSignatureFlag(SignatureFlags::STATIC);

    // Create the synthetic field where we will store the instance object which we are trying to obtain the function
    // reference through, if the referenced function is static, we won't need to store the instance object
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());
    if (!isStaticReference) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        properties.push_back(CreateLambdaImplicitField(classScope, refNode->Start()));
    }

    // Create the synthetic constructor node, where we will initialize the synthetic field (if present) to the
    // instance object
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *ctor = CreateLambdaImplicitCtor(refNode->Range(), isStaticReference);
    properties.push_back(ctor);

    // Create the template for the synthetic invoke function which will propagate the function call to the saved
    // instance's referenced function, or the class static function, if this is a static reference
    auto *invoke0Func = CreateLambdaInvokeProto(FUNCTIONAL_INTERFACE_INVOKE_METHOD_NAME);
    auto *invokeFunc = CreateLambdaInvokeProto("invoke");
    properties.push_back(invoke0Func);
    properties.push_back(invokeFunc);

    // Create the declarations for the synthetic constructor and invoke method
    CreateLambdaFuncDecl(ctor, classScope->StaticMethodScope());
    CreateLambdaFuncDecl(invoke0Func, classScope->InstanceMethodScope());
    CreateLambdaFuncDecl(invokeFunc, classScope->InstanceMethodScope());

    // Create the synthetic lambda class node
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *identNode = Allocator()->New<ir::Identifier>(util::StringView("LambdaObject"), Allocator());
    auto *lambdaObject =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        Allocator()->New<ir::ClassDefinition>(Allocator(), identNode, std::move(properties),
                                              ir::ClassDefinitionModifiers::DECLARATION, Language(Language::Id::ETS));
    lambdaObject->SetScope(classScope);
    // Set the parent nodes
    ctor->SetParent(lambdaObject);
    invoke0Func->SetParent(lambdaObject);
    invokeFunc->SetParent(lambdaObject);
    classScope->BindNode(lambdaObject);

    for (auto *param : lambdaObject->Body()) {
        param->SetParent(lambdaObject);
    }

    // Build the lambda object in the binder
    VarBinder()->AsETSBinder()->BuildLambdaObject(refNode, lambdaObject, trueSignature,
                                                  invokeFunc->Function()->IsExternal());

    // Resolve the lambda object
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObject(lambdaObject, trueSignature, functionalInterface, refNode);
}

ir::AstNode *ETSChecker::CreateLambdaImplicitField(varbinder::ClassScope *scope, const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the synthetic class property node
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *fieldIdent = Allocator()->New<ir::Identifier>("field0", Allocator());
    auto *field =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        Allocator()->New<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);

    // Add the declaration to the scope
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, fieldIdent->Name());
    var->SetScope(scope->InstanceFieldScope());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    fieldIdent->SetVariable(var);
    fieldIdent->SetParent(field);
    decl->BindNode(field);
    return field;
}

ir::MethodDefinition *ETSChecker::CreateLambdaImplicitCtor(const lexer::SourceRange &pos, bool isStaticReference)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    // Create the parameters for the synthetic constructor
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto [funcParamScope, var] = CreateLambdaCtorImplicitParam(params, pos, isStaticReference);

    // Create the scopes
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), funcParamScope);

    // If the reference refers to a static function, the constructor will be empty, otherwise, we have to make a
    // synthetic initializer to initialize the lambda class field
    if (!isStaticReference) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        statements.push_back(CreateLambdaCtorFieldInit(util::StringView("field0"), var));
    }
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::CONSTRUCTOR});
    func->SetScope(scope);
    // Bind the scopes
    scope->BindNode(func);
    funcParamScope->BindNode(func);
    scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(scope);

    for (auto *param : func->Params()) {
        param->SetParent(func);
    }

    // Create the synthetic constructor
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *key = AllocNode<ir::Identifier>("constructor", Allocator());
    func->SetIdent(key);

    auto *keyClone = key->Clone(Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, keyClone, funcExpr,
                                                 ir::ModifierFlags::NONE, Allocator(), false);

    return ctor;
}

std::tuple<varbinder::FunctionParamScope *, varbinder::Variable *> ETSChecker::CreateLambdaCtorImplicitParam(
    ArenaVector<ir::Expression *> &params, const lexer::SourceRange &pos, bool isStaticReference)
{
    // Create the function parameter scope
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // Create the synthetic constructors parameter, if this is a static reference, we don't need any parameter,
    // since when initializing the lambda class, we don't need to save the instance object which we tried to get the
    // function reference through
    if (!isStaticReference) {
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *paramIdent = AllocNode<ir::Identifier>("field0", Allocator());
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *param = AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
        paramIdent->SetRange(pos);
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        paramIdent->SetVariable(var);
        params.push_back(param);
        return {paramCtx.GetScope(), var};
    }

    return {paramCtx.GetScope(), nullptr};
}

ir::MethodDefinition *ETSChecker::CreateLambdaInvokeProto(util::StringView invokeName)
{
    // Create the template for the synthetic 'invoke' method, which will be used when the function type will be
    // called
    auto *paramScope =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), VarBinder()->GetScope());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::METHOD, ir::ModifierFlags::PUBLIC});
    func->SetScope(scope);

    scope->BindNode(func);
    paramScope->BindNode(func);
    scope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(scope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *name = AllocNode<ir::Identifier>(invokeName, Allocator());
    func->SetIdent(name);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);

    auto *nameClone = name->Clone(Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *method = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, nameClone, funcExpr,
                                                   ir::ModifierFlags::PUBLIC, Allocator(), false);

    return method;
}

void ETSChecker::CreateLambdaFuncDecl(ir::MethodDefinition *func, varbinder::LocalScope *scope)
{
    // Add the function declarations to the lambda class scope
    auto ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope);
    varbinder::Variable *var = scope->FindLocal(func->Id()->Name(), varbinder::ResolveBindingOptions::ALL_DECLARATION);
    if (var == nullptr) {
        var = std::get<1>(
            VarBinder()->NewVarDecl<varbinder::FunctionDecl>(func->Start(), Allocator(), func->Id()->Name(), func));
    }
    var->AddFlag(varbinder::VariableFlags::METHOD);
    var->SetScope(ctx.GetScope());
    func->Function()->Id()->SetVariable(var);
}

void ETSChecker::ResolveLambdaObject(ir::ClassDefinition *lambdaObject, Signature *signature,
                                     ETSObjectType *functionalInterface, ir::AstNode *refNode)
{
    // Set the type information for the lambda class, which will be required by the compiler
    Type *targetType = signature->Owner();
    bool isStaticReference = signature->HasSignatureFlag(SignatureFlags::STATIC);
    varbinder::Variable *fieldVar {};

    // If this is NOT a static function reference, we have to set the field's type to the referenced signatures
    // owner type, because that will be the type of the instance object which will be saved in that field
    if (!isStaticReference) {
        auto *field = lambdaObject->Body()[0]->AsClassProperty();
        fieldVar = field->Key()->AsIdentifier()->Variable();
        field->SetTsType(targetType);
        fieldVar->SetTsType(targetType);
        auto *ctorFunc = lambdaObject->Body()[1]->AsMethodDefinition()->Function();
        ctorFunc->Params()[0]->AsETSParameterExpression()->Variable()->SetTsType(targetType);
    }

    // Create the class type for the lambda
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *lambdaObjectType = Allocator()->New<checker::ETSObjectType>(Allocator(), lambdaObject->Ident()->Name(),
                                                                      lambdaObject->Ident()->Name(), lambdaObject,
                                                                      checker::ETSObjectFlags::CLASS, Relation());

    // Add the target function type to the implementing interfaces, this way, we can call the functional interface
    // virtual 'invoke' method and it will propagate the call to the currently stored lambda class 'invoke' function
    // which was assigned to the variable
    lambdaObjectType->AddInterface(functionalInterface);
    lambdaObject->SetTsType(lambdaObjectType);

    // Add the field if this is not a static reference to the lambda class type
    if (!isStaticReference) {
        lambdaObjectType->AddProperty<checker::PropertyType::INSTANCE_FIELD>(fieldVar->AsLocalVariable());
    }
    VarBinder()->AsETSBinder()->BuildLambdaObjectName(refNode);

    // Resolve the constructor
    ResolveLambdaObjectCtor(lambdaObject, isStaticReference);

    // Resolve the invoke function
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObjectInvoke(lambdaObject, signature, true);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ResolveLambdaObjectInvoke(lambdaObject, signature, false);
}

void ETSChecker::ResolveLambdaObjectCtor(ir::ClassDefinition *lambdaObject, bool isStaticReference)
{
    const auto &lambdaBody = lambdaObject->Body();
    auto *ctorFunc = lambdaBody[lambdaBody.size() - 3]->AsMethodDefinition()->Function();
    ETSObjectType *lambdaObjectType = lambdaObject->TsType()->AsETSObjectType();
    varbinder::Variable *fieldVar {};

    if (!isStaticReference) {
        auto *field = lambdaBody[0]->AsClassProperty();
        fieldVar = field->Key()->AsIdentifier()->Variable();
    }

    // Set the implicit 'this' parameters type to the lambda object
    auto *thisVar = ctorFunc->Scope()->ParamScope()->Params().front();
    thisVar->SetTsType(lambdaObjectType);

    // Create the signature for the constructor function type
    auto *ctorSignatureInfo = CreateSignatureInfo();
    ctorSignatureInfo->restVar = nullptr;

    if (isStaticReference) {
        ctorSignatureInfo->minArgCount = 0;
    } else {
        ctorSignatureInfo->minArgCount = 1;
        ctorSignatureInfo->params.push_back(
            ctorFunc->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }

    // Create the function type for the constructor
    auto *ctorSignature = CreateSignature(ctorSignatureInfo, GlobalVoidType(), ctorFunc);
    ctorSignature->SetOwner(lambdaObjectType);
    ctorSignature->AddSignatureFlag(checker::SignatureFlags::CONSTRUCTOR | checker::SignatureFlags::CONSTRUCT);
    lambdaObjectType->AddConstructSignature(ctorSignature);

    auto *ctorType = CreateETSFunctionType(ctorSignature);
    ctorFunc->SetSignature(ctorSignature);
    ctorFunc->Id()->Variable()->SetTsType(ctorType);
    VarBinder()->AsETSBinder()->BuildFunctionName(ctorFunc);

    // If this is a static function reference, we are done, since the constructor body is empty
    if (isStaticReference) {
        return;
    }

    // Otherwise, set the type information for the field initializer
    auto *fieldinit = ctorFunc->Body()
                          ->AsBlockStatement()
                          ->Statements()[0]
                          ->AsExpressionStatement()
                          ->GetExpression()
                          ->AsAssignmentExpression();

    auto *leftHandSide = fieldinit->Left();
    leftHandSide->AsMemberExpression()->SetObjectType(lambdaObjectType);
    leftHandSide->AsMemberExpression()->SetPropVar(fieldVar->AsLocalVariable());
    leftHandSide->AsMemberExpression()->SetTsType(fieldVar->TsType());
    leftHandSide->AsMemberExpression()->Object()->SetTsType(lambdaObjectType);
    fieldinit->Right()->AsIdentifier()->SetVariable(ctorSignature->Params()[0]);
    fieldinit->Right()->SetTsType(ctorSignature->Params()[0]->TsType());
}

static void CreateParametersForInvokeSignature(ETSChecker *checker, Signature *signatureRef,
                                               ir::ScriptFunction *invokeFunc, bool ifaceOverride)
{
    auto *allocator = checker->Allocator();

    // Create the signature for the invoke function type
    auto *invokeSignatureInfo = checker->CreateSignatureInfo();
    for (auto *it : signatureRef->Params()) {
        auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            checker->VarBinder(), invokeFunc->Scope()->ParamScope(), false);

        auto *paramIdent = checker->AllocNode<ir::Identifier>(it->Name(), allocator);
        auto *param = checker->AllocNode<ir::ETSParameterExpression>(paramIdent, nullptr);
        auto [_, var] = checker->VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(ifaceOverride ? checker->GlobalETSNullishObjectType() : it->TsType());
        paramIdent->SetVariable(var);
        invokeFunc->Params().push_back(param);
        invokeSignatureInfo->minArgCount++;
        invokeSignatureInfo->params.push_back(var->AsLocalVariable());
    }
    if (signatureRef->RestVar() != nullptr) {
        auto *oldRestVar = signatureRef->RestVar();
        auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            checker->VarBinder(), invokeFunc->Scope()->ParamScope(), false);
        auto *restParamIdent = checker->AllocNode<ir::Identifier>(oldRestVar->Name(), allocator);
        auto *restParamSpread =
            checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, allocator, restParamIdent);
        auto *restParam = checker->AllocNode<ir::ETSParameterExpression>(restParamSpread, nullptr);
        auto [_, restVar] = checker->VarBinder()->AddParamDecl(restParam);
        (void)_;
        if (ifaceOverride) {
            restVar->SetTsType(allocator->New<ETSArrayType>(checker->GlobalETSNullishObjectType()));
        } else {
            restVar->SetTsType(oldRestVar->TsType());
        }
        restParamIdent->SetVariable(restVar);
        invokeFunc->Params().push_back(restParam);
        invokeSignatureInfo->restVar = restVar->AsLocalVariable();
    }
}

static Signature *CreateInvokeSignature(ETSChecker *checker, Signature *signatureRef, ir::ScriptFunction *invokeFunc,
                                        ETSObjectType *lambdaObjectType, bool ifaceOverride)
{
    auto *allocator = checker->Allocator();

    // Create the signature for the invoke function type
    auto *invokeSignatureInfo = checker->CreateSignatureInfo();
    invokeSignatureInfo->restVar = nullptr;

    // Create the parameters for the invoke function, based on the referenced function's signature
    auto maxParamsNum = checker->GlobalBuiltinFunctionTypeVariadicThreshold();
    auto paramsNum = signatureRef->Params().size();
    if (paramsNum < maxParamsNum || !ifaceOverride) {
        CreateParametersForInvokeSignature(checker, signatureRef, invokeFunc, ifaceOverride);
    } else {
        auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            checker->VarBinder(), invokeFunc->Scope()->ParamScope(), false);

        auto *id = checker->AllocNode<ir::Identifier>("p", allocator);
        auto *restElement = checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, allocator, id);
        auto *const param = checker->AllocNode<ir::ETSParameterExpression>(restElement, nullptr);
        auto [_, var] = checker->VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(checker->CreateETSArrayType(checker->GlobalETSObjectType()));
        param->Ident()->SetVariable(var);
        param->SetParent(invokeFunc);
        invokeFunc->Params().push_back(param);
        invokeSignatureInfo->restVar = var->AsLocalVariable();
    }

    // Create the function type for the constructor
    auto *invokeSignature = checker->CreateSignature(
        invokeSignatureInfo, ifaceOverride ? checker->GlobalETSObjectType() : signatureRef->ReturnType(), invokeFunc);
    invokeSignature->SetOwner(lambdaObjectType);
    invokeSignature->AddSignatureFlag(checker::SignatureFlags::CALL);

    return invokeSignature;
}

void ETSChecker::ResolveLambdaObjectInvoke(ir::ClassDefinition *lambdaObject, Signature *signatureRef,
                                           bool ifaceOverride)
{
    const auto &lambdaBody = lambdaObject->Body();
    auto *invokeFunc = lambdaBody[lambdaBody.size() - (ifaceOverride ? 2 : 1)]->AsMethodDefinition()->Function();
    ETSObjectType *lambdaObjectType = lambdaObject->TsType()->AsETSObjectType();

    // Set the implicit 'this' parameters type to the lambda object
    auto *thisVar = invokeFunc->Scope()->ParamScope()->Params().front();
    thisVar->SetTsType(lambdaObjectType);

    auto *invokeSignature = CreateInvokeSignature(this, signatureRef, invokeFunc, lambdaObjectType, ifaceOverride);

    auto *invokeType = CreateETSFunctionType(invokeSignature);
    invokeFunc->SetSignature(invokeSignature);
    invokeFunc->Id()->Variable()->SetTsType(invokeType);
    VarBinder()->AsETSBinder()->BuildFunctionName(invokeFunc);
    lambdaObjectType->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invokeFunc->Id()->Variable()->AsLocalVariable());

    // Fill out the type information for the body of the invoke function
    ResolveLambdaObjectInvokeFuncBody(lambdaObject, signatureRef, ifaceOverride);
}

static ir::Expression *BuildParamExpression(ETSChecker *checker, ir::Identifier *paramIdent, Type *type)
{
    if (type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        auto *boxedType = checker->PrimitiveTypeAsETSBuiltinType(type);
        auto *boxedTypeNode = checker->AllocNode<ir::OpaqueTypeNode>(boxedType);
        boxedTypeNode->SetTsType(boxedType);
        auto *paramAsExpr = checker->AllocNode<ir::TSAsExpression>(paramIdent, boxedTypeNode, false);
        paramAsExpr->SetTsType(boxedType);
        paramAsExpr->AddBoxingUnboxingFlags(checker->GetUnboxingFlag(type));
        return paramAsExpr;
    }
    checker::CastingContext ctx(checker->Relation(), paramIdent, paramIdent->TsType(), type, paramIdent->Start(), {});
    auto *const paramCast = checker->Allocator()->New<ir::TSAsExpression>(paramIdent, nullptr, false);
    paramCast->SetUncheckedCast(ctx.UncheckedCast());
    paramCast->SetTsType(type);
    return paramCast;
}

static void AddLambdaFunctionParameters(ETSChecker *checker, Signature *signatureRef, ir::ScriptFunction *invokeFunc,
                                        ArenaVector<ir::Expression *> &callParams)
{
    auto *allocator = checker->Allocator();
    auto nargs = invokeFunc->Params().size();
    for (size_t i = 0; i < nargs; i++) {
        auto const *const param = invokeFunc->Params()[i]->AsETSParameterExpression();
        auto *const paramIdent = allocator->New<ir::Identifier>(param->Ident()->Name(), allocator);
        paramIdent->SetVariable(param->Variable());
        paramIdent->SetTsType(param->Variable()->TsType());
        if (param->IsRestParameter()) {
            auto *spreadArg = BuildParamExpression(checker, paramIdent, signatureRef->RestVar()->TsType());
            auto *spread = checker->AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, allocator, spreadArg);
            spread->SetTsType(signatureRef->RestVar()->TsType());
            callParams.push_back(spread);
        } else {
            callParams.push_back(BuildParamExpression(checker, paramIdent, signatureRef->Params()[i]->TsType()));
        }
    }
}

ArenaVector<ir::Expression *> ETSChecker::ResolveCallParametersForLambdaFuncBody(Signature *signatureRef,
                                                                                 ir::ScriptFunction *invokeFunc,
                                                                                 bool ifaceOverride)
{
    auto *allocator = Allocator();
    ArenaVector<ir::Expression *> callParams(allocator->Adapter());

    auto maxParamsNum = GlobalBuiltinFunctionTypeVariadicThreshold();
    auto paramsNum = signatureRef->Params().size();
    if (!ifaceOverride) {
        for (size_t idx = 0; idx != paramsNum; idx++) {
            auto *paramIdent = allocator->New<ir::Identifier>(signatureRef->Params()[idx]->Name(), allocator);
            paramIdent->SetVariable(invokeFunc->Params()[idx]->AsETSParameterExpression()->Variable());
            paramIdent->SetTsType(invokeFunc->Params()[idx]->AsETSParameterExpression()->Variable()->TsType());
            callParams.push_back(paramIdent);
        }
    } else if (paramsNum < maxParamsNum) {
        // Then we add the lambda functions parameters to the call
        AddLambdaFunctionParameters(this, signatureRef, invokeFunc, callParams);
    } else {
        ASSERT(invokeFunc->Params().size() == 1);
        auto const *const param = invokeFunc->Params()[0]->AsETSParameterExpression();
        auto *const paramIdent = allocator->New<ir::Identifier>(param->Ident()->Name(), allocator);
        paramIdent->SetVariable(param->Variable());
        paramIdent->SetTsType(param->Variable()->TsType());

        for (size_t i = 0; i < paramsNum; i++) {
            auto *idx = allocator->New<ir::NumberLiteral>(lexer::Number(static_cast<int>(i)));
            auto *arg = allocator->New<ir::MemberExpression>(paramIdent, idx, ir::MemberExpressionKind::ELEMENT_ACCESS,
                                                             true, false);

            auto *type = signatureRef->Params()[i]->TsType();
            if (type->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
                arg->AddBoxingUnboxingFlags(GetUnboxingFlag(type));
                callParams.push_back(arg);
            } else {
                auto *const paramCast = allocator->New<ir::TSAsExpression>(arg, nullptr, false);
                paramCast->SetTsType(type);
                callParams.push_back(paramCast);
            }
        }
    }

    return callParams;
}

void ETSChecker::ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambdaObject, Signature *signatureRef,
                                                   bool ifaceOverride)
{
    const auto &lambdaBody = lambdaObject->Body();
    bool isStaticReference = signatureRef->HasSignatureFlag(SignatureFlags::STATIC);
    ir::Identifier *fieldIdent {};
    ETSObjectType *fieldPropType {};

    // If this is a static function reference, we have to call the referenced function through the class itself
    if (isStaticReference) {
        fieldIdent = AllocNode<ir::Identifier>(signatureRef->Owner()->Name(), Allocator());
        fieldIdent->SetReference();
        fieldPropType = signatureRef->Owner();
        fieldIdent->SetVariable(signatureRef->Owner()->Variable());
    } else {
        // Otherwise, we should call the referenced function through the saved field, which hold the object instance
        // reference
        auto *fieldProp = lambdaBody[0]->AsClassProperty()->Key()->AsIdentifier()->Variable();
        fieldPropType = fieldProp->TsType()->AsETSObjectType();
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        fieldIdent = AllocNode<ir::Identifier>("field0", Allocator());
        fieldIdent->SetReference();
        fieldIdent->SetVariable(fieldProp);
    }
    fieldIdent->SetTsType(fieldPropType);

    // Set the type information for the function reference call
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcIdent = AllocNode<ir::Identifier>(signatureRef->Function()->Id()->Name(), Allocator());
    auto *callee =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        AllocNode<ir::MemberExpression>(fieldIdent, funcIdent, ir::MemberExpressionKind::ELEMENT_ACCESS, false, false);
    callee->SetPropVar(signatureRef->OwnerVar()->AsLocalVariable());
    callee->SetObjectType(fieldPropType);
    callee->SetTsType(signatureRef->OwnerVar()->TsType());
    fieldIdent->SetParent(callee);

    // Create the parameters for the referenced function call
    auto *invokeFunc = lambdaBody[lambdaBody.size() - (ifaceOverride ? 2 : 1)]->AsMethodDefinition()->Function();
    ArenaVector<ir::Expression *> callParams =
        ResolveCallParametersForLambdaFuncBody(signatureRef, invokeFunc, ifaceOverride);

    // Create the synthetic call expression to the referenced function
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *resolvedCall = AllocNode<ir::CallExpression>(callee, std::move(callParams), nullptr, false);
    resolvedCall->SetTsType(signatureRef->ReturnType());
    resolvedCall->SetSignature(signatureRef);

    ir::Expression *returnExpression = nullptr;
    if (signatureRef->ReturnType()->IsETSVoidType()) {
        auto *expressionStatementNode = AllocNode<ir::ExpressionStatement>(resolvedCall);
        expressionStatementNode->SetParent(invokeFunc->Body());
        invokeFunc->Body()->AsBlockStatement()->Statements().push_back(expressionStatementNode);
        if (ifaceOverride) {
            returnExpression = Allocator()->New<ir::UndefinedLiteral>();
            returnExpression->Check(this);
        }
    } else {
        if (ifaceOverride && resolvedCall->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            resolvedCall->AddBoxingUnboxingFlags(GetBoxingFlag(resolvedCall->TsType()));
        }
        returnExpression = resolvedCall;
    }

    auto *returnStatement = Allocator()->New<ir::ReturnStatement>(returnExpression);
    returnStatement->SetParent(invokeFunc->Body());
    invokeFunc->Body()->AsBlockStatement()->Statements().push_back(returnStatement);
}

bool ETSChecker::AreOverrideEquivalent(Signature *const s1, Signature *const s2)
{
    // Two functions, methods or constructors M and N have the same signature if
    // their names and type parameters (if any) are the same, and their formal parameter
    // types are also the same (after the formal parameter types of N are adapted to the type parameters of M).
    // Signatures s1 and s2 are override-equivalent only if s1 and s2 are the same.

    SavedTypeRelationFlagsContext savedFlagsCtx(Relation(), TypeRelationFlag::OVERRIDING_CONTEXT);
    return s1->Function()->Id()->Name() == s2->Function()->Id()->Name() && Relation()->IsCompatibleTo(s1, s2);
}

bool ETSChecker::IsReturnTypeSubstitutable(Signature *const s1, Signature *const s2)
{
    auto *const r1 = s1->ReturnType();
    auto *const r2 = s2->ReturnType();

    // A method declaration d1 with return type R1 is return-type-substitutable for another method d2 with return
    // type R2 if any of the following is true:

    // - If R1 is a primitive type then R2 is identical to R1.
    if (r1->HasTypeFlag(TypeFlag::ETS_PRIMITIVE | TypeFlag::ETS_ENUM | TypeFlag::ETS_STRING_ENUM |
                        TypeFlag::ETS_VOID)) {
        return Relation()->IsIdenticalTo(r2, r1);
    }

    // - If R1 is a reference type then R1, adapted to the type parameters of d2 (link to generic methods), is a
    // subtype of R2.
    ASSERT(IsReferenceType(r1));
    return Relation()->IsSupertypeOf(r2, r1);
}

std::string ETSChecker::GetAsyncImplName(const util::StringView &name)
{
    std::string implName(name);
    implName += "$asyncimpl";
    return implName;
}

std::string ETSChecker::GetAsyncImplName(ir::MethodDefinition *asyncMethod)
{
    ir::Identifier *asyncName = asyncMethod->Function()->Id();
    ASSERT(asyncName != nullptr);
    return GetAsyncImplName(asyncName->Name());
}

ir::MethodDefinition *ETSChecker::CreateAsyncImplMethod(ir::MethodDefinition *asyncMethod,
                                                        ir::ClassDefinition *classDef)
{
    util::UString implName(GetAsyncImplName(asyncMethod), Allocator());
    ir::ModifierFlags modifiers = asyncMethod->Modifiers();
    // clear ASYNC flag for implementation
    modifiers &= ~ir::ModifierFlags::ASYNC;
    ir::ScriptFunction *asyncFunc = asyncMethod->Function();
    ir::ScriptFunctionFlags flags = ir::ScriptFunctionFlags::METHOD;
    if (asyncFunc->IsProxy()) {
        flags |= ir::ScriptFunctionFlags::PROXY;
    }
    asyncMethod->AddModifier(ir::ModifierFlags::NATIVE);
    asyncFunc->AddModifier(ir::ModifierFlags::NATIVE);
    // Create async_impl method copied from CreateInvokeFunction
    auto scopeCtx =
        varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), classDef->Scope()->AsClassScope());
    auto *body = asyncFunc->Body();
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    varbinder::FunctionParamScope *paramScope = CopyParams(asyncFunc->Params(), params);

    // Set impl method return type "Object" because it may return Promise as well as Promise parameter's type
    auto *objectId = AllocNode<ir::Identifier>(compiler::Signatures::BUILTIN_OBJECT_CLASS, Allocator());
    objectId->SetReference();
    VarBinder()->AsETSBinder()->LookupTypeReference(objectId, false);
    auto *returnTypeAnn =
        AllocNode<ir::ETSTypeReference>(AllocNode<ir::ETSTypeReferencePart>(objectId, nullptr, nullptr));
    objectId->SetParent(returnTypeAnn->Part());
    returnTypeAnn->Part()->SetParent(returnTypeAnn);
    auto *asyncFuncRetTypeAnn = asyncFunc->ReturnTypeAnnotation();
    auto *promiseType = [this](ir::TypeNode *type) {
        if (type != nullptr) {
            return type->GetType(this)->AsETSObjectType();
        }

        return GlobalBuiltinPromiseType()->AsETSObjectType();
    }(asyncFuncRetTypeAnn);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *retType = Allocator()->New<ETSAsyncFuncReturnType>(Allocator(), Relation(), promiseType);
    returnTypeAnn->SetTsType(retType);

    ir::MethodDefinition *implMethod =
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        CreateMethod(implName.View(), modifiers, flags, std::move(params), paramScope, returnTypeAnn, body);
    asyncFunc->SetBody(nullptr);
    returnTypeAnn->SetParent(implMethod->Function());
    implMethod->SetParent(asyncMethod->Parent());
    return implMethod;
}

ir::MethodDefinition *ETSChecker::CreateAsyncProxy(ir::MethodDefinition *asyncMethod, ir::ClassDefinition *classDef,
                                                   bool createDecl)
{
    ir::ScriptFunction *asyncFunc = asyncMethod->Function();
    if (!asyncFunc->IsExternal()) {
        VarBinder()->AsETSBinder()->GetRecordTable()->Signatures().push_back(asyncFunc->Scope());
    }

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    ir::MethodDefinition *implMethod = CreateAsyncImplMethod(asyncMethod, classDef);
    varbinder::FunctionScope *implFuncScope = implMethod->Function()->Scope();
    for (auto *decl : asyncFunc->Scope()->Decls()) {
        auto res = asyncFunc->Scope()->Bindings().find(decl->Name());
        ASSERT(res != asyncFunc->Scope()->Bindings().end());
        auto *const var = std::get<1>(*res);
        var->SetScope(implFuncScope);
        implFuncScope->Decls().push_back(decl);
        implFuncScope->InsertBinding(decl->Name(), var);
    }
    for (const auto &entry : asyncFunc->Scope()->Bindings()) {
        auto *var = entry.second;
        var->SetScope(implFuncScope);
        implFuncScope->InsertBinding(entry.first, entry.second);
    }
    ReplaceScope(implMethod->Function()->Body(), asyncFunc, implFuncScope);

    ArenaVector<varbinder::Variable *> captured(Allocator()->Adapter());

    bool isStatic = asyncMethod->IsStatic();
    if (createDecl) {
        if (isStatic) {
            CreateLambdaFuncDecl(implMethod, classDef->Scope()->AsClassScope()->StaticMethodScope());
        } else {
            CreateLambdaFuncDecl(implMethod, classDef->Scope()->AsClassScope()->InstanceMethodScope());
        }
        implMethod->Id()->SetVariable(implMethod->Function()->Id()->Variable());
    }
    VarBinder()->AsETSBinder()->BuildProxyMethod(implMethod->Function(), classDef->InternalName(), isStatic,
                                                 asyncFunc->IsExternal());
    implMethod->SetParent(asyncMethod->Parent());

    return implMethod;
}

ir::MethodDefinition *ETSChecker::CreateMethod(const util::StringView &name, ir::ModifierFlags modifiers,
                                               ir::ScriptFunctionFlags flags, ArenaVector<ir::Expression *> &&params,
                                               varbinder::FunctionParamScope *paramScope, ir::TypeNode *returnType,
                                               ir::AstNode *body)
{
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *nameId = AllocNode<ir::Identifier>(name, Allocator());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), paramScope);
    // clang-format off
    auto *const func = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
            body, ir::FunctionSignature(nullptr, std::move(params), returnType), flags, modifiers});
    // clang-format on
    func->SetScope(scope);
    func->SetIdent(nameId);
    if (body != nullptr && body->IsBlockStatement()) {
        body->AsBlockStatement()->SetScope(scope);
    }
    scope->BindNode(func);
    paramScope->BindNode(func);
    scope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(scope);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    auto *nameClone = nameId->Clone(Allocator(), nullptr);
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *method = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, nameClone, funcExpr, modifiers,
                                                   Allocator(), false);
    return method;
}

varbinder::FunctionParamScope *ETSChecker::CopyParams(const ArenaVector<ir::Expression *> &params,
                                                      ArenaVector<ir::Expression *> &outParams)
{
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    for (auto *const it : params) {
        auto *const paramOld = it->AsETSParameterExpression();
        // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
        auto *const paramNew = paramOld->Clone(Allocator(), paramOld->Parent())->AsETSParameterExpression();

        auto *const var = std::get<1>(VarBinder()->AddParamDecl(paramNew));

        if (paramNew->Variable()->HasFlag(varbinder::VariableFlags::BOXED)) {
            var->AddFlag(varbinder::VariableFlags::BOXED);
        }

        var->SetTsType(paramOld->Ident()->Variable()->TsType());
        var->SetScope(paramCtx.GetScope());
        paramNew->SetVariable(var);

        paramNew->SetTsType(MaybeBoxedType(paramOld->Ident()->Variable()));

        outParams.emplace_back(paramNew);
    }

    return paramCtx.GetScope();
}

void ETSChecker::ReplaceScope(ir::AstNode *root, ir::AstNode *oldNode, varbinder::Scope *newScope)
{
    if (root == nullptr) {
        return;
    }

    root->Iterate([this, oldNode, newScope](ir::AstNode *child) {
        auto *scope = NodeScope(child);
        if (scope != nullptr) {
            while (scope->Parent() != nullptr && scope->Parent()->Node() != oldNode) {
                scope = scope->Parent();
            }
            scope->SetParent(newScope);
        } else {
            ReplaceScope(child, oldNode, newScope);
        }
    });
}

void ETSChecker::MoveTrailingBlockToEnclosingBlockStatement(ir::CallExpression *callExpr)
{
    if (callExpr == nullptr) {
        return;
    }

    ir::AstNode *parent = callExpr->Parent();
    ir::AstNode *current = callExpr;
    while (parent != nullptr) {
        if (!parent->IsBlockStatement()) {
            current = parent;
            parent = parent->Parent();
        } else {
            // Collect trailing block, insert it only when block statements traversal ends to avoid order mismatch.
            parent->AsBlockStatement()->AddTrailingBlock(current, callExpr->TrailingBlock());
            callExpr->TrailingBlock()->SetParent(parent);
            callExpr->SetTrailingBlock(nullptr);
            break;
        }
    }
}

void ETSChecker::TransformTraillingLambda(ir::CallExpression *callExpr)
{
    auto *trailingBlock = callExpr->TrailingBlock();
    ASSERT(trailingBlock != nullptr);

    auto *funcParamScope = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder()).GetScope();
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);

    auto funcCtx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *funcScope = funcCtx.GetScope();
    funcScope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(funcScope);
    funcParamScope->SetParent(trailingBlock->Scope()->Parent());

    for (auto [_, var] : trailingBlock->Scope()->Bindings()) {
        (void)_;
        if (var->GetScope() == trailingBlock->Scope()) {
            var->SetScope(funcScope);
            funcScope->InsertBinding(var->Name(), var);
        }
    }

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {trailingBlock,
                                                             ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                             ir::ScriptFunctionFlags::ARROW});
    funcNode->SetScope(funcScope);
    funcScope->BindNode(funcNode);
    funcParamScope->BindNode(funcNode);

    trailingBlock->SetScope(funcScope);
    ReplaceScope(funcNode->Body(), trailingBlock, funcScope);
    callExpr->SetTrailingBlock(nullptr);

    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(Allocator(), funcNode);
    arrowFuncNode->SetRange(trailingBlock->Range());
    arrowFuncNode->SetParent(callExpr);

    callExpr->Arguments().push_back(arrowFuncNode);
}

ArenaVector<ir::Expression *> ETSChecker::ExtendArgumentsWithFakeLamda(ir::CallExpression *callExpr)
{
    auto funcCtx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *funcScope = funcCtx.GetScope();
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    // SUPPRESS_CSA_NEXTLINE(alpha.core.AllocatorETSCheckerHint)
    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(funcScope);

    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                ir::ScriptFunctionFlags::ARROW});
    funcNode->SetScope(funcScope);
    funcScope->BindNode(funcNode);
    auto *arrowFuncNode = AllocNode<ir::ArrowFunctionExpression>(Allocator(), funcNode);
    arrowFuncNode->SetParent(callExpr);

    ArenaVector<ir::Expression *> fakeArguments = callExpr->Arguments();
    fakeArguments.push_back(arrowFuncNode);
    return fakeArguments;
}

void ETSChecker::EnsureValidCurlyBrace(ir::CallExpression *callExpr)
{
    if (callExpr->TrailingBlock() == nullptr) {
        return;
    }

    if (callExpr->IsTrailingBlockInNewLine()) {
        MoveTrailingBlockToEnclosingBlockStatement(callExpr);
        return;
    }

    ThrowTypeError({"No matching call signature with trailing lambda"}, callExpr->Start());
}

ETSObjectType *ETSChecker::GetCachedFunctionlInterface(ir::ETSFunctionType *type)
{
    auto hash = GetHashFromFunctionType(type);
    auto it = functionalInterfaceCache_.find(hash);
    if (it == functionalInterfaceCache_.cend()) {
        return nullptr;
    }
    return it->second;
}

void ETSChecker::CacheFunctionalInterface(ir::ETSFunctionType *type, ETSObjectType *ifaceType)
{
    auto hash = GetHashFromFunctionType(type);
    ASSERT(functionalInterfaceCache_.find(hash) == functionalInterfaceCache_.cend());
    functionalInterfaceCache_.emplace(hash, ifaceType);
}

}  // namespace ark::es2panda::checker
