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

#include "varbinder/varbinder.h"
#include "varbinder/declaration.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/scope.h"
#include "varbinder/variable.h"
#include "varbinder/variableFlags.h"
#include "checker/ETSchecker.h"
#include "checker/ets/function_helpers.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/types/ets/etsAsyncFuncReturnType.h"
#include "checker/types/ets/etsObjectType.h"
#include "checker/types/type.h"
#include "checker/types/typeFlag.h"
#include "ir/astNode.h"
#include "ir/typeNode.h"
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
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "parser/program/program.h"
#include "util/helpers.h"
#include "util/language.h"

namespace panda::es2panda::checker {

bool ETSChecker::IsCompatibleTypeArgument(Type *type_param, Type *type_argument, const Substitution *substitution)
{
    ASSERT(type_param->IsETSObjectType() &&
           type_param->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::TYPE_PARAMETER));
    if (type_argument->IsWildcardType()) {
        return true;
    }
    if (!type_argument->IsETSObjectType() && !type_argument->IsETSArrayType() && !type_argument->IsETSFunctionType()) {
        return false;
    }
    auto *type_param_obj = type_param->AsETSObjectType();
    auto *type_param_obj_supertype = type_param_obj->SuperType();
    if (type_param_obj_supertype != nullptr) {
        if (!type_param_obj_supertype->TypeArguments().empty()) {
            type_param_obj_supertype =
                type_param_obj_supertype->Substitute(this->Relation(), substitution)->AsETSObjectType();
        }
        type_param_obj_supertype->IsSupertypeOf(Relation(), type_argument);
        if (!Relation()->IsTrue()) {
            return false;
        }
    }
    for (auto *itf : type_param_obj->Interfaces()) {
        if (!itf->TypeArguments().empty()) {
            itf = itf->Substitute(this->Relation(), substitution)->AsETSObjectType();
        }
        itf->IsSupertypeOf(Relation(), type_argument);
        if (!Relation()->IsTrue()) {
            return false;
        }
    }

    return true;
}

/* A very rough and imprecise partial type inference */
void ETSChecker::EnhanceSubstitutionForType(const ArenaVector<Type *> &type_params, Type *param_type,
                                            Type *argument_type, Substitution *substitution,
                                            ArenaUnorderedSet<ETSObjectType *> *instantiated_type_params)
{
    if (!param_type->IsETSObjectType()) {
        return;
    }
    auto *param_obj_type = param_type->AsETSObjectType();
    if (param_obj_type->HasObjectFlag(ETSObjectFlags::TYPE_PARAMETER)) {
        auto *param_base = GetOriginalBaseType(param_obj_type);
        if (instantiated_type_params->find(param_obj_type) != instantiated_type_params->end() &&
            substitution->at(param_base) != argument_type) {
            ThrowTypeError({"Type parameter already instantiated with another type "},
                           param_obj_type->GetDeclNode()->Start());
        }
        if (std::find(type_params.begin(), type_params.end(), param_base) != type_params.end() &&
            substitution->count(param_base) == 0) {
            substitution->emplace(param_base, argument_type);
            instantiated_type_params->insert(param_obj_type);
            return;
        }
    }
    if (argument_type->IsETSObjectType()) {
        auto *arg_obj_type = argument_type->AsETSObjectType();
        if (GetOriginalBaseType(arg_obj_type) != GetOriginalBaseType(param_obj_type)) {
            return;  // don't attempt anything fancy for now
        }
        ASSERT(arg_obj_type->TypeArguments().size() == param_obj_type->TypeArguments().size());
        for (size_t ix = 0; ix < arg_obj_type->TypeArguments().size(); ix++) {
            EnhanceSubstitutionForType(type_params, param_obj_type->TypeArguments()[ix],
                                       arg_obj_type->TypeArguments()[ix], substitution, instantiated_type_params);
        }
    } else if (argument_type->IsETSFunctionType() &&
               param_obj_type->HasObjectFlag(ETSObjectFlags::FUNCTIONAL_INTERFACE)) {
        auto parameter_signatures = param_obj_type->GetOwnProperty<checker::PropertyType::INSTANCE_METHOD>("invoke")
                                        ->TsType()
                                        ->AsETSFunctionType()
                                        ->CallSignatures();
        auto argument_signatures = argument_type->AsETSFunctionType()->CallSignatures();
        ASSERT(argument_signatures.size() == 1);
        ASSERT(parameter_signatures.size() == 1);
        for (size_t idx = 0; idx < argument_signatures[0]->GetSignatureInfo()->params.size(); idx++) {
            EnhanceSubstitutionForType(type_params, parameter_signatures[0]->GetSignatureInfo()->params[idx]->TsType(),
                                       argument_signatures[0]->GetSignatureInfo()->params[idx]->TsType(), substitution,
                                       instantiated_type_params);
        }
        EnhanceSubstitutionForType(type_params, parameter_signatures[0]->ReturnType(),
                                   argument_signatures[0]->ReturnType(), substitution, instantiated_type_params);
    } else {
        return;
    }
}

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const INVALID_CALL_ARGUMENT_1[] = "Call argument at index ";
static constexpr char const INVALID_CALL_ARGUMENT_2[] = " is not compatible with the signature's type at that index.";
static constexpr char const INVALID_CALL_ARGUMENT_3[] = " is not compatible with the signature's rest parameter type.";
// NOLINTEND(modernize-avoid-c-arrays)

Signature *ETSChecker::ValidateSignature(Signature *signature, const ir::TSTypeParameterInstantiation *type_arguments,
                                         const ArenaVector<ir::Expression *> &arguments,
                                         const lexer::SourcePosition &pos, TypeRelationFlag flags,
                                         const std::vector<bool> &arg_type_inference_required)
{
    if (signature->Function()->IsDefaultParamProxy() && ((flags & TypeRelationFlag::CHECK_PROXY) == 0)) {
        return nullptr;
    }

    Signature *substituted_sig = MaybeSubstituteTypeParameters(this, signature, type_arguments, arguments, pos, flags);
    if (substituted_sig == nullptr) {
        return nullptr;
    }

    auto const has_rest_parameter = substituted_sig->RestVar() != nullptr;
    std::size_t const argument_count = arguments.size();
    std::size_t const parameter_count = substituted_sig->MinArgCount();
    auto const throw_error = (flags & TypeRelationFlag::NO_THROW) == 0;

    if (!signature->Function()->IsDefaultParamProxy()) {
        if (argument_count < parameter_count || (argument_count > parameter_count && !has_rest_parameter)) {
            if (throw_error) {
                ThrowTypeError({"Expected ", parameter_count, " arguments, got ", argument_count, "."}, pos);
            }
            return nullptr;
        }
    }

    if (substituted_sig->IsBaseReturnDiff() && substituted_sig->ReturnType()->IsETSArrayType()) {
        CreateBuiltinArraySignature(substituted_sig->ReturnType()->AsETSArrayType(),
                                    substituted_sig->ReturnType()->AsETSArrayType()->Rank());
    }

    // Check all required formal parameter(s) first
    auto const count = std::min(parameter_count, argument_count);
    std::size_t index = 0U;
    for (; index < count; ++index) {
        auto &argument = arguments[index];

        if (argument->IsObjectExpression()) {
            if (substituted_sig->Params()[index]->TsType()->IsETSObjectType()) {
                // No chance to check the argument at this point
                continue;
            }
            return nullptr;
        }

        if (argument->IsMemberExpression()) {
            SetArrayPreferredTypeForNestedMemberExpressions(arguments[index]->AsMemberExpression(),
                                                            substituted_sig->Params()[index]->TsType());
        } else if (argument->IsSpreadElement()) {
            if (throw_error) {
                ThrowTypeError("Spread argument cannot be passed for ordinary parameter.", argument->Start());
            }
            return nullptr;
        }

        if (arg_type_inference_required[index]) {
            ASSERT(argument->IsArrowFunctionExpression());
            auto *const arrow_func_expr = argument->AsArrowFunctionExpression();
            ir::ScriptFunction *const lambda = arrow_func_expr->Function();
            if (CheckLambdaAssignable(substituted_sig->Function()->Params()[index], lambda)) {
                continue;
            }
            return nullptr;
        }

        auto *const argument_type = argument->Check(this);

        if (auto const invocation_ctx = checker::InvocationContext(
                Relation(), argument, argument_type, substituted_sig->Params()[index]->TsType(), argument->Start(),
                {INVALID_CALL_ARGUMENT_1, index, INVALID_CALL_ARGUMENT_2}, flags);
            !invocation_ctx.IsInvocable()) {
            return nullptr;
        }
    }

    // Check rest parameter(s) if any exists
    if (has_rest_parameter && index < argument_count) {
        auto const rest_count = argument_count - index;

        for (; index < argument_count; ++index) {
            auto &argument = arguments[index];

            if (argument->IsSpreadElement()) {
                if (rest_count > 1U) {
                    if (throw_error) {
                        ThrowTypeError("Spread argument for the rest parameter can be only one.", argument->Start());
                    }
                    return nullptr;
                }

                auto *const rest_argument = argument->AsSpreadElement()->Argument();
                auto *const argument_type = rest_argument->Check(this);

                if (auto const invocation_ctx = checker::InvocationContext(
                        Relation(), rest_argument, argument_type, substituted_sig->RestVar()->TsType(),
                        argument->Start(), {INVALID_CALL_ARGUMENT_1, index, INVALID_CALL_ARGUMENT_3}, flags);
                    !invocation_ctx.IsInvocable()) {
                    return nullptr;
                }
            } else {
                auto *const argument_type = argument->Check(this);

                if (auto const invocation_ctx = checker::InvocationContext(
                        Relation(), argument, argument_type,
                        substituted_sig->RestVar()->TsType()->AsETSArrayType()->ElementType(), argument->Start(),
                        {INVALID_CALL_ARGUMENT_1, index, INVALID_CALL_ARGUMENT_3}, flags);
                    !invocation_ctx.IsInvocable()) {
                    return nullptr;
                }
            }
        }
    }

    return substituted_sig;
}

bool ETSChecker::ValidateProxySignature(Signature *const signature,
                                        const ir::TSTypeParameterInstantiation *type_arguments,
                                        const ArenaVector<ir::Expression *> &arguments,
                                        const std::vector<bool> &arg_type_inference_required)
{
    if (!signature->Function()->IsDefaultParamProxy()) {
        return false;
    }

    auto const *const proxy_param = signature->Function()->Params().back()->AsETSParameterExpression();
    if (!proxy_param->Ident()->Name().Is(ir::PROXY_PARAMETER_NAME)) {
        return false;
    }

    if (arguments.size() < proxy_param->GetRequiredParams()) {
        return false;
    }

    return ValidateSignature(signature, type_arguments, arguments, signature->Function()->Start(),
                             TypeRelationFlag::CHECK_PROXY | TypeRelationFlag::NO_THROW |
                                 TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_BOXING,
                             arg_type_inference_required) != nullptr;
}

std::pair<ArenaVector<Signature *>, ArenaVector<Signature *>> ETSChecker::CollectSignatures(
    ArenaVector<Signature *> &signatures, const ir::TSTypeParameterInstantiation *type_arguments,
    const ArenaVector<ir::Expression *> &arguments, std::vector<bool> &arg_type_inference_required,
    const lexer::SourcePosition &pos, TypeRelationFlag resolve_flags)
{
    ArenaVector<Signature *> compatible_signatures(Allocator()->Adapter());
    ArenaVector<Signature *> proxy_signatures(Allocator()->Adapter());

    for (auto *sig : signatures) {
        if (sig->Function()->IsDefaultParamProxy() &&
            ValidateProxySignature(sig, type_arguments, arguments, arg_type_inference_required)) {
            proxy_signatures.push_back(sig);
        }
    }

    auto collect_signatures = [&](TypeRelationFlag relation_flags) {
        for (auto *sig : signatures) {
            if (!sig->Function()->IsDefaultParamProxy()) {
                if (auto *concrete_sig = ValidateSignature(sig, type_arguments, arguments, pos, relation_flags,
                                                           arg_type_inference_required);
                    concrete_sig != nullptr) {
                    compatible_signatures.push_back(concrete_sig);
                }
            }
        }
    };

    // If there's only one signature, we don't need special checks for boxing/unboxing/widening.
    // We are also able to provide more specific error messages.
    if (signatures.size() == 1) {
        TypeRelationFlag flags = TypeRelationFlag::WIDENING | resolve_flags;
        collect_signatures(flags);
    } else {
        std::array<TypeRelationFlag, 4U> flag_variants {TypeRelationFlag::NO_THROW | TypeRelationFlag::NO_UNBOXING |
                                                            TypeRelationFlag::NO_BOXING,
                                                        TypeRelationFlag::NO_THROW,
                                                        TypeRelationFlag::NO_THROW | TypeRelationFlag::WIDENING |
                                                            TypeRelationFlag::NO_UNBOXING | TypeRelationFlag::NO_BOXING,
                                                        TypeRelationFlag::NO_THROW | TypeRelationFlag::WIDENING};
        for (auto flags : flag_variants) {
            flags = flags | resolve_flags;
            collect_signatures(flags);
            if (!compatible_signatures.empty()) {
                break;
            }
        }
    }
    return std::make_pair(compatible_signatures, proxy_signatures);
}

Signature *ETSChecker::GetMostSpecificSignature(ArenaVector<Signature *> &compatible_signatures,
                                                ArenaVector<Signature *> &proxy_signatures,
                                                const ArenaVector<ir::Expression *> &arguments,
                                                std::vector<bool> &arg_type_inference_required,
                                                const lexer::SourcePosition &pos, TypeRelationFlag resolve_flags)
{
    Signature *most_specific_signature =
        ChooseMostSpecificSignature(compatible_signatures, arg_type_inference_required, pos);

    if (most_specific_signature == nullptr) {
        ThrowTypeError({"Reference to ", compatible_signatures.front()->Function()->Id()->Name(), " is ambiguous"},
                       pos);
    }

    if (!TypeInference(most_specific_signature, arguments, resolve_flags)) {
        return nullptr;
    }

    // Just to avoid extra nesting level
    auto const check_ambiguous = [this, most_specific_signature, &pos](Signature const *const proxy_signature) -> void {
        auto const *const proxy_param = proxy_signature->Function()->Params().back()->AsETSParameterExpression();
        if (!proxy_param->Ident()->Name().Is(ir::PROXY_PARAMETER_NAME)) {
            ThrowTypeError({"Proxy parameter '", proxy_param->Ident()->Name(), "' has invalid name."}, pos);
        }

        if (most_specific_signature->Params().size() == proxy_param->GetRequiredParams()) {
            ThrowTypeError({"Reference to ", most_specific_signature->Function()->Id()->Name(), " is ambiguous"}, pos);
        }
    };

    if (!proxy_signatures.empty()) {
        auto *const proxy_signature =
            ChooseMostSpecificProxySignature(proxy_signatures, arg_type_inference_required, pos, arguments.size());
        if (proxy_signature != nullptr) {
            check_ambiguous(proxy_signature);
        }
    }

    return most_specific_signature;
}

Signature *ETSChecker::ValidateSignatures(ArenaVector<Signature *> &signatures,
                                          const ir::TSTypeParameterInstantiation *type_arguments,
                                          const ArenaVector<ir::Expression *> &arguments,
                                          const lexer::SourcePosition &pos, std::string_view signature_kind,
                                          TypeRelationFlag resolve_flags)
{
    std::vector<bool> arg_type_inference_required = FindTypeInferenceArguments(arguments);
    auto [compatible_signatures, proxy_signatures] =
        CollectSignatures(signatures, type_arguments, arguments, arg_type_inference_required, pos, resolve_flags);

    if (!compatible_signatures.empty()) {
        return GetMostSpecificSignature(compatible_signatures, proxy_signatures, arguments, arg_type_inference_required,
                                        pos, resolve_flags);
    }

    if (!proxy_signatures.empty()) {
        auto *const proxy_signature =
            ChooseMostSpecificProxySignature(proxy_signatures, arg_type_inference_required, pos, arguments.size());
        if (proxy_signature != nullptr) {
            return proxy_signature;
        }
    }

    if ((resolve_flags & TypeRelationFlag::NO_THROW) == 0) {
        ThrowTypeError({"No matching ", signature_kind, " signature"}, pos);
    }

    return nullptr;
}

Signature *ETSChecker::ChooseMostSpecificSignature(ArenaVector<Signature *> &signatures,
                                                   const std::vector<bool> &arg_type_inference_required,
                                                   const lexer::SourcePosition &pos, size_t arguments_size)
{
    ASSERT(signatures.empty() == false);

    if (signatures.size() == 1) {
        return signatures.front();
    }

    size_t param_count = signatures.front()->Params().size();
    if (arguments_size != ULONG_MAX) {
        param_count = arguments_size;
    }
    // Multiple signatures with zero parameter because of inheritance.
    // Return the closest one in inheritance chain that is defined at the beginning of the vector.
    if (param_count == 0) {
        return signatures.front();
    }

    // Collect which signatures are most specific for each parameter.
    ArenaMultiMap<size_t /* parameter index */, Signature *> best_signatures_for_parameter(Allocator()->Adapter());

    const checker::SavedTypeRelationFlagsContext saved_type_relation_flag_ctx(Relation(),
                                                                              TypeRelationFlag::ONLY_CHECK_WIDENING);

    for (size_t i = 0; i < param_count; ++i) {
        if (arg_type_inference_required[i]) {
            for (auto *sig : signatures) {
                best_signatures_for_parameter.insert({i, sig});
            }
            continue;
        }
        // 1st step: check which is the most specific parameter type for i. parameter.
        Type *most_specific_type = signatures.front()->Params().at(i)->TsType();
        Signature *prev_sig = signatures.front();

        auto init_most_specific_type = [&most_specific_type, &prev_sig, i](Signature *sig) {
            if (Type *sig_type = sig->Params().at(i)->TsType();
                sig_type->IsETSObjectType() && !sig_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
                most_specific_type = sig_type;
                prev_sig = sig;
                return true;
            }
            return false;
        };

        auto evaluate_result = [this, &most_specific_type, &prev_sig, pos](Signature *sig, Type *sig_type) {
            if (Relation()->IsAssignableTo(sig_type, most_specific_type)) {
                most_specific_type = sig_type;
                prev_sig = sig;
            } else if (sig_type->IsETSObjectType() && most_specific_type->IsETSObjectType() &&
                       !Relation()->IsAssignableTo(most_specific_type, sig_type)) {
                auto func_name = sig->Function()->Id()->Name();
                ThrowTypeError({"Call to `", func_name, "` is ambiguous as `2` versions of `", func_name,
                                "` are available: `", func_name, prev_sig, "` and `", func_name, sig, "`"},
                               pos);
            }
        };

        auto search_among_types = [this, &most_specific_type, arguments_size, param_count, i,
                                   &evaluate_result](Signature *sig, const bool look_for_class_type) {
            if (look_for_class_type && arguments_size == ULONG_MAX) {
                [[maybe_unused]] const bool equal_param_size = sig->Params().size() == param_count;
                ASSERT(equal_param_size);
            }
            Type *sig_type = sig->Params().at(i)->TsType();
            const bool is_class_type =
                sig_type->IsETSObjectType() && !sig_type->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::INTERFACE);
            if (is_class_type == look_for_class_type) {
                if (Relation()->IsIdenticalTo(sig_type, most_specific_type)) {
                    return;
                }
                evaluate_result(sig, sig_type);
            }
        };

        std::any_of(signatures.begin(), signatures.end(), init_most_specific_type);
        std::for_each(signatures.begin(), signatures.end(),
                      [&search_among_types](Signature *sig) mutable { search_among_types(sig, true); });
        std::for_each(signatures.begin(), signatures.end(),
                      [&search_among_types](Signature *sig) mutable { search_among_types(sig, false); });

        for (auto *sig : signatures) {
            Type *sig_type = sig->Params().at(i)->TsType();
            if (Relation()->IsIdenticalTo(sig_type, most_specific_type)) {
                best_signatures_for_parameter.insert({i, sig});
            }
        }
    }

    // Find the signature that are most specific for all parameters.
    Signature *most_specific_signature = nullptr;

    for (auto *sig : signatures) {
        bool most_specific = true;

        for (size_t param_idx = 0; param_idx < param_count; ++param_idx) {
            const auto range = best_signatures_for_parameter.equal_range(param_idx);
            // Check if signature is most specific for i. parameter type.
            const bool has_signature =
                std::any_of(range.first, range.second, [&sig](auto entry) { return entry.second == sig; });

            if (!has_signature) {
                most_specific = false;
                break;
            }
        }

        if (!most_specific) {
            continue;
        }
        if (most_specific_signature == nullptr) {
            most_specific_signature = sig;
            continue;
        }
        if (most_specific_signature->Owner() == sig->Owner()) {
            // NOTE: audovichenko. Remove this 'if' when #12443 gets resolved
            if (most_specific_signature->Function() == sig->Function()) {
                // The same signature
                continue;
            }
            return nullptr;
        }
    }

    return most_specific_signature;
}

Signature *ETSChecker::ChooseMostSpecificProxySignature(ArenaVector<Signature *> &signatures,
                                                        const std::vector<bool> &arg_type_inference_required,
                                                        const lexer::SourcePosition &pos, size_t arguments_size)
{
    if (pos.index == 0 && pos.line == 0) {
        return nullptr;
    }

    const auto most_specific_signature =
        ChooseMostSpecificSignature(signatures, arg_type_inference_required, pos, arguments_size);

    if (most_specific_signature == nullptr) {
        const auto str = signatures.front()->Function()->Id()->Name().Mutf8().substr(
            0, signatures.front()->Function()->Id()->Name().Length() - 6);
        ThrowTypeError("Reference to " + str + " is ambiguous", pos);
    }

    return most_specific_signature;
}

Signature *ETSChecker::ResolveCallExpression(ArenaVector<Signature *> &signatures,
                                             const ir::TSTypeParameterInstantiation *type_arguments,
                                             const ArenaVector<ir::Expression *> &arguments,
                                             const lexer::SourcePosition &pos)
{
    auto sig = ValidateSignatures(signatures, type_arguments, arguments, pos, "call");
    ASSERT(sig);
    return sig;
}

Signature *ETSChecker::ResolveCallExpressionAndTrailingLambda(ArenaVector<Signature *> &signatures,
                                                              ir::CallExpression *call_expr,
                                                              const lexer::SourcePosition &pos,
                                                              const TypeRelationFlag throw_flag)
{
    Signature *sig = nullptr;

    if (call_expr->TrailingBlock() == nullptr) {
        sig = ValidateSignatures(signatures, call_expr->TypeParams(), call_expr->Arguments(), pos, "call", throw_flag);
        return sig;
    }

    auto arguments = ExtendArgumentsWithFakeLamda(call_expr);
    sig = ValidateSignatures(signatures, call_expr->TypeParams(), arguments, pos, "call",
                             TypeRelationFlag::NO_THROW | TypeRelationFlag::NO_CHECK_TRAILING_LAMBDA);
    if (sig != nullptr) {
        TransformTraillingLambda(call_expr);
        TypeInference(sig, call_expr->Arguments());
        return sig;
    }

    sig = ValidateSignatures(signatures, call_expr->TypeParams(), call_expr->Arguments(), pos, "call", throw_flag);
    if (sig != nullptr) {
        EnsureValidCurlyBrace(call_expr);
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

    bool is_construct_sig = method->IsConstructor();

    auto *func_type = BuildFunctionSignature(method->Function(), is_construct_sig);

    std::vector<checker::ETSFunctionType *> overloads;
    for (ir::MethodDefinition *const current_func : method->Overloads()) {
        auto *const overload_type = BuildFunctionSignature(current_func->Function(), is_construct_sig);
        CheckIdenticalOverloads(func_type, overload_type, current_func);
        current_func->SetTsType(overload_type);
        func_type->AddCallSignature(current_func->Function()->Signature());
        overloads.push_back(overload_type);
    }
    for (size_t base_func_counter = 0; base_func_counter < overloads.size(); ++base_func_counter) {
        auto *overload_type = overloads.at(base_func_counter);
        for (size_t compare_func_counter = base_func_counter + 1; compare_func_counter < overloads.size();
             compare_func_counter++) {
            auto *compare_overload_type = overloads.at(compare_func_counter);
            CheckIdenticalOverloads(overload_type, compare_overload_type, method->Overloads()[compare_func_counter]);
        }
    }

    method->Id()->Variable()->SetTsType(func_type);
    return func_type;
}

void ETSChecker::CheckIdenticalOverloads(ETSFunctionType *func, ETSFunctionType *overload,
                                         const ir::MethodDefinition *const current_func)
{
    SavedTypeRelationFlagsContext saved_flags_ctx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);

    if (current_func->Function()->IsDefaultParamProxy()) {
        return;
    }

    Relation()->IsIdenticalTo(func, overload);
    if (Relation()->IsTrue()) {
        ThrowTypeError("Function already declared.", current_func->Start());
    }
    if (HasSameAssemblySignature(func, overload)) {
        ThrowTypeError("Function with this assembly signature already declared.", current_func->Start());
    }
}

Signature *ETSChecker::ComposeSignature(ir::ScriptFunction *func, SignatureInfo *signature_info, Type *return_type,
                                        varbinder::Variable *name_var)
{
    auto *signature = CreateSignature(signature_info, return_type, func);
    signature->SetOwner(Context().ContainingClass());
    signature->SetOwnerVar(name_var);

    const auto *return_type_annotation = func->ReturnTypeAnnotation();
    if (return_type_annotation == nullptr && ((func->Flags() & ir::ScriptFunctionFlags::HAS_RETURN) != 0)) {
        signature->AddSignatureFlag(SignatureFlags::NEED_RETURN_TYPE);
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

Type *ETSChecker::ComposeReturnType(ir::ScriptFunction *func, util::StringView func_name, bool is_construct_sig)
{
    auto *const return_type_annotation = func->ReturnTypeAnnotation();
    checker::Type *return_type {};

    if (return_type_annotation == nullptr) {
        // implicit void return type
        return_type = is_construct_sig || func->IsEntryPoint() || func_name.Is(compiler::Signatures::CCTOR)
                          ? GlobalVoidType()
                          : GlobalBuiltinVoidType();

        if (return_type == nullptr) {
            const auto var_map = VarBinder()->TopScope()->Bindings();

            const auto builtin_void = var_map.find(compiler::Signatures::BUILTIN_VOID_CLASS);
            ASSERT(builtin_void != var_map.end());

            BuildClassProperties(builtin_void->second->Declaration()->Node()->AsClassDefinition());

            ASSERT(GlobalBuiltinVoidType() != nullptr);
            return_type = GlobalBuiltinVoidType();
        }

        if (func->IsAsyncFunc()) {
            auto implicit_promise_void = [this]() {
                const auto &promise_global = GlobalBuiltinPromiseType()->AsETSObjectType();
                auto promise_type =
                    promise_global->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsETSObjectType();
                promise_type->AddTypeFlag(checker::TypeFlag::GENERIC);
                promise_type->TypeArguments().clear();
                promise_type->TypeArguments().emplace_back(GlobalBuiltinVoidType());
                return promise_type;
            };

            return_type = implicit_promise_void();
        }
    } else if (func->IsEntryPoint() && return_type_annotation->GetType(this) == GlobalBuiltinVoidType()) {
        return_type = GlobalVoidType();
    } else {
        return_type = GetTypeFromTypeAnnotation(return_type_annotation);
        return_type_annotation->SetTsType(return_type);
    }

    return return_type;
}

SignatureInfo *ETSChecker::ComposeSignatureInfo(ir::ScriptFunction *func)
{
    auto *signature_info = CreateSignatureInfo();
    signature_info->rest_var = nullptr;
    signature_info->min_arg_count = 0;

    if ((func->IsConstructor() || !func->IsStatic()) && !func->IsArrow()) {
        auto *this_var = func->Scope()->ParamScope()->Params().front();
        this_var->SetTsType(Context().ContainingClass());
    }

    if (func->TypeParams() != nullptr) {
        signature_info->type_params = CreateTypeForTypeParameters(func->TypeParams());
    }

    for (auto *const it : func->Params()) {
        auto *const param = it->AsETSParameterExpression();

        if (param->IsRestParameter()) {
            auto const *const rest_ident = param->Ident();

            ASSERT(rest_ident->Variable());
            signature_info->rest_var = rest_ident->Variable()->AsLocalVariable();

            auto *const rest_param_type_annotation = param->TypeAnnotation();
            ASSERT(rest_param_type_annotation);

            signature_info->rest_var->SetTsType(GetTypeFromTypeAnnotation(rest_param_type_annotation));
            auto array_type = signature_info->rest_var->TsType()->AsETSArrayType();
            CreateBuiltinArraySignature(array_type, array_type->Rank());
        } else {
            auto const *const param_ident = param->Ident();

            varbinder::Variable *const param_var = param_ident->Variable();
            ASSERT(param_var);

            auto *const param_type_annotation = param->TypeAnnotation();
            ASSERT(param_type_annotation);

            param_var->SetTsType(GetTypeFromTypeAnnotation(param_type_annotation));
            signature_info->params.push_back(param_var->AsLocalVariable());
            ++signature_info->min_arg_count;
        }
    }

    return signature_info;
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

        const auto param_type = param->Variable()->TsType();
        if (!param_type->IsETSArrayType() || !param_type->AsETSArrayType()->ElementType()->IsETSStringType()) {
            ThrowTypeError("Only 'string[]' type argument is allowed.", param->Start());
        }
    }
}

checker::ETSFunctionType *ETSChecker::BuildFunctionSignature(ir::ScriptFunction *func, bool is_construct_sig)
{
    bool is_arrow = func->IsArrow();
    auto *name_var = is_arrow ? nullptr : func->Id()->Variable();
    auto func_name = name_var == nullptr ? util::StringView() : name_var->Name();

    auto *signature_info = ComposeSignatureInfo(func);

    if (func_name.Is(compiler::Signatures::MAIN) &&
        func->Scope()->Name().Utf8().find(compiler::Signatures::ETS_GLOBAL) != std::string::npos) {
        func->AddFlag(ir::ScriptFunctionFlags::ENTRY_POINT);
    }
    if (func->IsEntryPoint()) {
        ValidateMainSignature(func);
    }

    auto *return_type = ComposeReturnType(func, func_name, is_construct_sig);
    auto *signature = ComposeSignature(func, signature_info, return_type, name_var);
    if (is_construct_sig) {
        signature->AddSignatureFlag(SignatureFlags::CONSTRUCT);
    } else {
        signature->AddSignatureFlag(SignatureFlags::CALL);
    }

    auto *func_type = CreateETSFunctionType(func, signature, func_name);
    func->SetSignature(signature);
    func_type->SetVariable(name_var);
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

    if (!is_arrow) {
        name_var->SetTsType(func_type);
    }

    return func_type;
}

Signature *ETSChecker::CheckEveryAbstractSignatureIsOverridden(ETSFunctionType *target, ETSFunctionType *source)
{
    for (auto target_sig = target->CallSignatures().begin(); target_sig != target->CallSignatures().end();) {
        if (!(*target_sig)->HasSignatureFlag(SignatureFlags::ABSTRACT)) {
            continue;
        }

        bool is_overridden = false;
        for (auto source_sig : source->CallSignatures()) {
            Relation()->IsIdenticalTo(*target_sig, source_sig);
            if (Relation()->IsTrue() &&
                (*target_sig)->Function()->Id()->Name() == source_sig->Function()->Id()->Name()) {
                target->CallSignatures().erase(target_sig);
                is_overridden = true;
                break;
            }
            source_sig++;
        }

        if (!is_overridden) {
            return *target_sig;
        }
    }

    return nullptr;
}

bool ETSChecker::IsOverridableIn(Signature *signature)
{
    if (signature->HasSignatureFlag(SignatureFlags::PRIVATE)) {
        return false;
    }

    if (signature->HasSignatureFlag(SignatureFlags::PUBLIC)) {
        return FindAncestorGivenByType(signature->Function(), ir::AstNodeType::TS_INTERFACE_DECLARATION) == nullptr ||
               signature->HasSignatureFlag(SignatureFlags::STATIC);
    }

    return signature->HasSignatureFlag(SignatureFlags::PROTECTED);
}

bool ETSChecker::IsMethodOverridesOther(Signature *target, Signature *source)
{
    if (source->Function()->IsConstructor()) {
        return false;
    }

    if (target == source) {
        return true;
    }

    if (IsOverridableIn(target)) {
        SavedTypeRelationFlagsContext saved_flags_ctx(Relation(), TypeRelationFlag::NO_RETURN_TYPE_CHECK);
        Relation()->IsIdenticalTo(target, source);
        if (Relation()->IsTrue()) {
            CheckThrowMarkers(source, target);

            CheckStaticHide(target, source);
            if (source->HasSignatureFlag(SignatureFlags::STATIC)) {
                return false;
            }

            if (!source->Function()->IsOverride()) {
                ThrowTypeError("Method overriding requires 'override' modifier", source->Function()->Start());
            }
            return true;
        }
    }

    return false;
}

void ETSChecker::CheckStaticHide(Signature *target, Signature *source)
{
    if (!target->HasSignatureFlag(SignatureFlags::STATIC) && source->HasSignatureFlag(SignatureFlags::STATIC)) {
        ThrowTypeError("A static method hides an instance method.", source->Function()->Body()->Start());
    }

    if ((target->HasSignatureFlag(SignatureFlags::STATIC) ||
         (source->HasSignatureFlag(SignatureFlags::STATIC) || !source->Function()->IsOverride())) &&
        !IsReturnTypeSubstitutable(target, source)) {
        ThrowTypeError("Hiding method is not return-type-substitutable for other method.", source->Function()->Start());
    }
}

void ETSChecker::CheckThrowMarkers(Signature *source, Signature *target)
{
    ir::ScriptFunctionFlags throw_markers = ir::ScriptFunctionFlags::THROWS | ir::ScriptFunctionFlags::RETHROWS;
    auto source_throw_markers = source->Function()->Flags() & throw_markers;
    auto target_throw_markers = target->Function()->Flags() & throw_markers;

    if (source_throw_markers != target_throw_markers) {
        ThrowTypeError(
            "A method that overrides or hides another method cannot change throw or rethrow clauses of the "
            "overridden "
            "or hidden method.",
            target->Function()->Body()->Start());
    }
}

std::tuple<bool, OverrideErrorCode> ETSChecker::CheckOverride(Signature *signature, Signature *other)
{
    if (other->HasSignatureFlag(SignatureFlags::STATIC)) {
        if (signature->Function()->IsOverride()) {
            return {false, OverrideErrorCode::OVERRIDDEN_STATIC};
        }

        ASSERT(signature->HasSignatureFlag(SignatureFlags::STATIC));
        return {true, OverrideErrorCode::NO_ERROR};
    }

    if (other->IsFinal()) {
        return {false, OverrideErrorCode::OVERRIDDEN_FINAL};
    }

    if (!IsReturnTypeSubstitutable(signature, other)) {
        return {false, OverrideErrorCode::INCOMPATIBLE_RETURN};
    }

    if (signature->ProtectionFlag() > other->ProtectionFlag()) {
        return {false, OverrideErrorCode::OVERRIDDEN_WEAKER};
    }

    return {true, OverrideErrorCode::NO_ERROR};
}

Signature *ETSChecker::AdjustForTypeParameters(Signature *source, Signature *target)
{
    auto &source_type_params = source->GetSignatureInfo()->type_params;
    auto &target_type_params = target->GetSignatureInfo()->type_params;
    if (source_type_params.size() != target_type_params.size()) {
        return nullptr;
    }
    if (source_type_params.empty()) {
        return target;
    }
    auto *substitution = NewSubstitution();
    for (size_t ix = 0; ix < source_type_params.size(); ix++) {
        substitution->emplace(target_type_params[ix], source_type_params[ix]);
    }
    return target->Substitute(Relation(), substitution);
}

bool ETSChecker::CheckOverride(Signature *signature, ETSObjectType *site)
{
    auto *target = site->GetProperty(signature->Function()->Id()->Name(), PropertySearchFlags::SEARCH_METHOD);
    bool is_overriding_any_signature = false;

    if (target == nullptr) {
        return is_overriding_any_signature;
    }

    for (auto *it : target->TsType()->AsETSFunctionType()->CallSignatures()) {
        auto *it_subst = AdjustForTypeParameters(signature, it);

        if (signature->Owner()->HasObjectFlag(ETSObjectFlags::INTERFACE) &&
            Relation()->IsIdenticalTo(it_subst->Owner(), GlobalETSObjectType()) &&
            !it_subst->HasSignatureFlag(SignatureFlags::PRIVATE)) {
            ThrowTypeError("Cannot override non-private method of the class Object from an interface.",
                           signature->Function()->Start());
        }

        if (it_subst == nullptr) {
            continue;
        }

        if (it_subst->HasSignatureFlag(SignatureFlags::ABSTRACT) || site->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
            if (site->HasObjectFlag(ETSObjectFlags::INTERFACE)) {
                CheckThrowMarkers(it_subst, signature);
            }
            if ((it_subst->Function()->IsSetter() && !signature->Function()->IsSetter()) ||
                (it_subst->Function()->IsGetter() && !signature->Function()->IsGetter())) {
                continue;
            }
        } else if (!IsMethodOverridesOther(it_subst, signature)) {
            continue;
        }

        auto [success, errorCode] = CheckOverride(signature, it_subst);

        if (!success) {
            const char *reason {};
            switch (errorCode) {
                case OverrideErrorCode::OVERRIDDEN_STATIC: {
                    reason = "overridden method is static.";
                    break;
                }
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

            ThrowTypeError({signature->Function()->Id()->Name(), signature, " in ", signature->Owner(),
                            " cannot override ", it->Function()->Id()->Name(), it, " in ", it->Owner(), " because ",
                            reason},
                           signature->Function()->Start());
        }

        is_overriding_any_signature = true;
        it->AddSignatureFlag(SignatureFlags::VIRTUAL);
    }

    return is_overriding_any_signature;
}

void ETSChecker::CheckOverride(Signature *signature)
{
    auto *owner = signature->Owner();
    bool is_overriding = false;

    if (!owner->HasObjectFlag(ETSObjectFlags::CLASS | ETSObjectFlags::INTERFACE)) {
        return;
    }

    for (auto *const interface : owner->Interfaces()) {
        is_overriding |= CheckInterfaceOverride(this, interface, signature);
    }

    ETSObjectType *iter = owner->SuperType();
    while (iter != nullptr) {
        is_overriding |= CheckOverride(signature, iter);

        for (auto *const interface : iter->Interfaces()) {
            is_overriding |= CheckInterfaceOverride(this, interface, signature);
        }

        iter = iter->SuperType();
    }

    if (!is_overriding && signature->Function()->IsOverride()) {
        ThrowTypeError({"Method ", signature->Function()->Id()->Name(), signature, " in ", signature->Owner(),
                        " not overriding any method"},
                       signature->Function()->Start());
    }
}

Signature *ETSChecker::GetSignatureFromMethodDefinition(const ir::MethodDefinition *method_def)
{
    ASSERT(method_def->TsType() && method_def->TsType()->IsETSFunctionType());

    for (auto *it : method_def->TsType()->AsETSFunctionType()->CallSignatures()) {
        if (it->Function() == method_def->Function()) {
            return it;
        }
    }

    return nullptr;
}

void ETSChecker::ValidateSignatureAccessibility(ETSObjectType *callee, const ir::CallExpression *call_expr,
                                                Signature *signature, const lexer::SourcePosition &pos,
                                                char const *error_message)
{
    if ((Context().Status() & CheckerStatus::IGNORE_VISIBILITY) != 0U) {
        return;
    }
    if (signature->HasSignatureFlag(SignatureFlags::PRIVATE) ||
        signature->HasSignatureFlag(SignatureFlags::PROTECTED)) {
        ASSERT(callee->GetDeclNode() &&
               (callee->GetDeclNode()->IsClassDefinition() || callee->GetDeclNode()->IsTSInterfaceDeclaration()));

        if (callee->GetDeclNode()->IsTSInterfaceDeclaration()) {
            if (call_expr->Callee()->IsMemberExpression() &&
                call_expr->Callee()->AsMemberExpression()->Object()->IsThisExpression()) {
                const auto *enclosing_func =
                    util::Helpers::FindAncestorGivenByType(call_expr, ir::AstNodeType::SCRIPT_FUNCTION)
                        ->AsScriptFunction();
                if (signature->Function()->IsPrivate() && !enclosing_func->IsPrivate()) {
                    ThrowTypeError({"Cannot reference 'this' in this context."}, enclosing_func->Start());
                }
            }

            if (Context().ContainingClass() == callee->GetDeclNode()->AsTSInterfaceDeclaration()->TsType() &&
                callee->GetDeclNode()->AsTSInterfaceDeclaration()->TsType()->AsETSObjectType()->IsSignatureInherited(
                    signature)) {
                return;
            }
        }
        if (Context().ContainingClass() == callee->GetDeclNode()->AsClassDefinition()->TsType() &&
            callee->GetDeclNode()->AsClassDefinition()->TsType()->AsETSObjectType()->IsSignatureInherited(signature)) {
            return;
        }

        if (signature->HasSignatureFlag(SignatureFlags::PROTECTED) &&
            Context().ContainingClass()->IsDescendantOf(callee) && callee->IsSignatureInherited(signature)) {
            return;
        }

        auto *current_outermost = Context().ContainingClass()->OutermostClass();
        auto *obj_outermost = callee->OutermostClass();

        if (current_outermost != nullptr && obj_outermost != nullptr && current_outermost == obj_outermost &&
            callee->IsSignatureInherited(signature)) {
            return;
        }

        if (error_message == nullptr) {
            ThrowTypeError({"Signature ", signature->Function()->Id()->Name(), signature, " is not visible here."},
                           pos);
        }
        ThrowTypeError(error_message, pos);
    }
}

void ETSChecker::CheckCapturedVariable(ir::AstNode *const node, varbinder::Variable *const var)
{
    if (node->IsIdentifier()) {
        const auto *const parent = node->Parent();

        if (parent->IsUpdateExpression() ||
            (parent->IsAssignmentExpression() && parent->AsAssignmentExpression()->Left() == node)) {
            const auto *const ident_node = node->AsIdentifier();

            const auto *resolved = ident_node->Variable();

            if (resolved == nullptr) {
                resolved = FindVariableInFunctionScope(ident_node->Name());
            }

            if (resolved == nullptr) {
                resolved = FindVariableInGlobal(ident_node);
            }

            if (resolved == var) {
                var->AddFlag(varbinder::VariableFlags::BOXED);
            }
        }
    }

    CheckCapturedVariableInSubnodes(node, var);
}

void ETSChecker::CheckCapturedVariableInSubnodes(ir::AstNode *node, varbinder::Variable *var)
{
    node->Iterate([this, var](ir::AstNode *child_node) { CheckCapturedVariable(child_node, var); });
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

        auto *search_node = var->Declaration()->Node()->Parent();

        if (search_node->IsVariableDeclarator()) {
            search_node = search_node->Parent()->Parent();
        }

        CheckCapturedVariableInSubnodes(search_node, var);
    }
}

void ETSChecker::BuildFunctionalInterfaceName(ir::ETSFunctionType *func_type)
{
    VarBinder()->AsETSBinder()->BuildFunctionalInterfaceName(func_type);
}

void ETSChecker::CreateFunctionalInterfaceForFunctionType(ir::ETSFunctionType *func_type)
{
    auto *ident_node = Allocator()->New<ir::Identifier>(util::StringView("FunctionalInterface"), Allocator());

    auto interface_ctx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *interface_scope = interface_ctx.GetScope();

    ArenaVector<ir::AstNode *> members(Allocator()->Adapter());
    ir::MethodDefinition *invoke_func = CreateInvokeFunction(func_type);
    members.push_back(invoke_func);

    auto method_ctx =
        varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), interface_scope->InstanceMethodScope());
    auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(invoke_func->Start(), Allocator(),
                                                                     invoke_func->Id()->Name(), invoke_func);
    (void)_;
    var->AddFlag(varbinder::VariableFlags::METHOD);
    invoke_func->Function()->Id()->SetVariable(var);

    if (func_type->IsThrowing()) {
        invoke_func->Function()->AddFlag(ir::ScriptFunctionFlags::THROWS);
    }

    auto *body = Allocator()->New<ir::TSInterfaceBody>(std::move(members));

    ArenaVector<ir::TSInterfaceHeritage *> extends(Allocator()->Adapter());
    auto *interface_decl = Allocator()->New<ir::TSInterfaceDeclaration>(
        Allocator(), ident_node, nullptr, body, std::move(extends), false, false, Language(Language::Id::ETS));
    interface_decl->SetScope(interface_scope);
    interface_decl->AddModifier(ir::ModifierFlags::FUNCTIONAL);
    func_type->SetFunctionalInterface(interface_decl);
    invoke_func->SetParent(interface_decl);

    VarBinder()->AsETSBinder()->BuildFunctionType(func_type);
}

ir::MethodDefinition *ETSChecker::CreateInvokeFunction(ir::ETSFunctionType *func_type)
{
    auto *ident_node = Allocator()->New<ir::Identifier>(util::StringView("invoke"), Allocator());

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *func_param_scope = CopyParams(func_type->Params(), params);

    auto param_ctx =
        varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), func_param_scope, false);
    auto function_ctx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *function_scope = function_ctx.GetScope();
    function_scope->BindParamScope(func_param_scope);
    func_param_scope->BindFunctionScope(function_scope);

    ir::ModifierFlags flags = ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::PUBLIC;
    auto *func = Allocator()->New<ir::ScriptFunction>(
        ir::FunctionSignature(nullptr, std::move(params), func_type->ReturnType()), nullptr,
        ir::ScriptFunctionFlags::METHOD, flags, false, Language(Language::Id::ETS));

    func->SetScope(function_scope);
    function_scope->BindNode(func);
    func_param_scope->BindNode(func);

    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    func->SetIdent(ident_node);

    auto *method = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, ident_node, func_expr,
                                                          flags, Allocator(), false);

    func_expr->SetParent(method);
    func->SetParent(func_expr);

    return method;
}

// Lambda creation for Lambda expressions

void ETSChecker::CreateLambdaObjectForLambdaReference(ir::ArrowFunctionExpression *lambda,
                                                      ETSObjectType *functional_interface)
{
    if (VarBinder()->AsETSBinder()->LambdaObjects().count(lambda) != 0) {
        return;
    }

    bool save_this = false;
    size_t idx = 0;
    const auto &captured_vars = lambda->CapturedVars();
    auto *current_class_def = Context().ContainingClass()->GetDeclNode()->AsClassDefinition();

    // Create the class scope for the synthetic lambda class node
    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *class_scope = class_ctx.GetScope();

    // Create the synthetic class property nodes for the captured variables
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());
    for (const auto *it : captured_vars) {
        if (it->HasFlag(varbinder::VariableFlags::LOCAL)) {
            properties.push_back(CreateLambdaCapturedField(it, class_scope, idx, lambda->Start()));
            idx++;
        } else if (!it->HasFlag(varbinder::VariableFlags::STATIC) &&
                   !Context().ContainingClass()->HasObjectFlag(ETSObjectFlags::GLOBAL)) {
            save_this = true;
        }
    }

    // If the lambda captured a property in the current class, we have to make a synthetic class property to store
    // 'this' in it
    if (save_this) {
        properties.push_back(CreateLambdaCapturedThis(class_scope, idx, lambda->Start()));
        idx++;
    }

    // Create the synthetic proxy method node for the current class definiton, which we will use in the lambda
    // 'invoke' method to propagate the function call to the current class
    auto *proxy_method = CreateProxyMethodForLambda(current_class_def, lambda, properties, !save_this);

    // Create the synthetic constructor node for the lambda class, to be able to save captured variables
    auto *ctor = CreateLambdaImplicitCtor(properties);
    properties.push_back(ctor);

    // Create the synthetic invoke node for the lambda class, which will propagate the call to the proxy method
    auto *invoke_func = CreateLambdaInvokeProto();

    properties.push_back(invoke_func);

    // Create the declarations for the synthetic constructor and invoke method
    CreateLambdaFuncDecl(ctor, class_scope->StaticMethodScope());
    CreateLambdaFuncDecl(invoke_func, class_scope->InstanceMethodScope());

    // Create the synthetic lambda class node
    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
    auto *ident_node = Allocator()->New<ir::Identifier>(util::StringView("LambdaObject"), Allocator());
    auto *lambda_object =
        Allocator()->New<ir::ClassDefinition>(Allocator(), ident_node, std::move(properties),
                                              ir::ClassDefinitionModifiers::DECLARATION, Language(Language::Id::ETS));
    lambda->SetResolvedLambda(lambda_object);
    lambda->SetTsType(functional_interface);
    lambda_object->SetScope(class_scope);
    lambda_object->SetParent(current_class_def);

    // if we should save 'this', then propagate this information to the lambda node, so when we are compiling it,
    // and calling the lambda object ctor, we can pass the 'this' as argument
    if (save_this) {
        lambda->SetPropagateThis();
    }

    // Set the parent nodes
    ctor->SetParent(lambda_object);
    invoke_func->SetParent(lambda_object);
    class_scope->BindNode(lambda_object);

    // Build the lambda object in the binder
    VarBinder()->AsETSBinder()->BuildLambdaObject(lambda, lambda_object, proxy_method->Function()->Signature());

    // Resolve the proxy method
    ResolveProxyMethod(proxy_method, lambda);
    if (lambda->Function()->IsAsyncFunc()) {
        ir::MethodDefinition *async_impl = CreateAsyncProxy(proxy_method, current_class_def);
        ir::ScriptFunction *async_impl_func = async_impl->Function();
        current_class_def->Body().push_back(async_impl);
        ReplaceIdentifierReferencesInProxyMethod(async_impl_func->Body(), async_impl_func->Params(),
                                                 lambda->Function()->Params(), lambda->CapturedVars());
        Signature *impl_sig = CreateSignature(proxy_method->Function()->Signature()->GetSignatureInfo(),
                                              GlobalETSObjectType(), async_impl_func);
        async_impl_func->SetSignature(impl_sig);
        VarBinder()->AsETSBinder()->BuildFunctionName(async_impl->Function());
    }

    // Resolve the lambda object
    ResolveLambdaObject(lambda_object, functional_interface, lambda, proxy_method, save_this);
}

void ETSChecker::ResolveLambdaObject(ir::ClassDefinition *lambda_object, ETSObjectType *functional_interface,
                                     ir::ArrowFunctionExpression *lambda, ir::MethodDefinition *proxy_method,
                                     bool save_this)
{
    // Create the class type for the lambda
    auto *lambda_object_type = Allocator()->New<checker::ETSObjectType>(Allocator(), lambda_object->Ident()->Name(),
                                                                        lambda_object->Ident()->Name(), lambda_object,
                                                                        checker::ETSObjectFlags::CLASS);

    // Add the target function type to the implementing interfaces, this way, we can call the functional interface
    // virtual 'invoke' method and it will propagate the call to the currently stored lambda class 'invoke' function
    // which was assigned to the variable
    lambda_object_type->AddInterface(functional_interface);
    lambda_object->SetTsType(lambda_object_type);

    // Add the captured fields to the lambda class type
    for (auto *it : lambda_object->Body()) {
        if (!it->IsClassProperty()) {
            continue;
        }

        auto *prop = it->AsClassProperty();
        lambda_object_type->AddProperty<checker::PropertyType::INSTANCE_FIELD>(
            prop->Key()->AsIdentifier()->Variable()->AsLocalVariable());
    }
    VarBinder()->AsETSBinder()->BuildLambdaObjectName(lambda);

    // Resolve the constructor
    ResolveLambdaObjectCtor(lambda_object);

    // Resolve the invoke function
    ResolveLambdaObjectInvoke(lambda_object, lambda, proxy_method, !save_this);
}

void ETSChecker::ResolveLambdaObjectInvoke(ir::ClassDefinition *lambda_object, ir::ArrowFunctionExpression *lambda,
                                           ir::MethodDefinition *proxy_method, bool is_static)
{
    const auto &lambda_body = lambda_object->Body();
    auto *invoke_func = lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function();
    ETSObjectType *lambda_object_type = lambda_object->TsType()->AsETSObjectType();

    // Set the implicit 'this' parameters type to the lambda object
    auto *this_var = invoke_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(lambda_object_type);

    // Create the signature for the invoke function type
    auto *invoke_signature_info = CreateSignatureInfo();
    invoke_signature_info->rest_var = nullptr;

    // Create the parameters for the invoke function, based on the lambda function's parameters
    for (auto *it : lambda->Function()->Params()) {
        auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            VarBinder(), invoke_func->Scope()->ParamScope(), false);

        auto *const param = it->AsETSParameterExpression();
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(param->Variable()->TsType());
        param->Ident()->SetVariable(var);
        invoke_func->Params().push_back(param);
        invoke_signature_info->min_arg_count++;
        invoke_signature_info->params.push_back(var->AsLocalVariable());
    }

    // Create the function type for the invoke method
    auto *invoke_signature =
        CreateSignature(invoke_signature_info, lambda->Function()->Signature()->ReturnType(), invoke_func);
    invoke_signature->SetOwner(lambda_object_type);
    invoke_signature->AddSignatureFlag(checker::SignatureFlags::CALL);

    auto *invoke_type = CreateETSFunctionType(invoke_signature);
    invoke_func->SetSignature(invoke_signature);
    invoke_func->Id()->Variable()->SetTsType(invoke_type);
    VarBinder()->AsETSBinder()->BuildFunctionName(invoke_func);
    lambda_object_type->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invoke_func->Id()->Variable()->AsLocalVariable());

    // Fill out the type information for the body of the invoke function
    auto *resolved_lambda_invoke_function_body =
        ResolveLambdaObjectInvokeFuncBody(lambda_object, proxy_method, is_static);
    if (invoke_func->IsAsyncFunc()) {
        return;
    }
    invoke_func->Body()->AsBlockStatement()->Statements().push_back(resolved_lambda_invoke_function_body);
    if (resolved_lambda_invoke_function_body->IsExpressionStatement()) {
        invoke_func->Body()->AsBlockStatement()->Statements().push_back(Allocator()->New<ir::ReturnStatement>(nullptr));
    }
}

ir::Statement *ETSChecker::ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambda_object,
                                                             ir::MethodDefinition *proxy_method, bool is_static)
{
    const auto &lambda_body = lambda_object->Body();
    auto *proxy_signature = proxy_method->Function()->Signature();
    ir::Identifier *field_ident {};
    ETSObjectType *field_prop_type {};

    // If the proxy method is static, we should call it through the owner class itself
    if (is_static) {
        field_ident = Allocator()->New<ir::Identifier>(proxy_signature->Owner()->Name(), Allocator());
        field_prop_type = proxy_signature->Owner();
        field_ident->SetVariable(proxy_signature->Owner()->Variable());
        field_ident->SetTsType(field_prop_type);
    } else {
        // Otherwise, we call the proxy method through the saved 'this' field
        auto *saved_this = lambda_body[lambda_body.size() - 3]->AsClassProperty();
        auto *field_prop = saved_this->Key()->AsIdentifier()->Variable();
        field_prop_type = field_prop->TsType()->AsETSObjectType();
        field_ident = Allocator()->New<ir::Identifier>(saved_this->Key()->AsIdentifier()->Name(), Allocator());
        field_ident->SetVariable(field_prop);
        field_ident->SetTsType(field_prop_type);
    }

    // Set the type information for the proxy function call
    auto *func_ident = Allocator()->New<ir::Identifier>(proxy_method->Function()->Id()->Name(), Allocator());
    auto *callee = Allocator()->New<ir::MemberExpression>(field_ident, func_ident,
                                                          ir::MemberExpressionKind::ELEMENT_ACCESS, false, false);
    callee->SetPropVar(proxy_signature->OwnerVar()->AsLocalVariable());
    callee->SetObjectType(field_prop_type);
    callee->SetTsType(proxy_signature->OwnerVar()->TsType());

    // Resolve the proxy method call arguments, first we add the captured fields to the call
    auto *invoke_func = lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function();
    ArenaVector<ir::Expression *> call_params(Allocator()->Adapter());
    size_t counter = is_static ? lambda_body.size() - 2 : lambda_body.size() - 3;
    for (size_t i = 0; i < counter; i++) {
        if (lambda_body[i]->IsMethodDefinition()) {
            break;
        }

        auto *class_prop = lambda_body[i]->AsClassProperty();
        auto *param = Allocator()->New<ir::Identifier>(class_prop->Key()->AsIdentifier()->Name(), Allocator());
        param->SetVariable(class_prop->Key()->AsIdentifier()->Variable());
        param->SetIgnoreBox();
        param->SetTsType(MaybeBoxedType(param->Variable()));
        call_params.push_back(param);
    }

    // Then we add the lambda functions parameters to the call
    for (auto const *const it : invoke_func->Params()) {
        auto const *const param = it->AsETSParameterExpression();
        auto *const param_ident = Allocator()->New<ir::Identifier>(param->Ident()->Name(), Allocator());
        param_ident->SetVariable(param->Variable());
        param_ident->SetTsType(param->Variable()->TsType());
        call_params.push_back(param_ident);
    }

    // Create the synthetic call expression to the proxy method
    auto *resolved_call = Allocator()->New<ir::CallExpression>(callee, std::move(call_params), nullptr, false);
    resolved_call->SetTsType(proxy_signature->ReturnType());
    resolved_call->SetSignature(proxy_signature);

    if (proxy_signature->ReturnType()->IsETSVoidType()) {
        return Allocator()->New<ir::ExpressionStatement>(resolved_call);
    }
    return Allocator()->New<ir::ReturnStatement>(resolved_call);
}

void ETSChecker::ResolveLambdaObjectCtor(ir::ClassDefinition *lambda_object)
{
    const auto &lambda_body = lambda_object->Body();
    auto *lambda_object_type = lambda_object->TsType()->AsETSObjectType();
    auto *ctor_func = lambda_body[lambda_body.size() - 2]->AsMethodDefinition()->Function();

    // Set the implicit 'this' parameters type to the lambda object
    auto *this_var = ctor_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(lambda_object_type);

    // Create the signature for the constructor function type
    auto *ctor_signature_info = CreateSignatureInfo();
    ctor_signature_info->rest_var = nullptr;

    for (auto const *const it : ctor_func->Params()) {
        ++ctor_signature_info->min_arg_count;
        ctor_signature_info->params.push_back(it->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }

    // Create the function type for the constructor
    auto *ctor_signature = CreateSignature(ctor_signature_info, GlobalVoidType(), ctor_func);
    ctor_signature->SetOwner(lambda_object_type);
    ctor_signature->AddSignatureFlag(checker::SignatureFlags::CONSTRUCTOR | checker::SignatureFlags::CONSTRUCT);
    lambda_object_type->AddConstructSignature(ctor_signature);

    auto *ctor_type = CreateETSFunctionType(ctor_signature);
    ctor_func->SetSignature(ctor_signature);
    ctor_func->Id()->Variable()->SetTsType(ctor_type);
    VarBinder()->AsETSBinder()->BuildFunctionName(ctor_func);

    // Add the type information for the lambda field initializers in the constructor
    auto &initializers = ctor_func->Body()->AsBlockStatement()->Statements();
    for (size_t i = 0; i < initializers.size(); i++) {
        auto *fieldinit = initializers[i]->AsExpressionStatement()->GetExpression()->AsAssignmentExpression();
        auto *ctor_param_var = ctor_func->Params()[i]->AsETSParameterExpression()->Variable();
        auto *field_var = lambda_body[i]->AsClassProperty()->Key()->AsIdentifier()->Variable();
        auto *left_hand_side = fieldinit->Left();
        left_hand_side->AsMemberExpression()->SetObjectType(lambda_object_type);
        left_hand_side->AsMemberExpression()->SetPropVar(field_var->AsLocalVariable());
        left_hand_side->AsMemberExpression()->SetIgnoreBox();
        left_hand_side->AsMemberExpression()->SetTsType(field_var->TsType());
        left_hand_side->AsMemberExpression()->Object()->SetTsType(lambda_object_type);
        fieldinit->Right()->AsIdentifier()->SetVariable(ctor_param_var);
        fieldinit->Right()->SetTsType(ctor_param_var->TsType());
    }
}

void ETSChecker::ResolveProxyMethod(ir::MethodDefinition *proxy_method, ir::ArrowFunctionExpression *lambda)
{
    auto *func = proxy_method->Function();
    bool is_static = func->IsStatic();
    auto *current_class_type = Context().ContainingClass();

    // Build the proxy method in the binder
    VarBinder()->AsETSBinder()->BuildProxyMethod(
        func, current_class_type->GetDeclNode()->AsClassDefinition()->InternalName(), is_static);

    // If the proxy method is not static, set the implicit 'this' parameters type to the current class
    if (!is_static) {
        auto *this_var = func->Scope()->ParamScope()->Params().front();
        this_var->SetTsType(current_class_type);
    }

    // Fill out the type information for the proxy method
    auto *signature = func->Signature();
    auto *signature_info = signature->GetSignatureInfo();
    signature_info->rest_var = nullptr;

    for (auto const *const it : proxy_method->Function()->Params()) {
        signature_info->params.push_back(it->AsETSParameterExpression()->Variable()->AsLocalVariable());
        ++signature_info->min_arg_count;
    }

    signature->SetReturnType(lambda->Function()->Signature()->ReturnType());
    signature->SetOwner(current_class_type);

    // Add the proxy method to the current class methods
    if (is_static) {
        current_class_type->AddProperty<checker::PropertyType::STATIC_METHOD>(
            func->Id()->Variable()->AsLocalVariable());
    } else {
        current_class_type->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
            func->Id()->Variable()->AsLocalVariable());
    }
    VarBinder()->AsETSBinder()->BuildFunctionName(func);
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

ir::ModifierFlags ETSChecker::GetFlagsForProxyLambda(bool is_static)
{
    // If every captured variable in the lambda is local variable, the proxy method can be 'static' since it doesn't
    // use any of the classes properties
    ir::ModifierFlags flags = ir::ModifierFlags::PUBLIC;

    if (is_static) {
        flags |= ir::ModifierFlags::STATIC;
    }

    return flags;
}

ir::ScriptFunction *ETSChecker::CreateProxyFunc(ir::ArrowFunctionExpression *lambda,
                                                ArenaVector<ir::AstNode *> &captured, bool is_static)
{
    // Create the synthetic parameters for the proxy method
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *func_param_scope = CreateProxyMethodParams(lambda, params, captured, is_static);

    // Create the scopes for the proxy method
    auto param_ctx =
        varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), func_param_scope, false);
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), func_param_scope);
    auto *body = lambda->Function()->Body();
    body->AsBlockStatement()->SetScope(scope);

    ir::ScriptFunctionFlags func_flags = ir::ScriptFunctionFlags::METHOD | ir::ScriptFunctionFlags::PROXY;
    if (lambda->Function()->IsAsyncFunc()) {
        func_flags |= ir::ScriptFunctionFlags::ASYNC;
    }
    auto *func = Allocator()->New<ir::ScriptFunction>(
        ir::FunctionSignature(nullptr, std::move(params), lambda->Function()->ReturnTypeAnnotation()), body, func_flags,
        GetFlagsForProxyLambda(is_static), false, Language(Language::Id::ETS));

    func->SetScope(scope);
    if (!func->IsAsyncFunc()) {
        // Replace the variable binding in the lambda body where an identifier refers to a lambda parameter or a
        // captured variable to the newly created proxy parameters
        ReplaceIdentifierReferencesInProxyMethod(body, func->Params(), lambda->Function()->Params(),
                                                 lambda->CapturedVars());
    }

    // Bind the scopes
    scope->BindNode(func);
    func_param_scope->BindNode(func);
    scope->BindParamScope(func_param_scope);
    func_param_scope->BindFunctionScope(scope);

    // Copy the bindings from the original function scope
    for (const auto &binding : lambda->Function()->Scope()->Bindings()) {
        scope->InsertBinding(binding.first, binding.second);
    }

    ReplaceScope(body, lambda->Function(), scope);
    return func;
}

ir::MethodDefinition *ETSChecker::CreateProxyMethodForLambda(ir::ClassDefinition *klass,
                                                             ir::ArrowFunctionExpression *lambda,
                                                             ArenaVector<ir::AstNode *> &captured, bool is_static)
{
    auto *func = CreateProxyFunc(lambda, captured, is_static);

    // Create the synthetic proxy method
    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    util::UString func_name(util::StringView("lambda$invoke$"), Allocator());
    func_name.Append(std::to_string(ComputeProxyMethods(klass)));
    auto *ident_node = Allocator()->New<ir::Identifier>(func_name.View(), Allocator());
    func->SetIdent(ident_node);
    auto *proxy = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, ident_node, func_expr,
                                                         GetFlagsForProxyLambda(is_static), Allocator(), false);
    klass->Body().push_back(proxy);
    proxy->SetParent(klass);

    // Add the proxy method to the current class declarations
    CreateLambdaFuncDecl(proxy, klass->Scope()->AsClassScope()->InstanceMethodScope());

    // Set the parent nodes
    func->SetParent(func_expr);
    func_expr->SetParent(proxy);

    // Create the signature template for the proxy method to be able to save this signatures pointer in the binder
    // lambdaObjects_ to be able to compute the lambda object invoke functions internal name later
    auto *proxy_signature_info = CreateSignatureInfo();
    auto *proxy_signature = CreateSignature(proxy_signature_info, GlobalVoidType(), func);

    SignatureFlags signature_flags = SignatureFlags::CALL;
    if (is_static) {
        signature_flags |= SignatureFlags::STATIC;
    }

    proxy_signature->AddSignatureFlag(signature_flags | SignatureFlags::PROXY);
    proxy_signature->SetOwnerVar(func->Id()->Variable());
    auto *proxy_type = CreateETSFunctionType(proxy_signature);
    func->SetSignature(proxy_signature);
    func->Id()->Variable()->SetTsType(proxy_type);

    return proxy;
}

void ETSChecker::ReplaceIdentifierReferencesInProxyMethod(ir::AstNode *body,
                                                          const ArenaVector<ir::Expression *> &proxy_params,
                                                          const ArenaVector<ir::Expression *> &lambda_params,
                                                          ArenaVector<varbinder::Variable *> &captured)
{
    if (proxy_params.empty()) {
        return;
    }

    // First, create a merged list of all of the potential references which we will replace. These references are
    // the original lambda expression parameters and the references to the captured variables inside the lambda
    // expression body. The order is crucial, thats why we save the index, because in the synthetic proxy method,
    // the first n number of parameters are which came from the lambda expression parameter list, and the last
    // parameters are which came from the captured variables
    std::unordered_map<varbinder::Variable *, size_t> merged_target_references;
    size_t idx = 0;

    for (auto *it : captured) {
        if (it->HasFlag(varbinder::VariableFlags::LOCAL)) {
            merged_target_references.insert({it, idx});
            idx++;
        }
    }

    for (auto const *const it : lambda_params) {
        merged_target_references.insert({it->AsETSParameterExpression()->Variable(), idx});
        idx++;
    }

    ReplaceIdentifierReferencesInProxyMethod(body, proxy_params, merged_target_references);
}

void ETSChecker::ReplaceIdentifierReferencesInProxyMethod(
    ir::AstNode *node, const ArenaVector<ir::Expression *> &proxy_params,
    std::unordered_map<varbinder::Variable *, size_t> &merged_target_references)
{
    if (node->IsMemberExpression()) {
        auto *member_expr = node->AsMemberExpression();
        if (member_expr->Kind() == ir::MemberExpressionKind::PROPERTY_ACCESS) {
            ReplaceIdentifierReferenceInProxyMethod(member_expr->Object(), proxy_params, merged_target_references);
            return;
        }
    }
    node->Iterate([this, &proxy_params, &merged_target_references](ir::AstNode *child_node) {
        ReplaceIdentifierReferenceInProxyMethod(child_node, proxy_params, merged_target_references);
    });
}

void ETSChecker::ReplaceIdentifierReferenceInProxyMethod(
    ir::AstNode *node, const ArenaVector<ir::Expression *> &proxy_params,
    std::unordered_map<varbinder::Variable *, size_t> &merged_target_references)
{
    // If we see an identifier reference
    if (node->IsIdentifier()) {
        auto *ident_node = node->AsIdentifier();
        ASSERT(ident_node->Variable());

        // Then check if that reference is present in the target references which we want to replace
        auto found = merged_target_references.find(ident_node->Variable());
        if (found != merged_target_references.end()) {
            // If it is present in the target references, replace it with the proper proxy parameter reference
            ident_node->SetVariable(proxy_params[found->second]->AsETSParameterExpression()->Variable());
        }
    }

    ReplaceIdentifierReferencesInProxyMethod(node, proxy_params, merged_target_references);
}

varbinder::FunctionParamScope *ETSChecker::CreateProxyMethodParams(ir::ArrowFunctionExpression *lambda,
                                                                   ArenaVector<ir::Expression *> &proxy_params,
                                                                   ArenaVector<ir::AstNode *> &captured, bool is_static)
{
    const auto &params = lambda->Function()->Params();
    // Create a param scope for the proxy method parameters
    auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // First add the parameters to the proxy method, based on how many variables have been captured, if this
    // is NOT a static method, we doesn't need the last captured parameter, which is the 'this' reference, because
    // this proxy method is bound to the class itself which the 'this' capture is referred to
    if (!captured.empty()) {
        size_t counter = is_static ? captured.size() : (captured.size() - 1);
        for (size_t i = 0; i < counter; i++) {
            auto *captured_var = captured[i]->AsClassProperty()->Key()->AsIdentifier()->Variable();
            ir::Identifier *param_ident = nullptr;

            // When a lambda is defined inside an instance extension function, if "this" is captured inside the lambda,
            // "this" should be binded with the parameter of the proxy method
            if (this->HasStatus(checker::CheckerStatus::IN_INSTANCE_EXTENSION_METHOD) &&
                lambda->CapturedVars()[i]->Name() == varbinder::VarBinder::MANDATORY_PARAM_THIS) {
                param_ident = Allocator()->New<ir::Identifier>(varbinder::VarBinder::MANDATORY_PARAM_THIS, Allocator());
            } else {
                param_ident = Allocator()->New<ir::Identifier>(captured_var->Name(), Allocator());
            }

            auto *param = Allocator()->New<ir::ETSParameterExpression>(param_ident, nullptr);
            auto [_, var] = VarBinder()->AddParamDecl(param);
            (void)_;
            var->SetTsType(captured_var->TsType());
            if (captured_var->HasFlag(varbinder::VariableFlags::BOXED)) {
                var->AddFlag(varbinder::VariableFlags::BOXED);
            }
            param->SetTsType(captured_var->TsType());
            param->SetVariable(var);
            proxy_params.push_back(param);
        }
    }

    // Then add the lambda function parameters to the proxy method's parameter vector, and set the type from the
    // already computed types for the lambda parameters
    for (auto const *const it : params) {
        auto *const old_param_expr_ident = it->AsETSParameterExpression()->Ident();
        auto *const param_ident = Allocator()->New<ir::Identifier>(old_param_expr_ident->Name(), Allocator());
        auto *param = Allocator()->New<ir::ETSParameterExpression>(param_ident, nullptr);
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(old_param_expr_ident->Variable()->TsType());
        param->SetVariable(var);
        param->SetTsType(old_param_expr_ident->Variable()->TsType());
        proxy_params.push_back(param);
    }

    return param_ctx.GetScope();
}

ir::ClassProperty *ETSChecker::CreateLambdaCapturedThis(varbinder::ClassScope *scope, size_t &idx,
                                                        const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto field_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the name for the synthetic property node
    util::UString field_name(util::StringView("field"), Allocator());
    field_name.Append(std::to_string(idx));
    auto *field_ident = Allocator()->New<ir::Identifier>(field_name.View(), Allocator());

    // Create the synthetic class property node
    auto *field =
        Allocator()->New<ir::ClassProperty>(field_ident, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);

    // Add the declaration to the scope, and set the type based on the current class type, to be able to store the
    // 'this' reference
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, field_ident->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(Context().ContainingClass());
    field_ident->SetVariable(var);
    field->SetTsType(Context().ContainingClass());
    decl->BindNode(field);
    return field;
}

ir::ClassProperty *ETSChecker::CreateLambdaCapturedField(const varbinder::Variable *captured_var,
                                                         varbinder::ClassScope *scope, size_t &idx,
                                                         const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto field_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the name for the synthetic property node
    util::UString field_name(util::StringView("field"), Allocator());
    field_name.Append(std::to_string(idx));
    auto *field_ident = Allocator()->New<ir::Identifier>(field_name.View(), Allocator());

    // Create the synthetic class property node
    auto *field =
        Allocator()->New<ir::ClassProperty>(field_ident, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);

    // Add the declaration to the scope, and set the type based on the captured variable's scope
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, field_ident->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(captured_var->TsType());
    if (captured_var->HasFlag(varbinder::VariableFlags::BOXED)) {
        var->AddFlag(varbinder::VariableFlags::BOXED);
    }
    field_ident->SetVariable(var);
    field->SetTsType(MaybeBoxedType(captured_var));
    decl->BindNode(field);
    return field;
}

ir::MethodDefinition *ETSChecker::CreateLambdaImplicitCtor(ArenaVector<ir::AstNode *> &properties)
{
    // Create the parameters for the synthetic constructor node for the lambda class
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *func_param_scope = CreateLambdaCtorImplicitParams(params, properties);

    // Create the scopes for the synthetic constructor node
    auto param_ctx =
        varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), func_param_scope, false);
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), func_param_scope);

    // Complete the synthetic constructor node's body, to be able to initialize every field by copying every
    // captured variables value
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    for (auto *it : properties) {
        auto *field = it->AsClassProperty()->Key()->AsIdentifier();
        statements.push_back(CreateLambdaCtorFieldInit(field->Name(), field->Variable()));
    }

    // Create the synthetic constructor node
    auto *body = Allocator()->New<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    auto *func =
        Allocator()->New<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), nullptr), body,
                                             ir::ScriptFunctionFlags::CONSTRUCTOR, false, Language(Language::Id::ETS));
    func->SetScope(scope);
    // Set the scopes
    scope->BindNode(func);
    func_param_scope->BindNode(func);
    scope->BindParamScope(func_param_scope);
    func_param_scope->BindFunctionScope(scope);

    // Create the name for the synthetic constructor
    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    auto *key = Allocator()->New<ir::Identifier>("constructor", Allocator());
    func->SetIdent(key);
    auto *ctor = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, key, func_expr,
                                                        ir::ModifierFlags::NONE, Allocator(), false);

    // Set the parent nodes
    func->SetParent(func_expr);
    func_expr->SetParent(ctor);

    return ctor;
}

varbinder::FunctionParamScope *ETSChecker::CreateLambdaCtorImplicitParams(ArenaVector<ir::Expression *> &params,
                                                                          ArenaVector<ir::AstNode *> &properties)
{
    // Create the scope for the synthetic constructor parameters
    auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // Create every parameter based on the synthetic field which was created for the lambda class to store the
    // captured variables
    for (auto *it : properties) {
        auto *field = it->AsClassProperty()->Key()->AsIdentifier();
        auto *param_field = Allocator()->New<ir::Identifier>(field->Name(), Allocator());
        auto *param = Allocator()->New<ir::ETSParameterExpression>(param_field, nullptr);
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        auto *type = MaybeBoxedType(field->Variable());
        var->SetTsType(type);
        param->Ident()->SetTsType(type);
        param->Ident()->SetVariable(var);
        params.push_back(param);
    }

    return param_ctx.GetScope();
}

ir::Statement *ETSChecker::CreateLambdaCtorFieldInit(util::StringView name, varbinder::Variable *var)
{
    // Create synthetic field initializers for the lambda class fields
    // The node structure is the following: this.field0 = field0, where the left hand side refers to the lambda
    // classes field, and the right hand side is refers to the constructors parameter
    auto *this_expr = Allocator()->New<ir::ThisExpression>();
    auto *field_access_expr = Allocator()->New<ir::Identifier>(name, Allocator());
    auto *left_hand_side = Allocator()->New<ir::MemberExpression>(
        this_expr, field_access_expr, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *right_hand_side = Allocator()->New<ir::Identifier>(name, Allocator());
    right_hand_side->SetVariable(var);
    auto *initializer = Allocator()->New<ir::AssignmentExpression>(left_hand_side, right_hand_side,
                                                                   lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    return Allocator()->New<ir::ExpressionStatement>(initializer);
}

// Lambda creation for Function references

void ETSChecker::CreateLambdaObjectForFunctionReference(ir::AstNode *ref_node, Signature *signature,
                                                        ETSObjectType *functional_interface)
{
    if (VarBinder()->AsETSBinder()->LambdaObjects().count(ref_node) != 0) {
        return;
    }

    // Create the class scope for the synthetic lambda class node
    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
    auto *class_scope = class_ctx.GetScope();
    bool is_static_reference = signature->HasSignatureFlag(SignatureFlags::STATIC);

    // Create the synthetic field where we will store the instance object which we are trying to obtain the function
    // reference through, if the referenced function is static, we won't need to store the instance object
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());
    if (!is_static_reference) {
        properties.push_back(CreateLambdaImplicitField(class_scope, ref_node->Start()));
    }

    // Create the synthetic constructor node, where we will initialize the synthetic field (if present) to the
    // instance object
    auto *ctor = CreateLambdaImplicitCtor(ref_node->Range(), is_static_reference);
    properties.push_back(ctor);

    // Create the template for the synthetic invoke function which will propagate the function call to the saved
    // instance's referenced function, or the class static function, if this is a static reference
    auto *invoke_func = CreateLambdaInvokeProto();
    properties.push_back(invoke_func);

    // Create the declarations for the synthetic constructor and invoke method
    CreateLambdaFuncDecl(ctor, class_scope->StaticMethodScope());
    CreateLambdaFuncDecl(invoke_func, class_scope->InstanceMethodScope());

    // Create the synthetic lambda class node
    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
    auto *ident_node = Allocator()->New<ir::Identifier>(util::StringView("LambdaObject"), Allocator());
    auto *lambda_object =
        Allocator()->New<ir::ClassDefinition>(Allocator(), ident_node, std::move(properties),
                                              ir::ClassDefinitionModifiers::DECLARATION, Language(Language::Id::ETS));
    lambda_object->SetScope(class_scope);
    // Set the parent nodes
    ctor->SetParent(lambda_object);
    invoke_func->SetParent(lambda_object);
    class_scope->BindNode(lambda_object);

    // Build the lambda object in the binder
    VarBinder()->AsETSBinder()->BuildLambdaObject(ref_node, lambda_object, signature);

    // Resolve the lambda object
    ResolveLambdaObject(lambda_object, signature, functional_interface, ref_node);
}

ir::AstNode *ETSChecker::CreateLambdaImplicitField(varbinder::ClassScope *scope, const lexer::SourcePosition &pos)
{
    // Enter the lambda class instance field scope, every property will be bound to the lambda instance itself
    auto field_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope->InstanceFieldScope());

    // Create the synthetic class property node
    auto *field_ident = Allocator()->New<ir::Identifier>("field0", Allocator());
    auto *field =
        Allocator()->New<ir::ClassProperty>(field_ident, nullptr, nullptr, ir::ModifierFlags::NONE, Allocator(), false);

    // Add the declaration to the scope
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(pos, field_ident->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    field_ident->SetVariable(var);
    decl->BindNode(field);
    return field;
}

ir::MethodDefinition *ETSChecker::CreateLambdaImplicitCtor(const lexer::SourceRange &pos, bool is_static_reference)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    // Create the parameters for the synthetic constructor
    auto [funcParamScope, var] = CreateLambdaCtorImplicitParam(params, pos, is_static_reference);

    // Create the scopes
    auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), funcParamScope);

    // If the reference refers to a static function, the constructor will be empty, otherwise, we have to make a
    // synthetic initializer to initialize the lambda class field
    if (!is_static_reference) {
        statements.push_back(CreateLambdaCtorFieldInit(util::StringView("field0"), var));
    }

    auto *body = Allocator()->New<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    auto *func =
        Allocator()->New<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), nullptr), body,
                                             ir::ScriptFunctionFlags::CONSTRUCTOR, false, Language(Language::Id::ETS));
    func->SetScope(scope);
    // Bind the scopes
    scope->BindNode(func);
    funcParamScope->BindNode(func);
    scope->BindParamScope(funcParamScope);
    funcParamScope->BindFunctionScope(scope);

    // Create the synthetic constructor
    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    auto *key = Allocator()->New<ir::Identifier>("constructor", Allocator());
    func->SetIdent(key);
    auto *ctor = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, key, func_expr,
                                                        ir::ModifierFlags::NONE, Allocator(), false);

    // Set the parent nodes
    func->SetParent(func_expr);
    func_expr->SetParent(ctor);

    return ctor;
}

std::tuple<varbinder::FunctionParamScope *, varbinder::Variable *> ETSChecker::CreateLambdaCtorImplicitParam(
    ArenaVector<ir::Expression *> &params, const lexer::SourceRange &pos, bool is_static_reference)
{
    // Create the function parameter scope
    auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    // Create the synthetic constructors parameter, if this is a static reference, we don't need any parameter,
    // since when initializing the lambda class, we don't need to save the instance object which we tried to get the
    // function reference through
    if (!is_static_reference) {
        auto *param_ident = Allocator()->New<ir::Identifier>("field0", Allocator());
        auto *param = Allocator()->New<ir::ETSParameterExpression>(param_ident, nullptr);
        param_ident->SetRange(pos);
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        param_ident->SetVariable(var);
        params.push_back(param);
        return {param_ctx.GetScope(), var};
    }

    return {param_ctx.GetScope(), nullptr};
}

ir::MethodDefinition *ETSChecker::CreateLambdaInvokeProto()
{
    // Create the template for the synthetic 'invoke' method, which will be used when the function type will be
    // called
    auto *name = Allocator()->New<ir::Identifier>("invoke", Allocator());
    auto *param_scope =
        VarBinder()->Allocator()->New<varbinder::FunctionParamScope>(Allocator(), VarBinder()->GetScope());
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), param_scope);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    auto *body = Allocator()->New<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(scope);
    auto *func = Allocator()->New<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), nullptr), body,
                                                      ir::ScriptFunctionFlags::METHOD, ir::ModifierFlags::PUBLIC, false,
                                                      Language(Language::Id::ETS));
    func->SetScope(scope);

    scope->BindNode(func);
    param_scope->BindNode(func);
    scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(scope);

    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    func->SetIdent(name);

    auto *method = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, name, func_expr,
                                                          ir::ModifierFlags::PUBLIC, Allocator(), false);

    func_expr->SetParent(method);
    func->SetParent(func_expr);

    return method;
}

void ETSChecker::CreateLambdaFuncDecl(ir::MethodDefinition *func, varbinder::LocalScope *scope)
{
    // Add the function declarations to the lambda class scope
    auto ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), scope);
    auto [_, var] =
        VarBinder()->NewVarDecl<varbinder::FunctionDecl>(func->Start(), Allocator(), func->Id()->Name(), func);
    (void)_;
    var->AddFlag(varbinder::VariableFlags::METHOD);
    func->Function()->Id()->SetVariable(var);
}

void ETSChecker::ResolveLambdaObject(ir::ClassDefinition *lambda_object, Signature *signature,
                                     ETSObjectType *functional_interface, ir::AstNode *ref_node)
{
    // Set the type information for the lambda class, which will be required by the compiler
    Type *target_type = signature->Owner();
    bool is_static_reference = signature->HasSignatureFlag(SignatureFlags::STATIC);
    varbinder::Variable *field_var {};

    // If this is NOT a static function reference, we have to set the field's type to the referenced signatures
    // owner type, because that will be the type of the instance object which will be saved in that field
    if (!is_static_reference) {
        auto *field = lambda_object->Body()[0]->AsClassProperty();
        field_var = field->Key()->AsIdentifier()->Variable();
        field->SetTsType(target_type);
        field_var->SetTsType(target_type);
        auto *ctor_func = lambda_object->Body()[1]->AsMethodDefinition()->Function();
        ctor_func->Params()[0]->AsETSParameterExpression()->Variable()->SetTsType(target_type);
    }

    // Create the class type for the lambda
    auto *lambda_object_type = Allocator()->New<checker::ETSObjectType>(Allocator(), lambda_object->Ident()->Name(),
                                                                        lambda_object->Ident()->Name(), lambda_object,
                                                                        checker::ETSObjectFlags::CLASS);

    // Add the target function type to the implementing interfaces, this way, we can call the functional interface
    // virtual 'invoke' method and it will propagate the call to the currently stored lambda class 'invoke' function
    // which was assigned to the variable
    lambda_object_type->AddInterface(functional_interface);
    lambda_object->SetTsType(lambda_object_type);

    // Add the field if this is not a static reference to the lambda class type
    if (!is_static_reference) {
        lambda_object_type->AddProperty<checker::PropertyType::INSTANCE_FIELD>(field_var->AsLocalVariable());
    }
    VarBinder()->AsETSBinder()->BuildLambdaObjectName(ref_node);

    // Resolve the constructor
    ResolveLambdaObjectCtor(lambda_object, is_static_reference);

    // Resolve the invoke function
    ResolveLambdaObjectInvoke(lambda_object, signature);
}

void ETSChecker::ResolveLambdaObjectCtor(ir::ClassDefinition *lambda_object, bool is_static_reference)
{
    const auto &lambda_body = lambda_object->Body();
    auto *ctor_func = lambda_body[lambda_body.size() - 2]->AsMethodDefinition()->Function();
    ETSObjectType *lambda_object_type = lambda_object->TsType()->AsETSObjectType();
    varbinder::Variable *field_var {};

    if (!is_static_reference) {
        auto *field = lambda_body[0]->AsClassProperty();
        field_var = field->Key()->AsIdentifier()->Variable();
    }

    // Set the implicit 'this' parameters type to the lambda object
    auto *this_var = ctor_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(lambda_object_type);

    // Create the signature for the constructor function type
    auto *ctor_signature_info = CreateSignatureInfo();
    ctor_signature_info->rest_var = nullptr;

    if (is_static_reference) {
        ctor_signature_info->min_arg_count = 0;
    } else {
        ctor_signature_info->min_arg_count = 1;
        ctor_signature_info->params.push_back(
            ctor_func->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }

    // Create the function type for the constructor
    auto *ctor_signature = CreateSignature(ctor_signature_info, GlobalVoidType(), ctor_func);
    ctor_signature->SetOwner(lambda_object_type);
    ctor_signature->AddSignatureFlag(checker::SignatureFlags::CONSTRUCTOR | checker::SignatureFlags::CONSTRUCT);
    lambda_object_type->AddConstructSignature(ctor_signature);

    auto *ctor_type = CreateETSFunctionType(ctor_signature);
    ctor_func->SetSignature(ctor_signature);
    ctor_func->Id()->Variable()->SetTsType(ctor_type);
    VarBinder()->AsETSBinder()->BuildFunctionName(ctor_func);

    // If this is a static function reference, we are done, since the constructor body is empty
    if (is_static_reference) {
        return;
    }

    // Otherwise, set the type information for the field initializer
    auto *fieldinit = ctor_func->Body()
                          ->AsBlockStatement()
                          ->Statements()[0]
                          ->AsExpressionStatement()
                          ->GetExpression()
                          ->AsAssignmentExpression();

    auto *left_hand_side = fieldinit->Left();
    left_hand_side->AsMemberExpression()->SetObjectType(lambda_object_type);
    left_hand_side->AsMemberExpression()->SetPropVar(field_var->AsLocalVariable());
    left_hand_side->AsMemberExpression()->SetTsType(field_var->TsType());
    left_hand_side->AsMemberExpression()->Object()->SetTsType(lambda_object_type);
    fieldinit->Right()->AsIdentifier()->SetVariable(ctor_signature->Params()[0]);
    fieldinit->Right()->SetTsType(ctor_signature->Params()[0]->TsType());
}

void ETSChecker::ResolveLambdaObjectInvoke(ir::ClassDefinition *lambda_object, Signature *signature_ref)
{
    const auto &lambda_body = lambda_object->Body();
    auto *invoke_func = lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function();
    ETSObjectType *lambda_object_type = lambda_object->TsType()->AsETSObjectType();

    // Set the implicit 'this' parameters type to the lambda object
    auto *this_var = invoke_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(lambda_object_type);

    // Create the signature for the invoke function type
    auto *invoke_signature_info = CreateSignatureInfo();
    invoke_signature_info->rest_var = nullptr;

    // Create the parameters for the invoke function, based on the referenced function's signature
    for (auto *it : signature_ref->Params()) {
        auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
            VarBinder(), invoke_func->Scope()->ParamScope(), false);

        auto *param_ident = Allocator()->New<ir::Identifier>(it->Name(), Allocator());
        auto *param = Allocator()->New<ir::ETSParameterExpression>(param_ident, nullptr);
        auto [_, var] = VarBinder()->AddParamDecl(param);
        (void)_;
        var->SetTsType(it->TsType());
        param_ident->SetVariable(var);
        invoke_func->Params().push_back(param);
        invoke_signature_info->min_arg_count++;
        invoke_signature_info->params.push_back(var->AsLocalVariable());
    }

    // Create the function type for the constructor
    auto *invoke_signature = CreateSignature(invoke_signature_info, signature_ref->ReturnType(), invoke_func);
    invoke_signature->SetOwner(lambda_object_type);
    invoke_signature->AddSignatureFlag(checker::SignatureFlags::CALL);

    auto *invoke_type = CreateETSFunctionType(invoke_signature);
    invoke_func->SetSignature(invoke_signature);
    invoke_func->Id()->Variable()->SetTsType(invoke_type);
    VarBinder()->AsETSBinder()->BuildFunctionName(invoke_func);
    lambda_object_type->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invoke_func->Id()->Variable()->AsLocalVariable());

    // Fill out the type information for the body of the invoke function

    auto *resolved_lambda_invoke_function_body = ResolveLambdaObjectInvokeFuncBody(lambda_object, signature_ref);

    invoke_func->Body()->AsBlockStatement()->Statements().push_back(resolved_lambda_invoke_function_body);
    if (resolved_lambda_invoke_function_body->IsExpressionStatement()) {
        invoke_func->Body()->AsBlockStatement()->Statements().push_back(Allocator()->New<ir::ReturnStatement>(nullptr));
    }
}

ir::Statement *ETSChecker::ResolveLambdaObjectInvokeFuncBody(ir::ClassDefinition *lambda_object,
                                                             Signature *signature_ref)
{
    const auto &lambda_body = lambda_object->Body();
    bool is_static_reference = signature_ref->HasSignatureFlag(SignatureFlags::STATIC);
    ir::Identifier *field_ident {};
    ETSObjectType *field_prop_type {};

    // If this is a static function reference, we have to call the referenced function through the class itself
    if (is_static_reference) {
        field_ident = Allocator()->New<ir::Identifier>(signature_ref->Owner()->Name(), Allocator());
        field_prop_type = signature_ref->Owner();
        field_ident->SetVariable(signature_ref->Owner()->Variable());
        field_ident->SetTsType(field_prop_type);
    } else {
        // Otherwise, we should call the referenced function through the saved field, which hold the object instance
        // reference
        auto *field_prop = lambda_body[0]->AsClassProperty()->Key()->AsIdentifier()->Variable();
        field_prop_type = field_prop->TsType()->AsETSObjectType();
        field_ident = Allocator()->New<ir::Identifier>("field0", Allocator());
        field_ident->SetVariable(field_prop);
        field_ident->SetTsType(field_prop_type);
    }

    // Set the type information for the function reference call
    auto *func_ident = Allocator()->New<ir::Identifier>(signature_ref->Function()->Id()->Name(), Allocator());
    auto *callee = Allocator()->New<ir::MemberExpression>(field_ident, func_ident,
                                                          ir::MemberExpressionKind::ELEMENT_ACCESS, false, false);
    callee->SetPropVar(signature_ref->OwnerVar()->AsLocalVariable());
    callee->SetObjectType(field_prop_type);
    callee->SetTsType(signature_ref->OwnerVar()->TsType());

    // Create the parameters for the referenced function call
    auto *invoke_func = lambda_body[lambda_body.size() - 1]->AsMethodDefinition()->Function();
    ArenaVector<ir::Expression *> call_params(Allocator()->Adapter());
    for (size_t idx = 0; idx != signature_ref->Params().size(); idx++) {
        auto *param_ident = Allocator()->New<ir::Identifier>(signature_ref->Params()[idx]->Name(), Allocator());
        param_ident->SetVariable(invoke_func->Params()[idx]->AsETSParameterExpression()->Variable());
        param_ident->SetTsType(invoke_func->Params()[idx]->AsETSParameterExpression()->Variable()->TsType());
        call_params.push_back(param_ident);
    }

    // Create the synthetic call expression to the referenced function
    auto *resolved_call = Allocator()->New<ir::CallExpression>(callee, std::move(call_params), nullptr, false);
    resolved_call->SetTsType(signature_ref->ReturnType());
    resolved_call->SetSignature(signature_ref);

    if (signature_ref->ReturnType()->IsETSVoidType()) {
        return Allocator()->New<ir::ExpressionStatement>(resolved_call);
    }

    return Allocator()->New<ir::ReturnStatement>(resolved_call);
}

bool ETSChecker::AreOverrideEquivalent(Signature *const s1, Signature *const s2)
{
    // Two functions, methods or constructors M and N have the same signature if
    // their names and type parameters (if any) are the same, and their formal parameter
    // types are also the same (after the formal parameter types of N are adapted to the type parameters of M).
    // Signatures s1 and s2 are override-equivalent only if s1 and s2 are the same.

    return s1->Function()->Id()->Name() == s2->Function()->Id()->Name() && Relation()->IsIdenticalTo(s1, s2);
}

bool ETSChecker::IsReturnTypeSubstitutable(Signature *const s1, Signature *const s2)
{
    auto *const r1 = s1->ReturnType();
    auto *const r2 = s2->ReturnType();

    // A method declaration d1 with return type R1 is return-type-substitutable for another method d2 with return
    // type R2 if any of the following is true:

    // - If R1 is a primitive type then R2 is identical to R1.
    if (r1->HasTypeFlag(TypeFlag::ETS_PRIMITIVE | TypeFlag::ETS_ENUM | TypeFlag::ETS_STRING_ENUM)) {
        return Relation()->IsIdenticalTo(r2, r1);
    }

    // - If R1 is a reference type then R1, adapted to the type parameters of d2 (link to generic methods), is a
    // subtype of R2.
    ASSERT(r1->HasTypeFlag(TypeFlag::ETS_ARRAY_OR_OBJECT));
    r2->IsSupertypeOf(Relation(), r1);
    return Relation()->IsTrue();
}

std::string ETSChecker::GetAsyncImplName(const util::StringView &name)
{
    std::string impl_name(name);
    impl_name += "$asyncimpl";
    return impl_name;
}

std::string ETSChecker::GetAsyncImplName(ir::MethodDefinition *async_method)
{
    ir::Identifier *async_name = async_method->Function()->Id();
    ASSERT(async_name != nullptr);
    return GetAsyncImplName(async_name->Name());
}

ir::MethodDefinition *ETSChecker::CreateAsyncImplMethod(ir::MethodDefinition *async_method,
                                                        ir::ClassDefinition *class_def)
{
    util::UString impl_name(GetAsyncImplName(async_method), Allocator());
    ir::ModifierFlags modifiers = async_method->Modifiers();
    // clear ASYNC flag for implementation
    modifiers &= ~ir::ModifierFlags::ASYNC;
    ir::ScriptFunction *async_func = async_method->Function();
    ir::ScriptFunctionFlags flags = ir::ScriptFunctionFlags::METHOD;
    if (async_func->IsProxy()) {
        flags |= ir::ScriptFunctionFlags::PROXY;
    }
    async_method->AddModifier(ir::ModifierFlags::NATIVE);
    async_func->AddModifier(ir::ModifierFlags::NATIVE);
    // Create async_impl method copied from CreateInvokeFunction
    auto scope_ctx =
        varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), class_def->Scope()->AsClassScope());
    auto *body = async_func->Body();
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    varbinder::FunctionParamScope *param_scope = CopyParams(async_func->Params(), params);

    // Set impl method return type "Object" because it may return Promise as well as Promise parameter's type
    auto *object_id = Allocator()->New<ir::Identifier>(compiler::Signatures::BUILTIN_OBJECT_CLASS, Allocator());
    object_id->SetReference();
    VarBinder()->AsETSBinder()->LookupTypeReference(object_id, false);
    auto *return_type_ann =
        Allocator()->New<ir::ETSTypeReference>(Allocator()->New<ir::ETSTypeReferencePart>(object_id, nullptr, nullptr));
    object_id->SetParent(return_type_ann->Part());
    return_type_ann->Part()->SetParent(return_type_ann);
    auto *async_func_ret_type_ann = async_func->ReturnTypeAnnotation();
    auto *promise_type = [this](ir::TypeNode *type) {
        if (type != nullptr) {
            return GetTypeFromTypeAnnotation(type)->AsETSObjectType();
        }

        return GlobalBuiltinPromiseType()->AsETSObjectType();
    }(async_func_ret_type_ann);

    auto *ret_type = Allocator()->New<ETSAsyncFuncReturnType>(Allocator(), promise_type);
    return_type_ann->SetTsType(ret_type);

    ir::MethodDefinition *impl_method =
        CreateMethod(impl_name.View(), modifiers, flags, std::move(params), param_scope, return_type_ann, body);
    async_func->SetBody(nullptr);
    return_type_ann->SetParent(impl_method->Function());
    impl_method->SetParent(async_method->Parent());
    std::for_each(impl_method->Function()->Params().begin(), impl_method->Function()->Params().end(),
                  [impl_method](ir::Expression *param) { param->SetParent(impl_method->Function()); });
    return impl_method;
}

ir::MethodDefinition *ETSChecker::CreateAsyncProxy(ir::MethodDefinition *async_method, ir::ClassDefinition *class_def,
                                                   bool create_decl)
{
    ir::ScriptFunction *async_func = async_method->Function();
    VarBinder()->AsETSBinder()->GetRecordTable()->Signatures().push_back(async_func->Scope());

    ir::MethodDefinition *impl_method = CreateAsyncImplMethod(async_method, class_def);
    varbinder::FunctionScope *impl_func_scope = impl_method->Function()->Scope();
    for (auto *decl : async_func->Scope()->Decls()) {
        auto res = async_func->Scope()->Bindings().find(decl->Name());
        ASSERT(res != async_func->Scope()->Bindings().end());
        auto *const var = std::get<1>(*res);
        var->SetScope(impl_func_scope);
        impl_func_scope->Decls().push_back(decl);
        impl_func_scope->InsertBinding(decl->Name(), var);
    }
    for (const auto &entry : async_func->Scope()->Bindings()) {
        auto *var = entry.second;
        var->SetScope(impl_func_scope);
        impl_func_scope->InsertBinding(entry.first, entry.second);
    }
    ReplaceScope(impl_method->Function()->Body(), async_func, impl_func_scope);

    ArenaVector<varbinder::Variable *> captured(Allocator()->Adapter());

    bool is_static = async_method->IsStatic();
    if (create_decl) {
        if (is_static) {
            CreateLambdaFuncDecl(impl_method, class_def->Scope()->AsClassScope()->StaticMethodScope());
        } else {
            CreateLambdaFuncDecl(impl_method, class_def->Scope()->AsClassScope()->InstanceMethodScope());
        }
    }
    VarBinder()->AsETSBinder()->BuildProxyMethod(impl_method->Function(), class_def->InternalName(), is_static);
    impl_method->SetParent(async_method->Parent());

    return impl_method;
}

ir::MethodDefinition *ETSChecker::CreateMethod(const util::StringView &name, ir::ModifierFlags modifiers,
                                               ir::ScriptFunctionFlags flags, ArenaVector<ir::Expression *> &&params,
                                               varbinder::FunctionParamScope *param_scope, ir::TypeNode *return_type,
                                               ir::AstNode *body)
{
    auto *name_id = Allocator()->New<ir::Identifier>(name, Allocator());
    auto *scope = VarBinder()->Allocator()->New<varbinder::FunctionScope>(Allocator(), param_scope);
    ir::ScriptFunction *func =
        Allocator()->New<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), return_type), body,
                                             flags, modifiers, false, Language(Language::Id::ETS));
    func->SetScope(scope);
    func->SetIdent(name_id);
    body->SetParent(func);
    if (body->IsBlockStatement()) {
        body->AsBlockStatement()->SetScope(scope);
    }
    scope->BindNode(func);
    param_scope->BindNode(func);
    scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(scope);
    auto *func_expr = Allocator()->New<ir::FunctionExpression>(func);
    auto *method = Allocator()->New<ir::MethodDefinition>(ir::MethodDefinitionKind::METHOD, name_id, func_expr,
                                                          modifiers, Allocator(), false);
    func_expr->SetParent(method);
    func->SetParent(func_expr);
    name_id->SetParent(method);

    return method;
}

varbinder::FunctionParamScope *ETSChecker::CopyParams(const ArenaVector<ir::Expression *> &params,
                                                      ArenaVector<ir::Expression *> &out_params)
{
    auto param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());

    for (auto *const it : params) {
        auto *const param_old = it->AsETSParameterExpression();
        auto *const param_new = param_old->Clone(Allocator(), param_old->Parent())->AsETSParameterExpression();

        auto *const var = std::get<1>(VarBinder()->AddParamDecl(param_new));
        var->SetTsType(param_old->Ident()->Variable()->TsType());
        var->SetScope(param_ctx.GetScope());
        param_new->SetVariable(var);

        param_new->SetTsType(param_old->TsType());

        out_params.emplace_back(param_new);
    }

    return param_ctx.GetScope();
}

void ETSChecker::ReplaceScope(ir::AstNode *root, ir::AstNode *old_node, varbinder::Scope *new_scope)
{
    root->Iterate([this, old_node, new_scope](ir::AstNode *child) {
        auto *scope = NodeScope(child);
        if (scope != nullptr) {
            while (scope->Parent()->Node() != old_node) {
                scope = scope->Parent();
            }
            scope->SetParent(new_scope);
        } else {
            ReplaceScope(child, old_node, new_scope);
        }
    });
}

void ETSChecker::MoveTrailingBlockToEnclosingBlockStatement(ir::CallExpression *call_expr)
{
    if (call_expr == nullptr) {
        return;
    }

    ir::AstNode *parent = call_expr->Parent();
    ir::AstNode *current = call_expr;
    while (parent != nullptr) {
        if (!parent->IsBlockStatement()) {
            current = parent;
            parent = parent->Parent();
        } else {
            // Collect trailing block, insert it only when block statements traversal ends to avoid order mismatch.
            parent->AsBlockStatement()->AddTrailingBlock(current, call_expr->TrailingBlock());
            call_expr->TrailingBlock()->SetParent(parent);
            call_expr->SetTrailingBlock(nullptr);
            break;
        }
    }
}

void ETSChecker::TransformTraillingLambda(ir::CallExpression *call_expr)
{
    auto *trailing_block = call_expr->TrailingBlock();
    ASSERT(trailing_block != nullptr);

    auto *func_param_scope = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder()).GetScope();
    auto param_ctx =
        varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), func_param_scope, false);

    auto func_ctx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *func_scope = func_ctx.GetScope();
    func_scope->BindParamScope(func_param_scope);
    func_param_scope->BindFunctionScope(func_scope);
    func_param_scope->SetParent(trailing_block->Scope()->Parent());

    for (auto [_, var] : trailing_block->Scope()->Bindings()) {
        (void)_;
        if (var->GetScope() == trailing_block->Scope()) {
            var->SetScope(func_scope);
        }
    }
    func_scope->ReplaceBindings(trailing_block->Scope()->Bindings());

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    auto *func_node =
        AllocNode<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), nullptr), trailing_block,
                                      ir::ScriptFunctionFlags::ARROW, false, Language(Language::Id::ETS));
    func_node->SetScope(func_scope);
    func_scope->BindNode(func_node);
    func_param_scope->BindNode(func_node);

    trailing_block->SetScope(func_scope);
    ReplaceScope(func_node->Body(), trailing_block, func_scope);
    call_expr->SetTrailingBlock(nullptr);

    auto *arrow_func_node = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func_node);
    arrow_func_node->SetRange(trailing_block->Range());
    arrow_func_node->SetParent(call_expr);

    call_expr->Arguments().push_back(arrow_func_node);
}

ArenaVector<ir::Expression *> ETSChecker::ExtendArgumentsWithFakeLamda(ir::CallExpression *call_expr)
{
    auto func_ctx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *func_scope = func_ctx.GetScope();
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    body->SetScope(func_scope);

    auto *func_node = AllocNode<ir::ScriptFunction>(ir::FunctionSignature(nullptr, std::move(params), nullptr), body,
                                                    ir::ScriptFunctionFlags::ARROW, false, Language(Language::Id::ETS));
    func_node->SetScope(func_scope);
    func_scope->BindNode(func_node);
    auto *arrow_func_node = AllocNode<ir::ArrowFunctionExpression>(Allocator(), func_node);
    arrow_func_node->SetParent(call_expr);

    ArenaVector<ir::Expression *> fake_arguments = call_expr->Arguments();
    fake_arguments.push_back(arrow_func_node);
    return fake_arguments;
}

void ETSChecker::EnsureValidCurlyBrace(ir::CallExpression *call_expr)
{
    if (call_expr->TrailingBlock() == nullptr) {
        return;
    }

    if (call_expr->IsTrailingBlockInNewLine()) {
        MoveTrailingBlockToEnclosingBlockStatement(call_expr);
        return;
    }

    ThrowTypeError({"No matching call signature with trailing lambda"}, call_expr->Start());
}
}  // namespace panda::es2panda::checker
