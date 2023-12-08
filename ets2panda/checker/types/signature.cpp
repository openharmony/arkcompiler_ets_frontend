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

#include "signature.h"

#include "varbinder/scope.h"
#include "ir/base/scriptFunction.h"
#include "ir/ts/tsTypeParameter.h"
#include "checker/ETSchecker.h"

namespace panda::es2panda::checker {

util::StringView Signature::InternalName() const
{
    return internal_name_.Empty() ? func_->Scope()->InternalName() : internal_name_;
}

Signature *Signature::Substitute(TypeRelation *relation, const Substitution *substitution)
{
    if (substitution == nullptr || substitution->empty()) {
        return this;
    }
    auto *checker = relation->GetChecker()->AsETSChecker();
    auto *allocator = checker->Allocator();
    bool any_change = false;
    SignatureInfo *new_sig_info = allocator->New<SignatureInfo>(allocator);
    const Substitution *new_substitution = substitution;

    if (!signature_info_->type_params.empty()) {
        auto *new_substitution_seed = checker->CopySubstitution(substitution);
        for (auto *tparam : signature_info_->type_params) {
            auto *new_tparam = tparam->Substitute(relation, new_substitution_seed);
            new_sig_info->type_params.push_back(new_tparam);
            if (new_tparam != tparam) {
                any_change = true;
                if (tparam->IsETSTypeParameter()) {
                    new_substitution_seed->insert({tparam->AsETSTypeParameter(), new_tparam});
                }
            }
        }
        new_substitution = new_substitution_seed;
    }
    new_sig_info->min_arg_count = signature_info_->min_arg_count;

    for (auto *param : signature_info_->params) {
        auto *new_param = param;
        auto *new_param_type = param->TsType()->Substitute(relation, new_substitution);
        if (new_param_type != param->TsType()) {
            any_change = true;
            new_param = param->Copy(allocator, param->Declaration());
            new_param->SetTsType(new_param_type);
        }
        new_sig_info->params.push_back(new_param);
    }

    if (signature_info_->rest_var != nullptr) {
        auto *new_rest_type = signature_info_->rest_var->TsType()->Substitute(relation, new_substitution);
        if (new_rest_type != signature_info_->rest_var->TsType()) {
            any_change = true;
            new_sig_info->rest_var =
                signature_info_->rest_var->Copy(allocator, signature_info_->rest_var->Declaration());
            new_sig_info->rest_var->SetTsType(new_rest_type);
        }
    }

    if (!any_change) {
        new_sig_info = signature_info_;
    }

    auto *new_return_type = return_type_->Substitute(relation, new_substitution);
    if (new_return_type != return_type_) {
        any_change = true;
    }
    if (!any_change) {
        return this;
    }
    auto *result = allocator->New<Signature>(new_sig_info, new_return_type);
    result->func_ = func_;
    result->flags_ = flags_;
    result->internal_name_ = internal_name_;
    result->owner_obj_ = owner_obj_;
    result->owner_var_ = owner_var_;

    return result;
}

Signature *Signature::Copy(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types)
{
    SignatureInfo *copied_info = allocator->New<SignatureInfo>(signature_info_, allocator);

    for (size_t idx = 0; idx < signature_info_->params.size(); idx++) {
        auto *const param_type = signature_info_->params[idx]->TsType();
        if (param_type->HasTypeFlag(TypeFlag::GENERIC) && param_type->IsETSObjectType()) {
            copied_info->params[idx]->SetTsType(param_type->Instantiate(allocator, relation, global_types));
            auto original_type_args = param_type->AsETSObjectType()->GetOriginalBaseType()->TypeArguments();
            copied_info->params[idx]->TsType()->AsETSObjectType()->SetTypeArguments(std::move(original_type_args));
        } else {
            copied_info->params[idx]->SetTsType(
                ETSChecker::TryToInstantiate(param_type, allocator, relation, global_types));
        }
    }

    auto *const copied_signature = allocator->New<Signature>(copied_info, return_type_, func_);
    copied_signature->flags_ = flags_;
    copied_signature->internal_name_ = internal_name_;
    copied_signature->owner_obj_ = owner_obj_;
    copied_signature->owner_var_ = owner_var_;

    return copied_signature;
}

void Signature::ToString(std::stringstream &ss, const varbinder::Variable *variable, bool print_as_method) const
{
    if (!signature_info_->type_params.empty()) {
        ss << "<";
        for (auto it = signature_info_->type_params.begin(); it != signature_info_->type_params.end(); ++it) {
            (*it)->ToString(ss);
            if (std::next(it) != signature_info_->type_params.end()) {
                ss << ", ";
            }
        }
        ss << ">";
    }

    ss << "(";

    for (auto it = signature_info_->params.begin(); it != signature_info_->params.end(); it++) {
        ss << (*it)->Name();

        if ((*it)->HasFlag(varbinder::VariableFlags::OPTIONAL)) {
            ss << "?";
        }

        ss << ": ";

        (*it)->TsType()->ToString(ss);

        if (std::next(it) != signature_info_->params.end()) {
            ss << ", ";
        }
    }

    if (signature_info_->rest_var != nullptr) {
        if (!signature_info_->params.empty()) {
            ss << ", ";
        }

        ss << "...";
        ss << signature_info_->rest_var->Name();
        ss << ": ";
        signature_info_->rest_var->TsType()->ToString(ss);
        ss << "[]";
    }

    ss << ")";

    if (print_as_method || (variable != nullptr && variable->HasFlag(varbinder::VariableFlags::METHOD))) {
        ss << ": ";
    } else {
        ss << " => ";
    }

    return_type_->ToString(ss);
}

namespace {
std::size_t GetToCheckParamCount(Signature *signature, bool is_ets)
{
    auto param_number = static_cast<ssize_t>(signature->Params().size());
    if (!is_ets || signature->Function() == nullptr) {
        return param_number;
    }
    for (auto i = param_number - 1; i >= 0; i--) {
        if (!signature->Function()->Params()[i]->AsETSParameterExpression()->IsDefault()) {
            return static_cast<std::size_t>(i + 1);
        }
    }
    return 0;
}
}  // namespace

bool Signature::IdenticalParameter(TypeRelation *relation, Type *type1, Type *type2)
{
    if (!CheckFunctionalInterfaces(relation, type1, type2)) {
        relation->IsIdenticalTo(type1, type2);
    }
    return relation->IsTrue();
}

void Signature::Identical(TypeRelation *relation, Signature *other)
{
    bool is_ets = relation->GetChecker()->IsETSChecker();
    auto const this_to_check_parameters_number = GetToCheckParamCount(this, is_ets);
    auto const other_to_check_parameters_number = GetToCheckParamCount(other, is_ets);
    if ((this_to_check_parameters_number != other_to_check_parameters_number ||
         this->MinArgCount() != other->MinArgCount()) &&
        this->RestVar() == nullptr && other->RestVar() == nullptr) {
        // skip check for ets cases only when all parameters are mandatory
        if (!is_ets || (this_to_check_parameters_number == this->Params().size() &&
                        other_to_check_parameters_number == other->Params().size())) {
            relation->Result(false);
            return;
        }
    }

    if (relation->NoReturnTypeCheck()) {
        relation->Result(true);
    } else {
        relation->IsIdenticalTo(this->ReturnType(), other->ReturnType());
    }

    if (relation->IsTrue()) {
        /* In ETS, the functions "foo(a: int)" and "foo(a: int, b: int = 1)" should be considered as having an
           equivalent signature. Hence, we only need to check if the mandatory parameters of the signature with
           more mandatory parameters can match the parameters of the other signature (including the optional
           parameter or rest parameters) here.

           XXX_to_check_parameters_number is calculated beforehand by counting mandatory parameters.
           Signature::params() stores all parameters (mandatory and optional), excluding the rest parameter.
           Signature::restVar() stores the rest parameters of the function.

           For example:
           foo(a: int): params().size: 1, to_check_param_number: 1, restVar: nullptr
           foo(a: int, b: int = 0): params().size: 2, to_check_param_number: 1, restVar: nullptr
           foo(a: int, ...b: int[]): params().size: 1, to_check_param_number: 1, restVar: ...b: int[]

           Note that optional parameters always come after mandatory parameters, and signatures containing both
           optional and rest parameters are not allowed.

           "to_check_parameters_number" is the number of parameters that need to be checked to ensure identical.
           "parameters_number" is the number of parameters that can be checked in Signature::params().
        */
        auto const to_check_parameters_number =
            std::max(this_to_check_parameters_number, other_to_check_parameters_number);
        auto const parameters_number =
            std::min({this->Params().size(), other->Params().size(), to_check_parameters_number});

        std::size_t i = 0U;
        for (; i < parameters_number; ++i) {
            if (!IdenticalParameter(relation, this->Params()[i]->TsType(), other->Params()[i]->TsType())) {
                return;
            }
        }

        /* "i" could be one of the following three cases:
            1. == to_check_parameters_number, we have finished the checking and can directly return.
            2. == other->Params().size(), must be < this_to_check_parameters_number in this case since
            xxx->Params().size() always >= xxx_to_check_parameters_number. We need to check the remaining
            mandatory parameters of "this" against ths RestVar of "other".
            3. == this->Params().size(), must be < other_to_check_parameters_number as described in 2, and
            we need to check the remaining mandatory parameters of "other" against the RestVar of "this".
        */
        if (i == to_check_parameters_number) {
            return;
        }
        bool is_other_mandatory_params_matched = i < this_to_check_parameters_number;
        ArenaVector<varbinder::LocalVariable *> const &parameters =
            is_other_mandatory_params_matched ? this->Params() : other->Params();
        varbinder::LocalVariable const *rest_parameter =
            is_other_mandatory_params_matched ? other->RestVar() : this->RestVar();
        if (rest_parameter == nullptr) {
            relation->Result(false);
            return;
        }
        auto *const rest_parameter_type = rest_parameter->TsType()->AsETSArrayType()->ElementType();
        for (; i < to_check_parameters_number; ++i) {
            if (!IdenticalParameter(relation, parameters[i]->TsType(), rest_parameter_type)) {
                return;
            }
        }
    }
}

bool Signature::CheckFunctionalInterfaces(TypeRelation *relation, Type *source, Type *target)
{
    if (!source->IsETSObjectType() || !source->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        return false;
    }

    if (!target->IsETSObjectType() || !target->AsETSObjectType()->HasObjectFlag(ETSObjectFlags::FUNCTIONAL)) {
        return false;
    }

    auto source_invoke_func = source->AsETSObjectType()
                                  ->GetProperty(util::StringView("invoke"), PropertySearchFlags::SEARCH_INSTANCE_METHOD)
                                  ->TsType()
                                  ->AsETSFunctionType()
                                  ->CallSignatures()[0];

    auto target_invoke_func = target->AsETSObjectType()
                                  ->GetProperty(util::StringView("invoke"), PropertySearchFlags::SEARCH_INSTANCE_METHOD)
                                  ->TsType()
                                  ->AsETSFunctionType()
                                  ->CallSignatures()[0];

    relation->IsIdenticalTo(source_invoke_func, target_invoke_func);
    return true;
}

void Signature::AssignmentTarget(TypeRelation *relation, Signature *source)
{
    if (signature_info_->rest_var == nullptr &&
        (source->Params().size() - source->OptionalArgCount()) > signature_info_->params.size()) {
        relation->Result(false);
        return;
    }

    for (size_t i = 0; i < source->Params().size(); i++) {
        if (signature_info_->rest_var == nullptr && i >= Params().size()) {
            break;
        }

        if (signature_info_->rest_var != nullptr) {
            relation->IsAssignableTo(source->Params()[i]->TsType(), signature_info_->rest_var->TsType());

            if (!relation->IsTrue()) {
                return;
            }

            continue;
        }

        relation->IsAssignableTo(source->Params()[i]->TsType(), Params()[i]->TsType());

        if (!relation->IsTrue()) {
            return;
        }
    }

    relation->IsAssignableTo(source->ReturnType(), return_type_);

    if (relation->IsTrue() && signature_info_->rest_var != nullptr && source->RestVar() != nullptr) {
        relation->IsAssignableTo(source->RestVar()->TsType(), signature_info_->rest_var->TsType());
    }
}
}  // namespace panda::es2panda::checker
