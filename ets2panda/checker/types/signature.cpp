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

#include "signature.h"

#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"

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
                new_substitution_seed->insert({tparam, new_tparam});
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
            auto original_type_args = relation->GetChecker()
                                          ->AsETSChecker()
                                          ->GetOriginalBaseType(param_type->AsETSObjectType())
                                          ->TypeArguments();
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

void Signature::ToString(std::stringstream &ss, const binder::Variable *variable, bool print_as_method) const
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

        if ((*it)->HasFlag(binder::VariableFlags::OPTIONAL)) {
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

    if (print_as_method || (variable != nullptr && variable->HasFlag(binder::VariableFlags::METHOD))) {
        ss << ": ";
    } else {
        ss << " => ";
    }

    return_type_->ToString(ss);
}

void Signature::Identical(TypeRelation *relation, Signature *other)
{
    if (signature_info_->min_arg_count != other->MinArgCount() ||
        signature_info_->params.size() != other->Params().size()) {
        relation->Result(false);
        return;
    }

    if (relation->NoReturnTypeCheck()) {
        relation->Result(true);
    } else {
        relation->IsIdenticalTo(return_type_, other->ReturnType());
    }

    if (relation->IsTrue()) {
        for (uint64_t i = 0; i < signature_info_->params.size(); i++) {
            auto *const this_sig_param_type = signature_info_->params[i]->TsType();
            auto *const other_sig_param_type = other->Params()[i]->TsType();
            if (!CheckFunctionalInterfaces(relation, this_sig_param_type, other_sig_param_type)) {
                relation->IsIdenticalTo(this_sig_param_type, other_sig_param_type);
            }

            if (!relation->IsTrue()) {
                return;
            }
        }

        if (signature_info_->rest_var != nullptr && other->RestVar() != nullptr) {
            relation->IsIdenticalTo(signature_info_->rest_var->TsType(), other->RestVar()->TsType());
        } else if ((signature_info_->rest_var != nullptr && other->RestVar() == nullptr) ||
                   (signature_info_->rest_var == nullptr && other->RestVar() != nullptr)) {
            relation->Result(false);
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
