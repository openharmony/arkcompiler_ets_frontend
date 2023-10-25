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

#include "etsFunctionType.h"

#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/types/signature.h"
#include "ir/astDump.h"
#include "ir/base/spreadElement.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ets/etsParameterExpression.h"

namespace panda::es2panda::ir {
void ETSFunctionType::TransformChildren(const NodeTransformer &cb)
{
    if (type_params_ != nullptr) {
        type_params_ = cb(type_params_)->AsTSTypeParameterDeclaration();
    }

    for (auto *&it : params_) {
        it = cb(it)->AsExpression();
    }

    if (return_type_ != nullptr) {
        return_type_ = static_cast<TypeNode *>(cb(return_type_));
    }
}

void ETSFunctionType::Iterate(const NodeTraverser &cb) const
{
    if (type_params_ != nullptr) {
        cb(type_params_);
    }

    for (auto *it : params_) {
        cb(it);
    }

    if (return_type_ != nullptr) {
        cb(return_type_);
    }
}

void ETSFunctionType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSFunctionType"},
                 {"params", params_},
                 {"typeParameters", AstDumper::Optional(type_params_)},
                 {"returnType", return_type_}});

    if (IsThrowing()) {
        dumper->Add({"throwMarker", "throws"});
    }
}

void ETSFunctionType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *ETSFunctionType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSFunctionType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSFunctionType::Check(checker::ETSChecker *checker)
{
    checker->CreateFunctionalInterfaceForFunctionType(this);
    auto *interface_type = checker->CreateETSObjectType(functional_interface_->Id()->Name(), functional_interface_,
                                                        checker::ETSObjectFlags::FUNCTIONAL_INTERFACE);
    interface_type->SetSuperType(checker->GlobalETSObjectType());

    auto *invoke_func = functional_interface_->Body()->Body()[0]->AsMethodDefinition()->Function();
    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());

    for (auto *it : invoke_func->Params()) {
        auto *const param = it->AsETSParameterExpression();
        if (param->IsRestParameter()) {
            auto *rest_ident = param->Ident();

            ASSERT(rest_ident->Variable());
            signature_info->rest_var = rest_ident->Variable()->AsLocalVariable();

            ASSERT(param->TypeAnnotation());
            signature_info->rest_var->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));

            auto array_type = signature_info->rest_var->TsType()->AsETSArrayType();
            checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
        } else {
            auto *param_ident = param->Ident();

            ASSERT(param_ident->Variable());
            binder::Variable *param_var = param_ident->Variable();

            ASSERT(param->TypeAnnotation());
            param_var->SetTsType(checker->GetTypeFromTypeAnnotation(param->TypeAnnotation()));
            signature_info->params.push_back(param_var->AsLocalVariable());
            ++signature_info->min_arg_count;
        }
    }

    invoke_func->ReturnTypeAnnotation()->Check(checker);
    auto *signature =
        checker->Allocator()->New<checker::Signature>(signature_info, return_type_->GetType(checker), invoke_func);
    signature->SetOwnerVar(invoke_func->Id()->Variable()->AsLocalVariable());
    signature->AddSignatureFlag(checker::SignatureFlags::FUNCTIONAL_INTERFACE_SIGNATURE);
    signature->SetOwner(interface_type);

    auto *func_type = checker->CreateETSFunctionType(signature);
    invoke_func->SetSignature(signature);
    invoke_func->Id()->Variable()->SetTsType(func_type);
    interface_type->AddProperty<checker::PropertyType::INSTANCE_METHOD>(
        invoke_func->Id()->Variable()->AsLocalVariable());
    functional_interface_->SetTsType(interface_type);

    auto *this_var = invoke_func->Scope()->ParamScope()->Params().front();
    this_var->SetTsType(interface_type);
    checker->BuildFunctionalInterfaceName(this);

    ts_type_ = interface_type;
    return interface_type;
}

checker::Type *ETSFunctionType::GetType(checker::ETSChecker *checker)
{
    return Check(checker);
}
}  // namespace panda::es2panda::ir
