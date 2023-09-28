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

#include "arrowFunctionExpression.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/thisExpression.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"

namespace panda::es2panda::ir {
void ArrowFunctionExpression::Iterate(const NodeTraverser &cb) const
{
    cb(func_);
}

void ArrowFunctionExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ArrowFunctionExpression"}, {"function", func_}});
}

void ArrowFunctionExpression::Compile(compiler::PandaGen *pg) const
{
    pg->DefineFunction(func_, func_, func_->Scope()->InternalName());
}

void ArrowFunctionExpression::Compile(compiler::ETSGen *etsg) const
{
    auto *ctor = resolved_lambda_->TsType()->AsETSObjectType()->ConstructSignatures()[0];
    std::vector<compiler::VReg> arguments;

    for (auto *it : captured_vars_) {
        if (it->HasFlag(binder::VariableFlags::LOCAL)) {
            arguments.push_back(it->AsLocalVariable()->Vreg());
        }
    }

    if (propagate_this_) {
        arguments.push_back(etsg->GetThisReg());
    }

    etsg->InitLambdaObject(this, ctor, arguments);
    etsg->SetAccumulatorType(resolved_lambda_->TsType());
}

checker::Type *ArrowFunctionExpression::Check(checker::TSChecker *checker)
{
    binder::Variable *func_var = nullptr;

    if (func_->Parent()->Parent() != nullptr && func_->Parent()->Parent()->IsVariableDeclarator() &&
        func_->Parent()->Parent()->AsVariableDeclarator()->Id()->IsIdentifier()) {
        func_var = func_->Parent()->Parent()->AsVariableDeclarator()->Id()->AsIdentifier()->Variable();
    }

    checker::ScopeContext scope_ctx(checker, func_->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(func_->Params(), signature_info);

    auto *signature =
        checker->Allocator()->New<checker::Signature>(signature_info, checker->GlobalResolvingReturnType(), func_);
    checker::Type *func_type = checker->CreateFunctionTypeWithSignature(signature);

    if (func_var != nullptr && func_var->TsType() == nullptr) {
        func_var->SetTsType(func_type);
    }

    signature->SetReturnType(checker->HandleFunctionReturn(func_));

    if (!func_->Body()->IsExpression()) {
        func_->Body()->Check(checker);
    }

    return func_type;
}

checker::Type *ArrowFunctionExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    auto *func_type = checker->BuildFunctionSignature(func_, false);

    if (Function()->IsAsyncFunc()) {
        auto *ret_type = static_cast<checker::ETSObjectType *>(Function()->Signature()->ReturnType());
        if (ret_type->AssemblerName() != checker->GlobalBuiltinPromiseType()->AssemblerName()) {
            checker->ThrowTypeError("Return type of async lambda must be 'Promise'", Function()->Start());
        }
    }

    checker::ScopeContext scope_ctx(checker, func_->Scope());
    checker::SavedCheckerContext saved_context(checker, checker->Context().Status(),
                                               checker->Context().ContainingClass());
    checker->AddStatus(checker::CheckerStatus::IN_LAMBDA);
    checker->Context().SetContainingSignature(func_type->CallSignatures()[0]);

    auto *body_type = func_->Body()->Check(checker);

    if (func_->Body()->IsExpression()) {
        checker::AssignmentContext(
            checker->Relation(), func_->Body()->AsExpression(), body_type, func_type->CallSignatures()[0]->ReturnType(),
            func_->Start(),
            {"Return statements return type is not compatible with the containing functions return type"},
            checker::TypeRelationFlag::DIRECT_RETURN);
    }

    checker->Context().SetContainingSignature(nullptr);
    checker->CheckCapturedVariables();

    for (auto [var, _] : checker->Context().CapturedVars()) {
        (void)_;
        captured_vars_.push_back(var);
    }

    SetTsType(func_type);
    return TsType();
}
}  // namespace panda::es2panda::ir
