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

#include "functionExpression.h"

#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/variableDeclarator.h"

namespace panda::es2panda::ir {
void FunctionExpression::Iterate(const NodeTraverser &cb) const
{
    cb(func_);
}

void FunctionExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "FunctionExpression"}, {"function", func_}});
}

void FunctionExpression::Compile(compiler::PandaGen *pg) const
{
    pg->DefineFunction(func_, func_, func_->Scope()->InternalName());
}

void FunctionExpression::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *FunctionExpression::Check(checker::TSChecker *checker)
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

    func_->Body()->Check(checker);

    return func_type;
}

checker::Type *FunctionExpression::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
