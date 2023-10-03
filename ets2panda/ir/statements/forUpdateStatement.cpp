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

#include "forUpdateStatement.h"

#include "binder/scope.h"
#include "compiler/base/condition.h"
#include "compiler/base/lreference.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/dynamicContext.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void ForUpdateStatement::Iterate(const NodeTraverser &cb) const
{
    if (init_ != nullptr) {
        cb(init_);
    }
    if (test_ != nullptr) {
        cb(test_);
    }
    if (update_ != nullptr) {
        cb(update_);
    }

    cb(body_);
}

void ForUpdateStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ForUpdateStatement"},
                 {"init", AstDumper::Nullable(init_)},
                 {"test", AstDumper::Nullable(test_)},
                 {"update", AstDumper::Nullable(update_)},
                 {"body", body_}});
}

void ForUpdateStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    compiler::LocalRegScope decl_reg_scope(pg, Scope()->DeclScope()->InitScope());

    if (init_ != nullptr) {
        ASSERT(init_->IsVariableDeclaration() || init_->IsExpression());
        init_->Compile(pg);
    }

    auto *start_label = pg->AllocLabel();
    compiler::LabelTarget label_target(pg);

    compiler::LoopEnvScope decl_env_scope(pg, Scope()->DeclScope());
    compiler::LoopEnvScope env_scope(pg, label_target, Scope());
    pg->SetLabel(this, start_label);

    {
        compiler::LocalRegScope reg_scope(pg, Scope());

        if (test_ != nullptr) {
            compiler::Condition::Compile(pg, test_, label_target.BreakTarget());
        }

        body_->Compile(pg);
        pg->SetLabel(this, label_target.ContinueTarget());
        env_scope.CopyPetIterationCtx();
    }

    if (update_ != nullptr) {
        update_->Compile(pg);
    }

    pg->Branch(this, start_label);
    pg->SetLabel(this, label_target.BreakTarget());
}

void ForUpdateStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    compiler::LocalRegScope decl_reg_scope(etsg, Scope()->DeclScope()->InitScope());

    if (init_ != nullptr) {
        ASSERT(init_->IsVariableDeclaration() || init_->IsExpression());
        init_->Compile(etsg);
    }

    auto *start_label = etsg->AllocLabel();
    compiler::LabelTarget label_target(etsg);
    auto label_ctx = compiler::LabelContext(etsg, label_target);
    etsg->SetLabel(this, start_label);

    {
        compiler::LocalRegScope reg_scope(etsg, Scope());

        if (test_ != nullptr) {
            compiler::Condition::Compile(etsg, test_, label_target.BreakTarget());
        }

        body_->Compile(etsg);
        etsg->SetLabel(this, label_target.ContinueTarget());
    }

    if (update_ != nullptr) {
        update_->Compile(etsg);
    }

    etsg->Branch(this, start_label);
    etsg->SetLabel(this, label_target.BreakTarget());
}

checker::Type *ForUpdateStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    if (init_ != nullptr) {
        init_->Check(checker);
    }

    if (test_ != nullptr) {
        checker::Type *test_type = test_->Check(checker);
        checker->CheckTruthinessOfType(test_type, Start());
    }

    if (update_ != nullptr) {
        update_->Check(checker);
    }

    body_->Check(checker);

    return nullptr;
}

checker::Type *ForUpdateStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    if (init_ != nullptr) {
        init_->Check(checker);
    }

    if (test_ != nullptr) {
        checker->CheckTruthinessOfType(test_);
    }

    if (update_ != nullptr) {
        update_->Check(checker);
    }

    body_->Check(checker);

    return nullptr;
}
}  // namespace panda::es2panda::ir
