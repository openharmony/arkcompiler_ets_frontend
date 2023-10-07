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

#include "doWhileStatement.h"

#include "binder/scope.h"
#include "compiler/base/condition.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void DoWhileStatement::TransformChildren(const NodeTransformer &cb)
{
    body_ = cb(body_)->AsStatement();
    test_ = cb(test_)->AsExpression();
}

void DoWhileStatement::Iterate(const NodeTraverser &cb) const
{
    cb(body_);
    cb(test_);
}

void DoWhileStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "DoWhileStatement"}, {"body", body_}, {"test", test_}});
}

template <typename CodeGen>
void CompileImpl(const DoWhileStatement *self, [[maybe_unused]] CodeGen *cg)
{
    auto *start_label = cg->AllocLabel();
    compiler::LabelTarget label_target(cg);

    cg->SetLabel(self, start_label);

    {
        compiler::LocalRegScope reg_scope(cg, self->Scope());
        compiler::LabelContext label_ctx(cg, label_target);
        self->Body()->Compile(cg);
    }

    cg->SetLabel(self, label_target.ContinueTarget());
    compiler::Condition::Compile(cg, self->Test(), label_target.BreakTarget());

    cg->Branch(self, start_label);
    cg->SetLabel(self, label_target.BreakTarget());
}

void DoWhileStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    CompileImpl(this, pg);
}

void DoWhileStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    CompileImpl(this, etsg);
}

checker::Type *DoWhileStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    checker::Type *test_type = Test()->Check(checker);
    checker->CheckTruthinessOfType(test_type, Test()->Start());
    Body()->Check(checker);

    return nullptr;
}

checker::Type *DoWhileStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    checker->CheckTruthinessOfType(Test());
    Body()->Check(checker);

    return nullptr;
}
}  // namespace panda::es2panda::ir
