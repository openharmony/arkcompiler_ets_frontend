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

#include "whileStatement.h"

#include "binder/scope.h"
#include "compiler/base/condition.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void WhileStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(body_);
}

void WhileStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "WhileStatement"}, {"test", test_}, {"body", body_}});
}

template <typename CodeGen>
void CompileImpl(const WhileStatement *while_stmt, [[maybe_unused]] CodeGen *cg)
{
    compiler::LabelTarget label_target(cg);

    cg->SetLabel(while_stmt, label_target.ContinueTarget());
    compiler::Condition::Compile(cg, while_stmt->Test(), label_target.BreakTarget());

    {
        compiler::LocalRegScope reg_scope(cg, while_stmt->Scope());
        compiler::LabelContext label_ctx(cg, label_target);
        while_stmt->Body()->Compile(cg);
    }

    cg->Branch(while_stmt, label_target.ContinueTarget());
    cg->SetLabel(while_stmt, label_target.BreakTarget());
}

void WhileStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    CompileImpl(this, pg);
}

void WhileStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    CompileImpl(this, etsg);
}

checker::Type *WhileStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    checker::Type *test_type = Test()->Check(checker);
    checker->CheckTruthinessOfType(test_type, Test()->Start());

    Body()->Check(checker);
    return nullptr;
}

checker::Type *WhileStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, Scope());

    checker->CheckTruthinessOfType(Test());

    Body()->Check(checker);
    return nullptr;
}
}  // namespace panda::es2panda::ir
