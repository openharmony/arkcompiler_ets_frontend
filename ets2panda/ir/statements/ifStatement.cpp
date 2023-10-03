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

#include "ifStatement.h"

#include "compiler/base/condition.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void IfStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(consequent_);

    if (alternate_ != nullptr) {
        cb(alternate_);
    }
}

void IfStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "IfStatement"},
                 {"test", test_},
                 {"consequent", consequent_},
                 {"alternate", AstDumper::Nullable(alternate_)}});
}

void IfStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    auto *consequent_end = pg->AllocLabel();
    compiler::Label *statement_end = consequent_end;

    compiler::Condition::Compile(pg, test_, consequent_end);
    consequent_->Compile(pg);

    if (alternate_ != nullptr) {
        statement_end = pg->AllocLabel();
        pg->Branch(pg->Insns().back()->Node(), statement_end);

        pg->SetLabel(this, consequent_end);
        alternate_->Compile(pg);
    }

    pg->SetLabel(this, statement_end);
}

void IfStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    auto res = compiler::Condition::CheckConstantExpr(test_);

    if (res == compiler::Condition::Result::CONST_TRUE) {
        consequent_->Compile(etsg);
        return;
    }

    if (res == compiler::Condition::Result::CONST_FALSE) {
        if (alternate_ != nullptr) {
            alternate_->Compile(etsg);
        }
        return;
    }

    auto *consequent_end = etsg->AllocLabel();
    compiler::Label *statement_end = consequent_end;

    compiler::Condition::Compile(etsg, test_, consequent_end);

    consequent_->Compile(etsg);

    if (alternate_ != nullptr) {
        statement_end = etsg->AllocLabel();
        etsg->Branch(etsg->Insns().back()->Node(), statement_end);

        etsg->SetLabel(this, consequent_end);
        alternate_->Compile(etsg);
    }

    etsg->SetLabel(this, statement_end);
}

checker::Type *IfStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::Type *test_type = test_->Check(checker);
    checker->CheckTruthinessOfType(test_type, Start());
    checker->CheckTestingKnownTruthyCallableOrAwaitableType(test_, test_type, consequent_);

    consequent_->Check(checker);

    if (alternate_ != nullptr) {
        alternate_->Check(checker);
    }

    return nullptr;
}

checker::Type *IfStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker->CheckTruthinessOfType(test_);

    consequent_->Check(checker);

    if (alternate_ != nullptr) {
        alternate_->Check(checker);
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
