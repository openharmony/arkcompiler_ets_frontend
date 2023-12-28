/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "switchCaseStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
void SwitchCaseStatement::TransformChildren(const NodeTransformer &cb)
{
    if (test_ != nullptr) {
        test_ = cb(test_)->AsExpression();
    }

    for (auto *&it : consequent_) {
        it = cb(it)->AsStatement();
    }
}

void SwitchCaseStatement::Iterate(const NodeTraverser &cb) const
{
    if (test_ != nullptr) {
        cb(test_);
    }

    for (auto *it : consequent_) {
        cb(it);
    }
}

void SwitchCaseStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "SwitchCase"}, {"test", AstDumper::Nullish(test_)}, {"consequent", consequent_}});
}

void SwitchCaseStatement::Dump(ir::SrcDumper *dumper) const
{
    if (test_ != nullptr) {
        dumper->Add("case ");
        test_->Dump(dumper);
        dumper->Add(":");
    } else {
        dumper->Add("default:");
    }
    if (!consequent_.empty()) {
        dumper->IncrIndent();
        dumper->Endl();
        for (auto cs : consequent_) {
            cs->Dump(dumper);
        }
        dumper->DecrIndent();
    }
}

void SwitchCaseStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void SwitchCaseStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *SwitchCaseStatement::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *SwitchCaseStatement::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
