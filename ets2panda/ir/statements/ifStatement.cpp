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
#include <cstddef>

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
void IfStatement::TransformChildren(const NodeTransformer &cb)
{
    test_ = cb(test_)->AsExpression();
    consequent_ = cb(consequent_)->AsStatement();

    if (alternate_ != nullptr) {
        alternate_ = cb(alternate_)->AsStatement();
    }
}

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
                 {"alternate", AstDumper::Nullish(alternate_)}});
}

void IfStatement::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(test_);
    dumper->Add("if (");
    test_->Dump(dumper);
    dumper->Add(") {");
    if (consequent_ != nullptr) {
        dumper->IncrIndent();
        dumper->Endl();
        dumper->DecrIndent();
        consequent_->Dump(dumper);
        dumper->Endl();
    }
    dumper->Add("}");
    if (alternate_ != nullptr) {
        dumper->Add(" else ");
        if (alternate_->IsBlockStatement()) {
            dumper->Add("{");
            dumper->IncrIndent();
            dumper->Endl();
            dumper->DecrIndent();
            alternate_->Dump(dumper);
            dumper->Endl();
            dumper->Add("}");
        } else {
            alternate_->Dump(dumper);
        }
    }
}

void IfStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void IfStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *IfStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *IfStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
