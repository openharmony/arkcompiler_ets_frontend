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

#include "varbinder/scope.h"
#include "compiler/base/condition.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void WhileStatement::TransformChildren(const NodeTransformer &cb)
{
    test_ = cb(test_)->AsExpression();
    body_ = cb(body_)->AsStatement();
}

void WhileStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(body_);
}

void WhileStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "WhileStatement"}, {"test", test_}, {"body", body_}});
}

void WhileStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("while (");
    if (test_ != nullptr) {
        test_->Dump(dumper);
    }
    dumper->Add(") {");
    if (body_ != nullptr) {
        dumper->IncrIndent();
        dumper->Endl();
        body_->Dump(dumper);
        dumper->DecrIndent();
        dumper->Endl();
    }
    dumper->Add("}");
}

void WhileStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void WhileStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *WhileStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *WhileStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
