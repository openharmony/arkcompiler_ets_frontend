/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "assertStatement.h"

#include "varbinder/ETSBinder.h"
#include "compiler/base/condition.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/expression.h"

namespace panda::es2panda::ir {
void AssertStatement::TransformChildren(const NodeTransformer &cb)
{
    test_ = cb(test_)->AsExpression();

    if (second_ != nullptr) {
        second_ = cb(second_)->AsExpression();
    }
}

void AssertStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);

    if (second_ != nullptr) {
        cb(second_);
    }
}

void AssertStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "AssertStatement"}, {"test", test_}, {"second", AstDumper::Nullish(second_)}});
}

void AssertStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void AssertStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *AssertStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *AssertStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
