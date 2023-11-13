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

#include "tsNonNullExpression.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace panda::es2panda::ir {
void TSNonNullExpression::TransformChildren(const NodeTransformer &cb)
{
    expr_ = cb(expr_)->AsExpression();
}

void TSNonNullExpression::Iterate(const NodeTraverser &cb) const
{
    cb(expr_);
}

void TSNonNullExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSNonNullExpression"}, {"expression", expr_}});
}

void TSNonNullExpression::Dump(ir::SrcDumper *dumper) const
{
    ASSERT(expr_ != nullptr);
    expr_->Dump(dumper);
    dumper->Add("!");
}

void TSNonNullExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TSNonNullExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TSNonNullExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TSNonNullExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
