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

#include "forInStatement.h"

#include "varbinder/scope.h"
#include "compiler/base/lreference.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ForInStatement::TransformChildren(const NodeTransformer &cb)
{
    left_ = cb(left_);
    right_ = cb(right_)->AsExpression();
    body_ = cb(body_)->AsStatement();
}

void ForInStatement::Iterate(const NodeTraverser &cb) const
{
    cb(left_);
    cb(right_);
    cb(body_);
}

void ForInStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ForInStatement"}, {"left", left_}, {"right", right_}, {"body", body_}});
}

void ForInStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ForInStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ForInStatement::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ForInStatement::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
