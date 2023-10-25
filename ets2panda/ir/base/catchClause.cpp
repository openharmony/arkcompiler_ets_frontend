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

#include "catchClause.h"

#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/blockStatement.h"

namespace panda::es2panda::ir {
void CatchClause::TransformChildren(const NodeTransformer &cb)
{
    if (param_ != nullptr) {
        param_ = cb(param_)->AsExpression();
    }

    body_ = cb(body_)->AsBlockStatement();
}

void CatchClause::Iterate(const NodeTraverser &cb) const
{
    if (param_ != nullptr) {
        cb(param_);
    }

    cb(body_);
}

void CatchClause::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "CatchClause"}, {"body", body_}, {"param", AstDumper::Nullable(param_)}});
}

bool CatchClause::IsDefaultCatchClause() const
{
    return param_->AsIdentifier()->TypeAnnotation() == nullptr;
}

void CatchClause::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void CatchClause::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *CatchClause::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *CatchClause::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
