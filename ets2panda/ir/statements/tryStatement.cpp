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

#include "tryStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/dynamicContext.h"
#include "compiler/base/catchTable.h"
#include "ir/astDump.h"
#include "ir/base/catchClause.h"
#include "ir/statements/blockStatement.h"

namespace panda::es2panda::ir {
void TryStatement::TransformChildren(const NodeTransformer &cb)
{
    block_ = cb(block_)->AsBlockStatement();

    for (auto *&it : catch_clauses_) {
        it = cb(it)->AsCatchClause();
    }

    if (finalizer_ != nullptr) {
        finalizer_ = cb(finalizer_)->AsBlockStatement();
    }
}

void TryStatement::Iterate(const NodeTraverser &cb) const
{
    cb(block_);

    for (auto *it : catch_clauses_) {
        cb(it);
    }

    if (finalizer_ != nullptr) {
        cb(finalizer_);
    }
}

void TryStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TryStatement"},
                 {"block", block_},
                 {"handler", catch_clauses_},
                 {"finalizer", AstDumper::Nullish(finalizer_)}});
}

bool TryStatement::HasDefaultCatchClause() const
{
    return (!catch_clauses_.empty() && catch_clauses_.back()->IsDefaultCatchClause());
}

void TryStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void TryStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *TryStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *TryStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

void TryStatement::SetReturnType(checker::ETSChecker *checker, checker::Type *type)
{
    if (block_ != nullptr) {
        block_->SetReturnType(checker, type);
    }
    if (finalizer_ != nullptr) {
        finalizer_->SetReturnType(checker, type);
    }
    for (auto *catch_clause : catch_clauses_) {
        if (catch_clause != nullptr) {
            catch_clause->SetReturnType(checker, type);
        }
    }
}
}  // namespace panda::es2panda::ir
