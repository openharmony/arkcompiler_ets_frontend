/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "emptyStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void EmptyStatement::TransformChildren([[maybe_unused]] const NodeTransformer &c,
                                       [[maybe_unused]] std::string_view const transformationName)
{
}

void EmptyStatement::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void EmptyStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "EmptyStatement"}});
}

void EmptyStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("");
}

void EmptyStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void EmptyStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

bool EmptyStatement::IsBrokenStatement()
{
    return isBrokenStatement_;
}

checker::Type *EmptyStatement::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType EmptyStatement::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

[[nodiscard]] EmptyStatement *EmptyStatement::Clone(ArenaAllocator *allocator, AstNode *parent)
{
    EmptyStatement *stmt = allocator->New<EmptyStatement>(IsBrokenStatement());
    if (stmt != nullptr) {
        stmt->SetParent(parent);
        stmt->SetRange(Range());
    }

    return stmt;
}
}  // namespace ark::es2panda::ir
