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

#include "blockStatement.h"

#include "varbinder/scope.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/regScope.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void BlockStatement::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : statements_) {
        it = cb(it)->AsStatement();
    }
}

void BlockStatement::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : statements_) {
        cb(it);
    }
}

void BlockStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", IsProgram() ? "Program" : "BlockStatement"}, {"statements", statements_}});
}

void BlockStatement::Dump(ir::SrcDumper *dumper) const
{
    // NOTE(nsizov): trailing blocks
    for (auto statement : statements_) {
        statement->Dump(dumper);
        if (statement != statements_.back()) {
            dumper->Endl();
        }
    }
}

void BlockStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void BlockStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *BlockStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *BlockStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace ark::es2panda::ir