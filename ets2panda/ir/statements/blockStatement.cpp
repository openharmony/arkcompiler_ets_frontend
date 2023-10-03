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

#include "binder/scope.h"
#include "compiler/core/regScope.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {
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

void BlockStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    compiler::LocalRegScope lrs(pg, scope_);

    for (const auto *it : statements_) {
        it->Compile(pg);
    }
}

void BlockStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    compiler::LocalRegScope lrs(etsg, scope_);

    etsg->CompileStatements(statements_);
}

checker::Type *BlockStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, scope_);

    for (auto *it : statements_) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *BlockStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    checker::ScopeContext scope_ctx(checker, scope_);

    for (auto *it : statements_) {
        it->Check(checker);
    }

    for (auto [stmt, trailing_block] : trailing_blocks_) {
        auto iterator = std::find(statements_.begin(), statements_.end(), stmt);
        ASSERT(iterator != statements_.end());
        statements_.insert(iterator + 1, trailing_block);
        trailing_block->Check(checker);
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
