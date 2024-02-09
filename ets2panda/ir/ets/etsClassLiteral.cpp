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

#include "etsClassLiteral.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void ETSClassLiteral::TransformChildren(const NodeTransformer &cb)
{
    expr_ = static_cast<TypeNode *>(cb(expr_));
}

void ETSClassLiteral::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    cb(expr_);
}

void ETSClassLiteral::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSClassLiteral"}});
}

void ETSClassLiteral::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("ETSClassLiteral");
}

void ETSClassLiteral::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void ETSClassLiteral::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSClassLiteral::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSClassLiteral::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
ETSClassLiteral *ETSClassLiteral::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const expr = expr_ != nullptr ? expr_->Clone(allocator) : nullptr;

    if (auto *const clone = allocator->New<ETSClassLiteral>(expr); clone != nullptr) {
        if (expr != nullptr) {
            expr->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace ark::es2panda::ir
