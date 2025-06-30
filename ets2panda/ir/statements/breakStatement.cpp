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

#include "breakStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::ir {
void BreakStatement::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (ident_ != nullptr) {
        if (auto *transformedNode = cb(ident_); ident_ != transformedNode) {
            ident_->SetTransformedNode(transformationName, transformedNode);
            ident_ = transformedNode->AsIdentifier();
        }
    }
}

void BreakStatement::Iterate(const NodeTraverser &cb) const
{
    if (ident_ != nullptr) {
        cb(ident_);
    }
}

void BreakStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "BreakStatement"}, {"label", AstDumper::Nullish(ident_)}});
}

void BreakStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("break");
    if (ident_ != nullptr) {
        dumper->Add(" ");
        ident_->Dump(dumper);
    }
    dumper->Add(";");
}

void BreakStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void BreakStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *BreakStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType BreakStatement::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

BreakStatement *BreakStatement::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const ident = ident_ != nullptr ? ident_->Clone(allocator, nullptr) : nullptr;
    auto *const clone = util::NodeAllocator::ForceSetParent<BreakStatement>(allocator, ident);
    ES2PANDA_ASSERT(clone != nullptr);

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    return clone;
}
}  // namespace ark::es2panda::ir
