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

#include "sequenceExpression.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
SequenceExpression::SequenceExpression([[maybe_unused]] Tag const tag, SequenceExpression const &other,
                                       ArenaAllocator *const allocator)
    : Expression(static_cast<Expression const &>(other)), sequence_(allocator->Adapter())
{
    for (auto *sequence : other.sequence_) {
        sequence_.emplace_back(sequence->Clone(allocator, this)->AsExpression());
    }
}

SequenceExpression *SequenceExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<SequenceExpression>(Tag {}, *this, allocator);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }
    clone->SetRange(Range());
    return clone;
}

void SequenceExpression::TransformChildren(const NodeTransformer &cb, std::string_view const transformationName)
{
    for (auto *&it : VectorIterationGuard(sequence_)) {
        if (auto *transformedNode = cb(it); it != transformedNode) {
            it->SetTransformedNode(transformationName, transformedNode);
            it = transformedNode->AsExpression();
        }
    }
}

void SequenceExpression::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : VectorIterationGuard(sequence_)) {
        cb(it);
    }
}

void SequenceExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "SequenceExpression"}, {"expressions", sequence_}});
}

void SequenceExpression::Dump(ir::SrcDumper *dumper) const
{
    for (auto *expr : sequence_) {
        expr->Dump(dumper);
        if (expr != sequence_.back()) {
            dumper->Add(", ");
        }
    }
}

void SequenceExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void SequenceExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *SequenceExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType SequenceExpression::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}
}  // namespace ark::es2panda::ir
