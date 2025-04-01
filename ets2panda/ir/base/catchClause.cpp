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

#include "catchClause.h"

#include "checker/TSchecker.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"

namespace ark::es2panda::ir {
void CatchClause::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (param_ != nullptr) {
        if (auto *transformedNode = cb(param_); param_ != transformedNode) {
            param_->SetTransformedNode(transformationName, transformedNode);
            param_ = transformedNode->AsExpression();
        }
    }

    if (auto *transformedNode = cb(body_); body_ != transformedNode) {
        body_->SetTransformedNode(transformationName, transformedNode);
        body_ = transformedNode->AsBlockStatement();
    }
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
    dumper->Add({{"type", "CatchClause"}, {"body", body_}, {"param", AstDumper::Nullish(param_)}});
}

void CatchClause::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(body_ != nullptr);
    dumper->Add("(");
    if (param_ != nullptr) {
        param_->Dump(dumper);
        if (param_->IsIdentifier() && param_->AsIdentifier()->TypeAnnotation() != nullptr) {
            dumper->Add(": ");
            param_->AsIdentifier()->TypeAnnotation()->Dump(dumper);
        }
    }
    dumper->Add(") {");
    dumper->IncrIndent();
    dumper->Endl();
    body_->Dump(dumper);
    dumper->DecrIndent();
    dumper->Endl();
    dumper->Add("}");
}

bool CatchClause::IsDefaultCatchClause() const
{
    return param_ != nullptr && param_->AsIdentifier()->TypeAnnotation() == nullptr;
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

checker::VerifiedType CatchClause::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

CatchClause::CatchClause(CatchClause const &other, ArenaAllocator *allocator) : TypedStatement(other)
{
    param_ = other.param_ == nullptr ? nullptr : other.param_->Clone(allocator, this)->AsExpression();
    body_ = other.body_ == nullptr ? nullptr : other.body_->Clone(allocator, this)->AsBlockStatement();
}

CatchClause *CatchClause::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<CatchClause>(*this, allocator);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    return clone;
}

}  // namespace ark::es2panda::ir
