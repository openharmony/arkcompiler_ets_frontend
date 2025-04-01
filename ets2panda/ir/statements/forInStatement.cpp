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

#include "forInStatement.h"

#include "varbinder/scope.h"
#include "compiler/base/lreference.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {
void ForInStatement::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (auto *transformedNode = cb(left_); left_ != transformedNode) {
        left_->SetTransformedNode(transformationName, transformedNode);
        left_ = transformedNode;
    }

    if (auto *transformedNode = cb(right_); right_ != transformedNode) {
        right_->SetTransformedNode(transformationName, transformedNode);
        right_ = transformedNode->AsExpression();
    }

    if (auto *transformedNode = cb(body_); body_ != transformedNode) {
        body_->SetTransformedNode(transformationName, transformedNode);
        body_ = transformedNode->AsStatement();
    }
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

void ForInStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("ForInStatement");
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

checker::VerifiedType ForInStatement::Check(checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

ForInStatement *ForInStatement::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const left = left_->Clone(allocator, nullptr);
    auto *const right = right_->Clone(allocator, nullptr)->AsExpression();
    auto *const body = body_->Clone(allocator, nullptr)->AsStatement();
    auto *const clone = util::NodeAllocator::ForceSetParent<ForInStatement>(allocator, left, right, body);

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    ES2PANDA_ASSERT(clone->Scope() == nullptr);
    return clone;
}
}  // namespace ark::es2panda::ir
