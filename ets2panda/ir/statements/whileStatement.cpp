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

#include "whileStatement.h"

#include "compiler/base/condition.h"
#include "compiler/core/labelTarget.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/regScope.h"
#include "checker/TSchecker.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/expression.h"

namespace ark::es2panda::ir {
void WhileStatement::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (auto *transformedNode = cb(test_); test_ != transformedNode) {
        test_->SetTransformedNode(transformationName, transformedNode);
        test_ = transformedNode->AsExpression();
    }

    if (auto *transformedNode = cb(body_); body_ != transformedNode) {
        body_->SetTransformedNode(transformationName, transformedNode);
        body_ = transformedNode->AsStatement();
    }
}

void WhileStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(body_);
}

void WhileStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "WhileStatement"}, {"test", test_}, {"body", body_}});
}

void WhileStatement::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("while (");
    if (test_ != nullptr) {
        test_->Dump(dumper);
    }
    dumper->Add(") {");
    if (body_ != nullptr) {
        dumper->IncrIndent();
        dumper->Endl();
        body_->Dump(dumper);
        dumper->DecrIndent();
        dumper->Endl();
    }
    dumper->Add("}");
}

void WhileStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void WhileStatement::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *WhileStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType WhileStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

WhileStatement *WhileStatement::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const test = test_->Clone(allocator, nullptr)->AsExpression();
    auto *const body = body_->Clone(allocator, nullptr)->AsStatement();
    auto *const clone = util::NodeAllocator::ForceSetParent<WhileStatement>(allocator, test, body);

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    clone->SetRange(Range());
    ES2PANDA_ASSERT(clone->Scope() == nullptr);
    return clone;
}
}  // namespace ark::es2panda::ir
