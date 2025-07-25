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

#include "ifStatement.h"

#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"

namespace ark::es2panda::ir {
void IfStatement::TransformChildren(const NodeTransformer &cb, std::string_view transformationName)
{
    if (auto *transformedNode = cb(test_); test_ != transformedNode) {
        test_->SetTransformedNode(transformationName, transformedNode);
        test_ = transformedNode->AsExpression();
    }

    if (auto *transformedNode = cb(consequent_); consequent_ != transformedNode) {
        consequent_->SetTransformedNode(transformationName, transformedNode);
        consequent_ = transformedNode->AsStatement();
    }

    if (alternate_ != nullptr) {
        if (auto *transformedNode = cb(alternate_); alternate_ != transformedNode) {
            alternate_->SetTransformedNode(transformationName, transformedNode);
            alternate_ = transformedNode->AsStatement();
        }
    }
}

void IfStatement::Iterate(const NodeTraverser &cb) const
{
    cb(test_);
    cb(consequent_);

    if (alternate_ != nullptr) {
        cb(alternate_);
    }
}

void IfStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "IfStatement"},
                 {"test", test_},
                 {"consequent", consequent_},
                 {"alternate", AstDumper::Nullish(alternate_)}});
}

void IfStatement::Dump(ir::SrcDumper *dumper) const
{
    ES2PANDA_ASSERT(test_);
    ES2PANDA_ASSERT(consequent_ != nullptr);
    dumper->Add("if (");
    test_->Dump(dumper);
    dumper->Add(") {");
    dumper->IncrIndent();
    dumper->Endl();
    consequent_->Dump(dumper);
    dumper->DecrIndent();
    dumper->Endl();
    dumper->Add("}");
    if (alternate_ != nullptr) {
        dumper->Add(" else {");
        dumper->IncrIndent();
        dumper->Endl();
        alternate_->Dump(dumper);
        dumper->DecrIndent();
        dumper->Endl();
        dumper->Add("}");
    }
}

void IfStatement::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void IfStatement::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *IfStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::VerifiedType IfStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

IfStatement *IfStatement::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const test = test_->Clone(allocator, nullptr)->AsExpression();
    auto *const consequent = consequent_->Clone(allocator, nullptr)->AsStatement();
    auto *const alternate = alternate_ != nullptr ? consequent_->Clone(allocator, nullptr)->AsStatement() : nullptr;
    auto *const clone = allocator->New<IfStatement>(test, consequent, alternate);

    if (parent != nullptr) {
        clone->SetParent(parent);
    }

    test->SetParent(clone);
    consequent->SetParent(clone);
    if (alternate != nullptr) {
        alternate->SetParent(clone);
    }

    clone->SetRange(Range());
    return clone;
}
}  // namespace ark::es2panda::ir
