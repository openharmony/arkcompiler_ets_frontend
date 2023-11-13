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

#include "etsNewArrayInstanceExpression.h"

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "ir/typeNode.h"

namespace panda::es2panda::ir {
void ETSNewArrayInstanceExpression::TransformChildren(const NodeTransformer &cb)
{
    type_reference_ = static_cast<TypeNode *>(cb(type_reference_));
    dimension_ = cb(dimension_)->AsExpression();
}

void ETSNewArrayInstanceExpression::Iterate(const NodeTraverser &cb) const
{
    cb(type_reference_);
    cb(dimension_);
}

void ETSNewArrayInstanceExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add(
        {{"type", "ETSNewArrayInstanceExpression"}, {"typeReference", type_reference_}, {"dimension", dimension_}});
}

void ETSNewArrayInstanceExpression::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add("new ");
    ASSERT(type_reference_);
    type_reference_->Dump(dumper);
    ASSERT(dimension_);
    dumper->Add("[");
    dimension_->Dump(dumper);
    dumper->Add("]");
}

void ETSNewArrayInstanceExpression::Compile(compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}
void ETSNewArrayInstanceExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ETSNewArrayInstanceExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *ETSNewArrayInstanceExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

// NOLINTNEXTLINE(google-default-arguments)
ETSNewArrayInstanceExpression *ETSNewArrayInstanceExpression::Clone(ArenaAllocator *const allocator,
                                                                    AstNode *const parent)
{
    auto *const type_ref = type_reference_ != nullptr ? type_reference_->Clone(allocator) : nullptr;
    auto *const dimension = dimension_ != nullptr ? dimension_->Clone(allocator)->AsExpression() : nullptr;

    if (auto *const clone = allocator->New<ETSNewArrayInstanceExpression>(type_ref, dimension); clone != nullptr) {
        if (type_ref != nullptr) {
            type_ref->SetParent(clone);
        }
        if (dimension != nullptr) {
            dimension->SetParent(clone);
        }
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }

    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}
}  // namespace panda::es2panda::ir
