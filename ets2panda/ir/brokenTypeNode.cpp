/*
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

#include "brokenTypeNode.h"
#include "checker/TSchecker.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/srcDump.h"

namespace ark::es2panda::ir {

void BrokenTypeNode::TransformChildren([[maybe_unused]] const NodeTransformer &cb,
                                       [[maybe_unused]] std::string_view transformationName)
{
}

void BrokenTypeNode::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void BrokenTypeNode::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ErrorType"}});
}

void BrokenTypeNode::Dump(ir::SrcDumper *dumper) const
{
    dumper->Add(ERROR_TYPE);
}

void BrokenTypeNode::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
}

void BrokenTypeNode::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *BrokenTypeNode::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

checker::Type *BrokenTypeNode::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *BrokenTypeNode::GetType([[maybe_unused]] checker::ETSChecker *checker)
{
    return checker->GlobalTypeError();
}

checker::VerifiedType BrokenTypeNode::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return {this, checker->GetAnalyzer()->Check(this)};
}

BrokenTypeNode *BrokenTypeNode::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    auto *const clone = allocator->New<BrokenTypeNode>(allocator);
    ES2PANDA_ASSERT(clone != nullptr);
    if (parent != nullptr) {
        clone->SetParent(parent);
    }
    return clone;
}
}  // namespace ark::es2panda::ir
