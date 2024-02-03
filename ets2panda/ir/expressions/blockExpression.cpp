/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "blockExpression.h"

#include "ir/astDump.h"
#include "ir/srcDump.h"
#include "compiler/core/ETSGen.h"
#include "checker/ETSchecker.h"
#include "ir/astNode.h"

namespace ark::es2panda::ir {

BlockExpression::BlockExpression(ArenaVector<ir::Statement *> &&statements)
    : Expression(AstNodeType::BLOCK_EXPRESSION), statements_(std::move(statements))
{
    for (auto *const node : statements_) {
        node->SetParent(this);
    }
}

BlockExpression::BlockExpression([[maybe_unused]] Tag const tag, BlockExpression const &other,
                                 ArenaAllocator *const allocator)
    : Expression(static_cast<Expression const &>(other)), statements_(allocator->Adapter())
{
    for (auto *const node : other.statements_) {
        statements_.emplace_back(node->Clone(allocator, this)->AsStatement());
    }
}

BlockExpression *BlockExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<BlockExpression>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

void BlockExpression::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&node : statements_) {
        node = cb(node)->AsStatement();
    }
}

void BlockExpression::Iterate(const NodeTraverser &cb) const
{
    for (auto *const node : statements_) {
        cb(node);
    }
}

void BlockExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "BlockExpression"}, {"statements", statements_}});
}

void BlockExpression::Dump(ir::SrcDumper *dumper) const
{
    for (auto *statement : statements_) {
        statement->Dump(dumper);
        if (statement != statements_.back()) {
            dumper->Endl();
        }
    }
}

void BlockExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    UNREACHABLE();
}

void BlockExpression::Compile(compiler::ETSGen *etsg) const
{
    for (auto const *const node : statements_) {
        node->Compile(etsg);
    }
}

checker::Type *BlockExpression::Check([[maybe_unused]] checker::TSChecker *checker)
{
    UNREACHABLE();
}

checker::Type *BlockExpression::Check(checker::ETSChecker *checker)
{
    if (TsType() == nullptr) {
        for (auto *const node : statements_) {
            if (auto *const exprType = node->Check(checker); exprType != nullptr) {
                SetTsType(exprType);
            }
        }
    }
    return TsType();
}
}  // namespace ark::es2panda::ir
