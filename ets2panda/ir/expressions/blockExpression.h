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

#ifndef ES2PANDA_IR_EXPRESSION_BLOCK_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_BLOCK_EXPRESSION_H

#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/statement.h"

namespace panda::es2panda::ir {

class BlockExpression : public Expression {
private:
    struct Tag {};

public:
    BlockExpression() = delete;
    ~BlockExpression() override = default;

    NO_COPY_SEMANTIC(BlockExpression);
    NO_MOVE_SEMANTIC(BlockExpression);

    explicit BlockExpression(ArenaVector<ir::Statement *> &&statements);
    explicit BlockExpression(Tag tag, BlockExpression const &other, ArenaAllocator *allocator);

    [[nodiscard]] ArenaVector<ir::Statement *> const &Statements() const noexcept
    {
        return statements_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] BlockExpression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    ArenaVector<ir::Statement *> statements_;
};
}  // namespace panda::es2panda::ir

#endif
