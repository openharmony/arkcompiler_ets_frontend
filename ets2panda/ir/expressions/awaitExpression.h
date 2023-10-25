/**
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

#ifndef ES2PANDA_IR_EXPRESSION_AWAIT_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_AWAIT_EXPRESSION_H

#include "ir/expression.h"

namespace panda::es2panda::ir {
class AwaitExpression : public Expression {
public:
    AwaitExpression() = delete;
    ~AwaitExpression() override = default;

    NO_COPY_SEMANTIC(AwaitExpression);
    NO_MOVE_SEMANTIC(AwaitExpression);

    explicit AwaitExpression(Expression *argument) : Expression(AstNodeType::AWAIT_EXPRESSION), argument_(argument) {}

    [[nodiscard]] const Expression *Argument() const noexcept
    {
        return argument_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *argument_;
};
}  // namespace panda::es2panda::ir

#endif
