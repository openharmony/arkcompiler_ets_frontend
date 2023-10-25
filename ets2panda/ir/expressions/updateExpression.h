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

#ifndef ES2PANDA_IR_EXPRESSION_UPDATE_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_UPDATE_EXPRESSION_H

#include "ir/expression.h"
#include "lexer/token/tokenType.h"

namespace panda::es2panda::ir {
class UpdateExpression : public Expression {
public:
    UpdateExpression() = delete;
    ~UpdateExpression() override = default;

    NO_COPY_SEMANTIC(UpdateExpression);
    NO_MOVE_SEMANTIC(UpdateExpression);

    explicit UpdateExpression(Expression *const argument, lexer::TokenType const update_operator, bool const is_prefix)
        : Expression(AstNodeType::UPDATE_EXPRESSION),
          argument_(argument),
          operator_(update_operator),
          prefix_(is_prefix)
    {
        ASSERT(update_operator == lexer::TokenType::PUNCTUATOR_PLUS_PLUS ||
               update_operator == lexer::TokenType::PUNCTUATOR_MINUS_MINUS);
    }

    [[nodiscard]] lexer::TokenType OperatorType() const noexcept
    {
        return operator_;
    }

    [[nodiscard]] const Expression *Argument() const noexcept
    {
        return argument_;
    }

    [[nodiscard]] bool IsPrefix() const noexcept
    {
        return prefix_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *argument_;
    lexer::TokenType operator_;
    bool prefix_;
};
}  // namespace panda::es2panda::ir

#endif
