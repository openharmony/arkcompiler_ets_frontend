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

#ifndef ES2PANDA_IR_EXPRESSION_YIELD_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_YIELD_EXPRESSION_H

#include "ir/expression.h"

namespace panda::es2panda::compiler {
class GeneratorFunctionBuilder;
}  // namespace panda::es2panda::compiler

namespace panda::es2panda::ir {
class YieldExpression : public Expression {
public:
    YieldExpression() = delete;
    ~YieldExpression() override = default;

    NO_COPY_SEMANTIC(YieldExpression);
    NO_MOVE_SEMANTIC(YieldExpression);

    explicit YieldExpression(Expression *const argument, bool const is_delegate)
        : Expression(AstNodeType::YIELD_EXPRESSION), argument_(argument), delegate_(is_delegate)
    {
    }

    [[nodiscard]] bool HasDelegate() const noexcept
    {
        return delegate_;
    }

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
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *argument_;
    bool delegate_;
};
}  // namespace panda::es2panda::ir

#endif
