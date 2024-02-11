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

#ifndef ES2PANDA_IR_EXPRESSION_ARROW_FUNCTION_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_ARROW_FUNCTION_EXPRESSION_H

#include "ir/expression.h"

namespace ark::es2panda::compiler {
class ETSCompiler;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::ir {
class ScriptFunction;

class ArrowFunctionExpression : public Expression {
public:
    ArrowFunctionExpression() = delete;
    ~ArrowFunctionExpression() override = default;

    NO_COPY_SEMANTIC(ArrowFunctionExpression);
    NO_MOVE_SEMANTIC(ArrowFunctionExpression);

    explicit ArrowFunctionExpression(ArenaAllocator *const allocator, ScriptFunction *const func)
        : Expression(AstNodeType::ARROW_FUNCTION_EXPRESSION), func_(func), capturedVars_(allocator->Adapter())
    {
    }

    explicit ArrowFunctionExpression(ArrowFunctionExpression const &other, ArenaAllocator *allocator);

    // NOTE (csabahurton): friend relationship can be removed once there are getters for private fields
    friend class compiler::ETSCompiler;

    [[nodiscard]] const ScriptFunction *Function() const noexcept
    {
        return func_;
    }

    [[nodiscard]] ScriptFunction *Function() noexcept
    {
        return func_;
    }

    [[nodiscard]] const ClassDefinition *ResolvedLambda() const noexcept
    {
        return resolvedLambda_;
    }

    [[nodiscard]] ClassDefinition *ResolvedLambda() noexcept
    {
        return resolvedLambda_;
    }

    [[nodiscard]] ArenaVector<varbinder::Variable *> &CapturedVars() noexcept
    {
        return capturedVars_;
    }

    [[nodiscard]] const ArenaVector<varbinder::Variable *> &CapturedVars() const noexcept
    {
        return capturedVars_;
    }

    void SetResolvedLambda(ClassDefinition *const lambda) noexcept
    {
        resolvedLambda_ = lambda;
    }

    void SetPropagateThis() noexcept
    {
        propagateThis_ = true;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] ArrowFunctionExpression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;
    ir::TypeNode *CreateTypeAnnotation(checker::ETSChecker *checker);
    ir::TypeNode *CreateReturnNodeFromType(checker::ETSChecker *checker, checker::Type *returnType);

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    ScriptFunction *func_;
    ArenaVector<varbinder::Variable *> capturedVars_;
    ir::ClassDefinition *resolvedLambda_ {nullptr};
    bool propagateThis_ {false};
};
}  // namespace ark::es2panda::ir

#endif