/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_EXPRESSION_TAGGED_TEMPLATE_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_TAGGED_TEMPLATE_EXPRESSION_H

#include "ir/expression.h"

namespace ark::es2panda::ir {
class TemplateLiteral;
class TSTypeParameterInstantiation;

class TaggedTemplateExpression : public Expression {
public:
    TaggedTemplateExpression() = delete;
    ~TaggedTemplateExpression() override = default;

    NO_COPY_SEMANTIC(TaggedTemplateExpression);
    NO_MOVE_SEMANTIC(TaggedTemplateExpression);

    explicit TaggedTemplateExpression(Expression *tag, TemplateLiteral *quasi, TSTypeParameterInstantiation *typeParams)
        : Expression(AstNodeType::TAGGED_TEMPLATE_EXPRESSION), tag_(tag), quasi_(quasi), typeParams_(typeParams)
    {
    }

    [[nodiscard]] const Expression *Tag() const noexcept
    {
        return tag_;
    }

    [[nodiscard]] const TemplateLiteral *Quasi() const noexcept
    {
        return quasi_;
    }

    [[nodiscard]] const TSTypeParameterInstantiation *TypeParams() const noexcept
    {
        return typeParams_;
    }

    [[nodiscard]] TaggedTemplateExpression *Clone(ArenaAllocator *allocator, AstNode *parent) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    Expression *tag_;
    TemplateLiteral *quasi_;
    TSTypeParameterInstantiation *typeParams_;
};
}  // namespace ark::es2panda::ir

#endif