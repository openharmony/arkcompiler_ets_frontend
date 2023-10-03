/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_EXPRESSION_OBJECT_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_OBJECT_EXPRESSION_H

#include "binder/variable.h"
#include "ir/expression.h"
#include "ir/validationInfo.h"

namespace panda::es2panda::util {
class BitSet;
}  // namespace panda::es2panda::util

namespace panda::es2panda::ir {
class ObjectExpression : public AnnotatedExpression {
public:
    explicit ObjectExpression(AstNodeType node_type, ArenaAllocator *allocator, ArenaVector<Expression *> &&properties,
                              bool trailing_comma)
        : AnnotatedExpression(node_type),
          decorators_(allocator->Adapter()),
          properties_(std::move(properties)),
          trailing_comma_(trailing_comma)
    {
    }

    const ArenaVector<Expression *> &Properties() const
    {
        return properties_;
    }

    bool IsDeclaration() const
    {
        return is_declaration_;
    }

    bool IsOptional() const
    {
        return optional_;
    }

    void SetPreferredType(checker::Type *preferred_type)
    {
        preferred_type_ = preferred_type;
    }

    checker::Type *PreferredType() const
    {
        return preferred_type_;
    }

    const ArenaVector<Decorator *> &Decorators() const
    {
        return decorators_;
    }

    void AddDecorators([[maybe_unused]] ArenaVector<ir::Decorator *> &&decorators) override
    {
        decorators_ = std::move(decorators);
    }

    ValidationInfo ValidateExpression();
    bool ConvertibleToObjectPattern();

    void SetDeclaration();
    void SetOptional(bool optional);
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check(checker::ETSChecker *checker) override;
    checker::Type *CheckPattern(checker::TSChecker *checker);

private:
    void CompileStaticProperties(compiler::PandaGen *pg, util::BitSet *compiled) const;
    void CompileRemainingProperties(compiler::PandaGen *pg, const util::BitSet *compiled) const;

    ArenaVector<Decorator *> decorators_;
    ArenaVector<Expression *> properties_;
    checker::Type *preferred_type_ {};
    bool is_declaration_ {};
    bool trailing_comma_ {};
    bool optional_ {};
};
}  // namespace panda::es2panda::ir

#endif
