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

#ifndef ES2PANDA_IR_EXPRESSION_TAGGED_TEMPLATE_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_TAGGED_TEMPLATE_EXPRESSION_H

#include "plugins/ecmascript/es2panda/ir/expression.h"

namespace panda::es2panda::ir {
class TemplateLiteral;
class TSTypeParameterInstantiation;

class TaggedTemplateExpression : public Expression {
public:
    explicit TaggedTemplateExpression(Expression *tag, TemplateLiteral *quasi,
                                      TSTypeParameterInstantiation *type_params)
        : Expression(AstNodeType::TAGGED_TEMPLATE_EXPRESSION), tag_(tag), quasi_(quasi), type_params_(type_params)
    {
    }

    const Expression *Tag() const
    {
        return tag_;
    }

    const TemplateLiteral *Quasi() const
    {
        return quasi_;
    }

    const TSTypeParameterInstantiation *TypeParams() const
    {
        return type_params_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *tag_;
    TemplateLiteral *quasi_;
    TSTypeParameterInstantiation *type_params_;
};
}  // namespace panda::es2panda::ir

#endif
