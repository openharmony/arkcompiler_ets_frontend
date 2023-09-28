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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_PROPERTY_H
#define ES2PANDA_PARSER_INCLUDE_AST_PROPERTY_H

#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/validationInfo.h"

namespace panda::es2panda::ir {
enum class PropertyKind { INIT, GET, SET, PROTO };

class Property : public Expression {
public:
    explicit Property(Expression *key, Expression *value)
        : Expression(AstNodeType::PROPERTY),
          kind_(PropertyKind::INIT),
          key_(key),
          value_(value),
          is_method_(false),
          is_shorthand_(true),
          is_computed_(false)
    {
    }

    explicit Property(PropertyKind kind, Expression *key, Expression *value, bool is_method, bool is_computed)
        : Expression(AstNodeType::PROPERTY),
          kind_(kind),
          key_(key),
          value_(value),
          is_method_(is_method),
          is_shorthand_(false),
          is_computed_(is_computed)
    {
    }

    Expression *Key()
    {
        return key_;
    }

    const Expression *Key() const
    {
        return key_;
    }

    const Expression *Value() const
    {
        return value_;
    }

    Expression *Value()
    {
        return value_;
    }

    PropertyKind Kind() const
    {
        return kind_;
    }

    bool IsMethod() const
    {
        return is_method_;
    }

    bool IsShorthand() const
    {
        return is_shorthand_;
    }

    bool IsComputed() const
    {
        return is_computed_;
    }

    bool IsAccessor() const
    {
        return IsAccessorKind(kind_);
    }

    static bool IsAccessorKind(PropertyKind kind)
    {
        return kind == PropertyKind::GET || kind == PropertyKind::SET;
    }

    bool ConvertibleToPatternProperty();
    ValidationInfo ValidateExpression();
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    PropertyKind kind_;
    Expression *key_;
    Expression *value_;
    bool is_method_;
    bool is_shorthand_;
    bool is_computed_;
};
}  // namespace panda::es2panda::ir

#endif
