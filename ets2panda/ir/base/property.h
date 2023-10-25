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

#ifndef ES2PANDA_PARSER_INCLUDE_AST_PROPERTY_H
#define ES2PANDA_PARSER_INCLUDE_AST_PROPERTY_H

#include "ir/expression.h"
#include "ir/validationInfo.h"

namespace panda::es2panda::ir {
enum class PropertyKind { INIT, GET, SET, PROTO };

class Property : public Expression {
private:
    struct Tag {};

public:
    Property() = delete;
    ~Property() override = default;

    NO_COPY_OPERATOR(Property);
    NO_MOVE_SEMANTIC(Property);

    explicit Property(Expression *const key, Expression *const value)
        : Expression(AstNodeType::PROPERTY), kind_(PropertyKind::INIT), key_(key), value_(value)
    {
    }

    explicit Property(PropertyKind const kind, Expression *const key, Expression *const value, bool const is_method,
                      bool const is_computed)
        : Expression(AstNodeType::PROPERTY),
          kind_(kind),
          key_(key),
          value_(value),
          is_method_(is_method),
          is_shorthand_(false),
          is_computed_(is_computed)
    {
    }

    explicit Property(Tag tag, Expression *key, Expression *value);

    [[nodiscard]] Expression *Key() noexcept
    {
        return key_;
    }

    [[nodiscard]] const Expression *Key() const noexcept
    {
        return key_;
    }

    [[nodiscard]] const Expression *Value() const noexcept
    {
        return value_;
    }

    [[nodiscard]] Expression *Value() noexcept
    {
        return value_;
    }

    [[nodiscard]] PropertyKind Kind() const noexcept
    {
        return kind_;
    }

    [[nodiscard]] bool IsMethod() const noexcept
    {
        return is_method_;
    }

    [[nodiscard]] bool IsShorthand() const noexcept
    {
        return is_shorthand_;
    }

    [[nodiscard]] bool IsComputed() const noexcept
    {
        return is_computed_;
    }

    [[nodiscard]] bool IsAccessor() const noexcept
    {
        return IsAccessorKind(kind_);
    }

    [[nodiscard]] static bool IsAccessorKind(PropertyKind kind) noexcept
    {
        return kind == PropertyKind::GET || kind == PropertyKind::SET;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    bool ConvertibleToPatternProperty();
    ValidationInfo ValidateExpression();

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

protected:
    Property(Property const &other) : Expression(static_cast<Expression const &>(other))
    {
        kind_ = other.kind_;
        is_method_ = other.is_method_;
        is_shorthand_ = other.is_shorthand_;
        is_computed_ = other.is_computed_;
    }

private:
    PropertyKind kind_;
    Expression *key_ = nullptr;
    Expression *value_ = nullptr;
    bool is_method_ = false;
    bool is_shorthand_ = true;
    bool is_computed_ = false;
};
}  // namespace panda::es2panda::ir

#endif
