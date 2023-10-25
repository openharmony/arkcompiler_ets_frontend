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

#ifndef ES2PANDA_IR_EXPRESSION_MEMBER_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_MEMBER_EXPRESSION_H

#include "binder/variable.h"
#include "ir/expression.h"
#include "ir/irnode.h"

namespace panda::es2panda::checker {
class ETSObjectType;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {
enum class MemberExpressionKind : uint32_t {
    NONE = 0,
    ELEMENT_ACCESS = 1U << 0U,
    PROPERTY_ACCESS = 1U << 1U,
    GETTER = 1U << 2U,
    SETTER = 1U << 3U,
};

DEFINE_BITOPS(MemberExpressionKind)

class MemberExpression : public Expression {
private:
    struct Tag {};

public:
    MemberExpression() = delete;
    ~MemberExpression() override = default;

    NO_COPY_OPERATOR(MemberExpression);
    NO_MOVE_SEMANTIC(MemberExpression);

    explicit MemberExpression(Expression *object, Expression *property, MemberExpressionKind kind, bool computed,
                              bool optional)
        : Expression(AstNodeType::MEMBER_EXPRESSION),
          object_(object),
          property_(property),
          kind_(kind),
          computed_(computed),
          optional_(optional)
    {
    }

    explicit MemberExpression(Tag tag, Expression *object, Expression *property);

    [[nodiscard]] Expression *Object() noexcept
    {
        return object_;
    }

    [[nodiscard]] const Expression *Object() const noexcept
    {
        return object_;
    }

    [[nodiscard]] Expression *Property() noexcept
    {
        return property_;
    }

    [[nodiscard]] const Expression *Property() const noexcept
    {
        return property_;
    }

    [[nodiscard]] binder::LocalVariable *PropVar() noexcept
    {
        return prop_var_;
    }

    [[nodiscard]] const binder::LocalVariable *PropVar() const noexcept
    {
        return prop_var_;
    }

    [[nodiscard]] bool IsComputed() const noexcept
    {
        return computed_;
    }

    [[nodiscard]] bool IsOptional() const noexcept
    {
        return optional_;
    }

    [[nodiscard]] MemberExpressionKind Kind() const noexcept
    {
        return kind_;
    }

    void AddMemberKind(MemberExpressionKind kind) noexcept
    {
        kind_ |= kind;
    }

    [[nodiscard]] bool HasMemberKind(MemberExpressionKind kind) const noexcept
    {
        return (kind_ & kind) != 0;
    }

    void RemoveMemberKind(MemberExpressionKind const kind) noexcept
    {
        kind_ &= ~kind;
    }

    [[nodiscard]] checker::ETSObjectType *ObjType() const noexcept
    {
        return obj_type_;
    }

    void SetPropVar(binder::LocalVariable *prop_var) noexcept
    {
        prop_var_ = prop_var;
    }

    void SetObjectType(checker::ETSObjectType *obj_type) noexcept
    {
        obj_type_ = obj_type;
    }

    [[nodiscard]] bool IsIgnoreBox() const noexcept
    {
        return ignore_box_;
    }

    void SetIgnoreBox() noexcept
    {
        ignore_box_ = true;
    }

    [[nodiscard]] bool IsPrivateReference() const noexcept;

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] Expression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompileToReg(compiler::PandaGen *pg, compiler::VReg obj_reg) const;
    void CompileToRegs(compiler::PandaGen *pg, compiler::VReg object, compiler::VReg property) const;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

protected:
    MemberExpression(MemberExpression const &other) : Expression(static_cast<Expression const &>(other))
    {
        kind_ = other.kind_;
        computed_ = other.computed_;
        optional_ = other.optional_;
        ignore_box_ = other.ignore_box_;
        prop_var_ = other.prop_var_;
        // Note! Probably, we need to do 'Instantiate(...)' but we haven't access to 'Relation()' here...
        obj_type_ = other.obj_type_;
    }

private:
    void LoadRhs(compiler::PandaGen *pg) const;
    Expression *object_ = nullptr;
    Expression *property_ = nullptr;
    MemberExpressionKind kind_;
    bool computed_;
    bool optional_;
    bool ignore_box_ {false};
    binder::LocalVariable *prop_var_ {};
    checker::ETSObjectType *obj_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
