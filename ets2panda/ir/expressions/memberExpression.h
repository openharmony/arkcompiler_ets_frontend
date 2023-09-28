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

#ifndef ES2PANDA_IR_EXPRESSION_MEMBER_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_MEMBER_EXPRESSION_H

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/irnode.h"

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
public:
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

    Expression *Object()
    {
        return object_;
    }

    const Expression *Object() const
    {
        return object_;
    }

    Expression *Property()
    {
        return property_;
    }

    const Expression *Property() const
    {
        return property_;
    }

    binder::LocalVariable *PropVar()
    {
        return prop_var_;
    }

    const binder::LocalVariable *PropVar() const
    {
        return prop_var_;
    }

    bool IsComputed() const
    {
        return computed_;
    }

    bool IsOptional() const
    {
        return optional_;
    }

    MemberExpressionKind Kind() const
    {
        return kind_;
    }

    void AddMemberKind(MemberExpressionKind kind)
    {
        kind_ |= kind;
    }

    bool HasMemberKind(MemberExpressionKind kind) const
    {
        return (kind_ & kind) != 0;
    }

    void RemoveMemberKind(MemberExpressionKind const kind) noexcept
    {
        kind_ &= ~kind;
    }

    checker::ETSObjectType *ObjType() const
    {
        return obj_type_;
    }

    void SetPropVar(binder::LocalVariable *prop_var)
    {
        prop_var_ = prop_var;
    }

    void SetObjectType(checker::ETSObjectType *obj_type)
    {
        obj_type_ = obj_type;
    }

    bool IsIgnoreBox() const
    {
        return ignore_box_;
    }

    void SetIgnoreBox()
    {
        ignore_box_ = true;
    }

    bool IsPrivateReference() const;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile(compiler::PandaGen *pg) const override;
    void Compile(compiler::ETSGen *etsg) const override;
    void CompileToReg(compiler::PandaGen *pg, compiler::VReg obj_reg) const;
    void CompileToRegs(compiler::PandaGen *pg, compiler::VReg object, compiler::VReg property) const;
    checker::Type *Check(checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    void LoadRhs(compiler::PandaGen *pg) const;
    Expression *object_;
    Expression *property_;
    MemberExpressionKind kind_;
    bool computed_;
    bool optional_;
    bool ignore_box_ {false};
    binder::LocalVariable *prop_var_ {};
    checker::ETSObjectType *obj_type_ {};
};
}  // namespace panda::es2panda::ir

#endif
