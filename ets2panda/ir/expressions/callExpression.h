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

#ifndef ES2PANDA_IR_EXPRESSION_CALL_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_CALL_EXPRESSION_H

#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/ir/expression.h"

namespace panda::es2panda::checker {
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {
class TSTypeParameterInstantiation;

class CallExpression : public Expression {
public:
    explicit CallExpression(Expression *callee, ArenaVector<Expression *> &&arguments,
                            TSTypeParameterInstantiation *type_params, bool optional, bool trailing_comma = false)
        : Expression(AstNodeType::CALL_EXPRESSION),
          callee_(callee),
          arguments_(std::move(arguments)),
          type_params_(type_params),
          optional_(optional),
          trailing_comma_(trailing_comma)
    {
    }

    const Expression *Callee() const
    {
        return callee_;
    }

    const TSTypeParameterInstantiation *TypeParams() const
    {
        return type_params_;
    }

    const ArenaVector<Expression *> &Arguments() const
    {
        return arguments_;
    }

    ArenaVector<Expression *> &Arguments()
    {
        return arguments_;
    }

    bool HasTrailingComma() const
    {
        return trailing_comma_;
    }

    checker::Signature *Signature()
    {
        return signature_;
    }

    checker::Signature *Signature() const
    {
        return signature_;
    }

    void SetSignature(checker::Signature *signature)
    {
        signature_ = signature;
    }

    void SetTypeParams(TSTypeParameterInstantiation *type_params)
    {
        type_params_ = type_params;
    }

    void SetTrailingBlock(ir::BlockStatement *block)
    {
        trailing_block_ = block;
    }

    ir::BlockStatement *TrailingBlock() const
    {
        return trailing_block_;
    }

    void SetIsTrailingBlockInNewLine(bool is_new_line)
    {
        is_trailing_block_in_new_line_ = is_new_line;
    }

    bool IsTrailingBlockInNewLine() const
    {
        return is_trailing_block_in_new_line_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

protected:
    compiler::VReg CreateSpreadArguments(compiler::PandaGen *pg) const;

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Expression *callee_;
    ArenaVector<Expression *> arguments_;
    TSTypeParameterInstantiation *type_params_;
    checker::Signature *signature_ {};
    bool optional_;
    bool trailing_comma_;
    // for trailing lambda feature in ets
    ir::BlockStatement *trailing_block_ {};
    bool is_trailing_block_in_new_line_ {false};
    // NOLINTEND(misc-non-private-member-variables-in-classes)

private:
    bool IsETSConstructorCall() const;
    checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, Expression *callee,
                                             checker::Type *callee_type);
};
}  // namespace panda::es2panda::ir

#endif
