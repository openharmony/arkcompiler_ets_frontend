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

#ifndef ES2PANDA_IR_EXPRESSION_CALL_EXPRESSION_H
#define ES2PANDA_IR_EXPRESSION_CALL_EXPRESSION_H

#include "varbinder/variable.h"
#include "checker/types/ets/etsFunctionType.h"
#include "ir/expression.h"

namespace panda::es2panda::checker {
class Signature;
}  // namespace panda::es2panda::checker

namespace panda::es2panda::ir {
class TSTypeParameterInstantiation;

class CallExpression : public MaybeOptionalExpression {
public:
    CallExpression() = delete;
    ~CallExpression() override = default;

    NO_COPY_SEMANTIC(CallExpression);
    NO_MOVE_SEMANTIC(CallExpression);

    explicit CallExpression(Expression *const callee, ArenaVector<Expression *> &&arguments,
                            TSTypeParameterInstantiation *const type_params, bool const optional,
                            bool const trailing_comma = false)
        : MaybeOptionalExpression(AstNodeType::CALL_EXPRESSION, optional),
          callee_(callee),
          arguments_(std::move(arguments)),
          type_params_(type_params),
          trailing_comma_(trailing_comma)
    {
    }

    explicit CallExpression(CallExpression const &other, ArenaAllocator *allocator);

    [[nodiscard]] const Expression *Callee() const noexcept
    {
        return callee_;
    }

    [[nodiscard]] Expression *Callee() noexcept
    {
        return callee_;
    }

    void SetCallee(Expression *callee) noexcept
    {
        callee_ = callee;
    }

    [[nodiscard]] const TSTypeParameterInstantiation *TypeParams() const noexcept
    {
        return type_params_;
    }

    [[nodiscard]] TSTypeParameterInstantiation *TypeParams() noexcept
    {
        return type_params_;
    }

    [[nodiscard]] const ArenaVector<Expression *> &Arguments() const noexcept
    {
        return arguments_;
    }

    [[nodiscard]] ArenaVector<Expression *> &Arguments() noexcept
    {
        return arguments_;
    }

    [[nodiscard]] bool HasTrailingComma() const noexcept
    {
        return trailing_comma_;
    }

    [[nodiscard]] checker::Signature *Signature() noexcept
    {
        return signature_;
    }

    [[nodiscard]] checker::Signature *Signature() const noexcept
    {
        return signature_;
    }

    void SetSignature(checker::Signature *const signature) noexcept
    {
        signature_ = signature;
    }

    void SetTypeParams(TSTypeParameterInstantiation *const type_params) noexcept
    {
        type_params_ = type_params;
    }

    void SetTrailingBlock(ir::BlockStatement *const block) noexcept
    {
        trailing_block_ = block;
    }

    [[nodiscard]] ir::BlockStatement *TrailingBlock() const noexcept
    {
        return trailing_block_;
    }

    void SetIsTrailingBlockInNewLine(bool const is_new_line) noexcept
    {
        is_trailing_block_in_new_line_ = is_new_line;
    }

    [[nodiscard]] bool IsTrailingBlockInNewLine() const noexcept
    {
        return is_trailing_block_in_new_line_;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    [[nodiscard]] CallExpression *Clone(ArenaAllocator *allocator, AstNode *parent = nullptr) override;

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;

    void Dump(ir::AstDumper *dumper) const override;

    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

    checker::Signature *ResolveCallExtensionFunction(checker::ETSFunctionType *function_type,
                                                     checker::ETSChecker *checker);
    checker::Signature *ResolveCallForETSExtensionFuncHelperType(checker::ETSExtensionFuncHelperType *type,
                                                                 checker::ETSChecker *checker);

protected:
    compiler::VReg CreateSpreadArguments(compiler::PandaGen *pg) const;

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Expression *callee_;
    ArenaVector<Expression *> arguments_;
    TSTypeParameterInstantiation *type_params_;
    checker::Signature *signature_ {};
    bool trailing_comma_;
    // for trailing lambda feature in ets
    ir::BlockStatement *trailing_block_ {};
    bool is_trailing_block_in_new_line_ {false};
    // NOLINTEND(misc-non-private-member-variables-in-classes)

private:
    bool IsETSConstructorCall() const;
    checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, Expression *callee,
                                             checker::Type *callee_type);
    void ConvertRestArguments(checker::ETSChecker *checker) const;
};
}  // namespace panda::es2panda::ir

#endif
