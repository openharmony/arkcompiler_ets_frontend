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

#ifndef ES2PANDA_IR_STATEMENT_SWITCH_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_SWITCH_STATEMENT_H

#include "binder/scope.h"
#include "ir/statement.h"

namespace panda::es2panda::ir {
class Expression;
class SwitchCaseStatement;

class SwitchStatement : public Statement {
public:
    explicit SwitchStatement(binder::LocalScope *scope, Expression *discriminant,
                             ArenaVector<SwitchCaseStatement *> &&cases)
        : Statement(AstNodeType::SWITCH_STATEMENT), scope_(scope), discriminant_(discriminant), cases_(std::move(cases))
    {
    }

    const Expression *Discriminant() const
    {
        return discriminant_;
    }

    const ArenaVector<SwitchCaseStatement *> &Cases() const
    {
        return cases_;
    }

    bool IsScopeBearer() const override
    {
        return true;
    }

    binder::LocalScope *Scope() const override
    {
        return scope_;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void SetReturnType(checker::ETSChecker *checker, checker::Type *type) override;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::LocalScope *scope_;
    Expression *discriminant_;
    ArenaVector<SwitchCaseStatement *> cases_;
};
}  // namespace panda::es2panda::ir

#endif
