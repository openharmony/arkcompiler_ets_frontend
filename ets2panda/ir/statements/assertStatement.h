/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_STATEMENT_ASSERT_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_ASSERT_STATEMENT_H

#include "ir/statement.h"

namespace ark::es2panda::checker {
class ETSAnalyzer;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::ir {
class Expression;

class AssertStatement : public Statement {
public:
    explicit AssertStatement([[maybe_unused]] Expression *test, [[maybe_unused]] Expression *second)
        : Statement(AstNodeType::ASSERT_STATEMENT)
    {
        ES2PANDA_UNREACHABLE();
    }
    // NOTE (somas): this friend relationship can be removed once there are getters for private fields
    friend class checker::ETSAnalyzer;

    const Expression *Test() const
    {
        ES2PANDA_UNREACHABLE();
    }

    Expression *Test()
    {
        ES2PANDA_UNREACHABLE();
    }

    const Expression *Second() const
    {
        ES2PANDA_UNREACHABLE();
    }

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::VerifiedType Check([[maybe_unused]] checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

    AssertStatement *Clone(ArenaAllocator *const allocator, AstNode *const parent) override;
};
}  // namespace ark::es2panda::ir

#endif
