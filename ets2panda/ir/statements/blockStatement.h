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

#ifndef ES2PANDA_IR_STATEMENT_BLOCK_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_BLOCK_STATEMENT_H

#include "ir/statement.h"

namespace panda::es2panda::binder {
class Scope;
}  // namespace panda::es2panda::binder

namespace panda::es2panda::ir {
class BlockStatement : public Statement {
public:
    explicit BlockStatement(ArenaAllocator *allocator, binder::Scope *scope, ArenaVector<Statement *> &&statement_list)
        : Statement(AstNodeType::BLOCK_STATEMENT),
          scope_(scope),
          statements_(std::move(statement_list)),
          trailing_blocks_(allocator->Adapter())
    {
    }

    binder::Scope *Scope() const
    {
        return scope_;
    }

    void SetScope(binder::Scope *scope)
    {
        scope_ = scope;
    }

    const ArenaVector<Statement *> &Statements() const
    {
        return statements_;
    }

    ArenaVector<Statement *> &Statements()
    {
        return statements_;
    }

    void AddTrailingBlock(AstNode *stmt, BlockStatement *trailing_block)
    {
        trailing_blocks_.emplace(stmt, trailing_block);
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    binder::Scope *scope_;
    ArenaVector<Statement *> statements_;
    ArenaUnorderedMap<AstNode *, BlockStatement *> trailing_blocks_;
};
}  // namespace panda::es2panda::ir

#endif
