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

#ifndef ES2PANDA_IR_STATEMENT_TRY_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_TRY_STATEMENT_H

#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/statement.h"

namespace panda::es2panda::compiler {
class PandaGen;
class TryLabelSet;
class TryContext;
}  // namespace panda::es2panda::compiler

namespace panda::es2panda::ir {
class BlockStatement;
class CatchClause;

class TryStatement : public Statement {
public:
    explicit TryStatement(BlockStatement *block, ArenaVector<CatchClause *> &&catch_clauses, BlockStatement *finalizer,
                          ArenaVector<std::pair<compiler::LabelPair, const Statement *>> finalizer_insertions)
        : Statement(AstNodeType::TRY_STATEMENT),
          block_(block),
          catch_clauses_(std::move(catch_clauses)),
          finalizer_(finalizer),
          finalizer_insertions_(std::move(finalizer_insertions))
    {
    }

    const BlockStatement *FinallyBlock() const
    {
        return finalizer_;
    }

    BlockStatement *Block() const
    {
        return block_;
    }

    std::pair<compiler::LabelPair, const Statement *> AddFinalizerInsertion(compiler::LabelPair insertion,
                                                                            const Statement *insertion_stmt)
    {
        finalizer_insertions_.push_back(std::pair<compiler::LabelPair, const Statement *>(insertion, insertion_stmt));
        return finalizer_insertions_.back();
    }

    bool HasFinalizer()
    {
        return finalizer_ != nullptr;
    }

    bool HasDefaultCatchClause() const;

    const ArenaVector<CatchClause *> &CatchClauses() const
    {
        return catch_clauses_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    void CompileTryCatch(compiler::PandaGen *pg) const;
    void CompileTryFinally(compiler::PandaGen *pg) const;
    void CompileTryCatchFinally(compiler::PandaGen *pg) const;
    void CompileFinally(compiler::PandaGen *pg, compiler::TryContext *try_ctx,
                        const compiler::TryLabelSet &label_set) const;

    BlockStatement *block_;
    ArenaVector<CatchClause *> catch_clauses_;
    BlockStatement *finalizer_;
    ArenaVector<std::pair<compiler::LabelPair, const Statement *>> finalizer_insertions_;
};
}  // namespace panda::es2panda::ir

#endif
