/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "compiler/core/labelPair.h"
#include "ir/statement.h"

namespace ark::es2panda::checker {
class TSAnalyzer;
class ETSAnalyzer;
}  // namespace ark::es2panda::checker

namespace ark::es2panda::compiler {
class JSCompiler;
class ETSCompiler;
class PandaGen;
class TryLabelSet;
class TryContext;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::ir {
class BlockStatement;
class CatchClause;

class TryStatement : public Statement {
public:
    explicit TryStatement(BlockStatement *block, ArenaVector<CatchClause *> &&catchClauses, BlockStatement *finalizer,
                          ArenaVector<std::pair<compiler::LabelPair, const Statement *>> finalizerInsertions)
        : Statement(AstNodeType::TRY_STATEMENT),
          block_(block),
          catchClauses_(std::move(catchClauses)),
          finalizer_(finalizer),
          finalizerInsertions_(std::move(finalizerInsertions))
    {
    }

    friend class checker::TSAnalyzer;
    friend class checker::ETSAnalyzer;
    friend class compiler::JSCompiler;
    friend class compiler::ETSCompiler;

    const BlockStatement *FinallyBlock() const
    {
        return finalizer_;
    }

    BlockStatement *Block() const
    {
        return block_;
    }

    std::pair<compiler::LabelPair, const Statement *> AddFinalizerInsertion(compiler::LabelPair insertion,
                                                                            const Statement *insertionStmt)
    {
        finalizerInsertions_.push_back(std::pair<compiler::LabelPair, const Statement *>(insertion, insertionStmt));
        return finalizerInsertions_.back();
    }

    [[nodiscard]] bool HasFinalizer() const noexcept
    {
        return finalizer_ != nullptr;
    }

    bool HasDefaultCatchClause() const;

    const ArenaVector<CatchClause *> &CatchClauses() const
    {
        return catchClauses_;
    }

    void TransformChildren(const NodeTransformer &cb, std::string_view transformationName) override;

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Dump(ir::SrcDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    void Compile([[maybe_unused]] compiler::ETSGen *etsg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

    void Accept(ASTVisitorT *v) override
    {
        v->Accept(this);
    }

private:
    BlockStatement *block_;
    ArenaVector<CatchClause *> catchClauses_;
    BlockStatement *finalizer_;
    ArenaVector<std::pair<compiler::LabelPair, const Statement *>> finalizerInsertions_;
};
}  // namespace ark::es2panda::ir

#endif
