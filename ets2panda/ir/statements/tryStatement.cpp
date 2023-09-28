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

#include "tryStatement.h"

#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/compiler/core/dynamicContext.h"
#include "plugins/ecmascript/es2panda/compiler/base/catchTable.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/catchClause.h"
#include "plugins/ecmascript/es2panda/ir/statements/blockStatement.h"

namespace panda::es2panda::ir {
void TryStatement::Iterate(const NodeTraverser &cb) const
{
    cb(block_);

    for (auto *it : catch_clauses_) {
        cb(it);
    }

    if (finalizer_ != nullptr) {
        cb(finalizer_);
    }
}

void TryStatement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TryStatement"},
                 {"block", block_},
                 {"handler", catch_clauses_},
                 {"finalizer", AstDumper::Nullable(finalizer_)}});
}

bool TryStatement::HasDefaultCatchClause() const
{
    return (!catch_clauses_.empty() && catch_clauses_.back()->IsDefaultCatchClause());
}

void TryStatement::CompileTryCatch(compiler::PandaGen *pg) const
{
    ASSERT(catch_clauses_.size() == 1);
    ASSERT(catch_clauses_.front() && !finalizer_);

    compiler::TryContext try_ctx(pg, this);
    const auto &label_set = try_ctx.LabelSet();

    pg->SetLabel(this, label_set.TryBegin());
    block_->Compile(pg);
    pg->SetLabel(this, label_set.TryEnd());

    pg->Branch(this, label_set.CatchEnd());

    pg->SetLabel(this, label_set.CatchBegin());
    catch_clauses_.front()->Compile(pg);
    pg->SetLabel(this, label_set.CatchEnd());
}

void TryStatement::CompileTryCatchFinally(compiler::PandaGen *pg) const
{
    ASSERT(catch_clauses_.size() == 1);
    ASSERT(catch_clauses_.front() && finalizer_);

    compiler::TryContext try_ctx(pg, this);
    const auto &label_set = try_ctx.LabelSet();

    pg->SetLabel(this, label_set.TryBegin());
    {
        compiler::TryContext inner_try_ctx(pg, this, false);
        const auto &inner_label_set = inner_try_ctx.LabelSet();

        pg->SetLabel(this, inner_label_set.TryBegin());
        block_->Compile(pg);
        pg->SetLabel(this, inner_label_set.TryEnd());

        pg->Branch(this, inner_label_set.CatchEnd());

        pg->SetLabel(this, inner_label_set.CatchBegin());
        catch_clauses_.front()->Compile(pg);
        pg->SetLabel(this, inner_label_set.CatchEnd());
    }
    pg->SetLabel(this, label_set.TryEnd());

    CompileFinally(pg, &try_ctx, label_set);
}

void TryStatement::CompileFinally(compiler::PandaGen *pg, compiler::TryContext *try_ctx,
                                  const compiler::TryLabelSet &label_set) const
{
    compiler::RegScope rs(pg);
    compiler::VReg exception = pg->AllocReg();
    pg->StoreConst(this, exception, compiler::Constant::JS_HOLE);
    pg->Branch(this, label_set.CatchEnd());

    pg->SetLabel(this, label_set.CatchBegin());
    pg->StoreAccumulator(this, exception);

    pg->SetLabel(this, label_set.CatchEnd());

    compiler::Label *label = pg->AllocLabel();
    pg->LoadAccumulator(this, try_ctx->FinalizerRun());

    pg->BranchIfNotUndefined(this, label);
    pg->StoreAccumulator(this, try_ctx->FinalizerRun());
    try_ctx->EmitFinalizer();
    pg->SetLabel(this, label);

    pg->LoadAccumulator(this, exception);
    pg->EmitRethrow(this);
}

void TryStatement::CompileTryFinally(compiler::PandaGen *pg) const
{
    ASSERT(catch_clauses_.empty() && finalizer_);

    compiler::TryContext try_ctx(pg, this);
    const auto &label_set = try_ctx.LabelSet();

    pg->SetLabel(this, label_set.TryBegin());
    {
        compiler::TryContext inner_try_ctx(pg, this, false);
        const auto &inner_label_set = inner_try_ctx.LabelSet();

        pg->SetLabel(this, inner_label_set.TryBegin());
        block_->Compile(pg);
        pg->SetLabel(this, inner_label_set.TryEnd());

        pg->Branch(this, inner_label_set.CatchEnd());

        pg->SetLabel(this, inner_label_set.CatchBegin());
        pg->EmitThrow(this);
        pg->SetLabel(this, inner_label_set.CatchEnd());
    }
    pg->SetLabel(this, label_set.TryEnd());

    CompileFinally(pg, &try_ctx, label_set);
}

void TryStatement::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    if (finalizer_ != nullptr) {
        if (!catch_clauses_.empty()) {
            CompileTryCatchFinally(pg);
        } else {
            CompileTryFinally(pg);
        }
    } else {
        CompileTryCatch(pg);
    }
}

void TryStatement::Compile(compiler::ETSGen *etsg) const
{
    compiler::ETSTryContext try_ctx(etsg, etsg->Allocator(), this, finalizer_ != nullptr);

    compiler::LabelPair try_label_pair(etsg->AllocLabel(), etsg->AllocLabel());

    for (CatchClause *clause : catch_clauses_) {
        try_ctx.AddNewCathTable(clause->TsType()->AsETSObjectType()->AssemblerName(), try_label_pair);
    }

    compiler::Label *statement_end = etsg->AllocLabel();
    auto catch_tables = try_ctx.GetETSCatchTable();

    etsg->SetLabel(this, try_label_pair.Begin());
    block_->Compile(etsg);
    etsg->Branch(this, statement_end);
    etsg->SetLabel(this, try_label_pair.End());

    ASSERT(catch_clauses_.size() == catch_tables.size());

    for (uint32_t i = 0; i < catch_clauses_.size(); i++) {
        etsg->SetLabel(this, catch_tables.at(i)->LabelSet().CatchBegin());

        catch_clauses_.at(i)->Compile(etsg);

        etsg->Branch(this, statement_end);
    }

    etsg->SetLabel(this, statement_end);

    auto trycatch_label_pair = compiler::LabelPair(try_label_pair.Begin(), statement_end);

    try_ctx.EmitFinalizer(trycatch_label_pair, finalizer_insertions_);
}

checker::Type *TryStatement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    block_->Check(checker);

    for (auto *catch_clause : catch_clauses_) {
        if (catch_clause != nullptr) {
            catch_clause->Check(checker);
        }
    }

    if (finalizer_ != nullptr) {
        finalizer_->Check(checker);
    }

    return nullptr;
}

checker::Type *TryStatement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    std::vector<checker::ETSObjectType *> exceptions;
    block_->Check(checker);

    for (auto *catch_clause : catch_clauses_) {
        auto exception_type = catch_clause->Check(checker);

        if ((exception_type != nullptr) && (catch_clause->Param() != nullptr)) {
            auto *clause_type = exception_type->AsETSObjectType();

            for (auto *exception : exceptions) {
                checker->Relation()->IsIdenticalTo(clause_type, exception);
                if (checker->Relation()->IsTrue()) {
                    checker->ThrowTypeError("Redeclaration of exception type", catch_clause->Start());
                }
            }

            exceptions.push_back(clause_type);
        }
    }

    bool default_catch_found = false;

    for (auto *catch_clause : catch_clauses_) {
        if (default_catch_found) {
            checker->ThrowTypeError("Default catch clause should be the last in the try statement",
                                    catch_clause->Start());
        }

        default_catch_found = catch_clause->IsDefaultCatchClause();
    }

    if (finalizer_ != nullptr) {
        finalizer_->Check(checker);
    }

    return nullptr;
}
}  // namespace panda::es2panda::ir
