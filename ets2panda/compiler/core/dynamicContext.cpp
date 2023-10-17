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

#include "dynamicContext.h"

#include "checker/types/ets/etsObjectType.h"
#include "checker/types/type.h"
#include "compiler/core/envScope.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "compiler/base/catchTable.h"
#include "ir/expressions/identifier.h"
#include "ir/base/catchClause.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/labelledStatement.h"

namespace panda::es2panda::compiler {
DynamicContext::DynamicContext(CodeGen *cg, LabelTarget target)
    : cg_(cg), target_(target), prev_(Cg()->dynamic_context_)
{
    Cg()->dynamic_context_ = this;
}

DynamicContext::~DynamicContext()
{
    Cg()->dynamic_context_ = prev_;
}

LabelContext::LabelContext(CodeGen *cg, const ir::LabelledStatement *labelled_stmt)
    : DynamicContext(cg, LabelTarget(labelled_stmt->Ident()->Name())), labelled_stmt_(labelled_stmt)
{
    if (!labelled_stmt->Body()->IsBlockStatement()) {
        return;
    }

    label_ = cg->AllocLabel();
    Target().SetBreakTarget(label_);
}

LabelContext::~LabelContext()
{
    if (label_ == nullptr) {
        return;
    }

    Cg()->SetLabel(labelled_stmt_, label_);
}

LexEnvContext::LexEnvContext(LoopEnvScope *env_scope, PandaGen *pg, LabelTarget target)
    : DynamicContext(pg, target), env_scope_(env_scope)
{
    if (!env_scope_->HasEnv()) {
        return;
    }

    catch_table_ = Cg()->CreateCatchTable();
    const auto &label_set = catch_table_->LabelSet();
    const auto *node = env_scope_->Scope()->Node();

    Cg()->SetLabel(node, label_set.TryBegin());
}

LexEnvContext::~LexEnvContext()
{
    if (!env_scope_->HasEnv()) {
        return;
    }

    const auto &label_set = catch_table_->LabelSet();
    const auto *node = env_scope_->Scope()->Node();

    Cg()->SetLabel(node, label_set.TryEnd());
    Cg()->Branch(node, label_set.CatchEnd());

    Cg()->SetLabel(node, label_set.CatchBegin());
    AsPandaGen()->PopLexEnv(node);
    AsPandaGen()->EmitThrow(node);
    Cg()->SetLabel(node, label_set.CatchEnd());
    AsPandaGen()->PopLexEnv(node);
}

PandaGen *LexEnvContext::AsPandaGen() const
{
    return static_cast<PandaGen *>(Cg());
}

bool LexEnvContext::HasTryCatch() const
{
    return env_scope_->HasEnv();
}

void LexEnvContext::AbortContext([[maybe_unused]] ControlFlowChange cfc,
                                 [[maybe_unused]] const util::StringView &target_label)
{
    if (cfc == ControlFlowChange::CONTINUE || !env_scope_->HasEnv()) {
        return;
    }

    const auto *node = env_scope_->Scope()->Node();
    AsPandaGen()->PopLexEnv(node);
}

IteratorContext::IteratorContext(PandaGen *pg, const Iterator &iterator, LabelTarget target)
    : DynamicContext(pg, target), iterator_(iterator), catch_table_(pg->CreateCatchTable())
{
    const auto &label_set = catch_table_->LabelSet();
    pg->SetLabel(iterator_.Node(), label_set.TryBegin());
}

IteratorContext::~IteratorContext()
{
    const auto &label_set = catch_table_->LabelSet();
    const auto *node = iterator_.Node();

    Cg()->SetLabel(node, label_set.TryEnd());
    Cg()->Branch(node, label_set.CatchEnd());

    Cg()->SetLabel(node, label_set.CatchBegin());
    iterator_.Close(true);
    Cg()->SetLabel(node, label_set.CatchEnd());
}

void IteratorContext::AbortContext([[maybe_unused]] ControlFlowChange cfc,
                                   [[maybe_unused]] const util::StringView &target_label)
{
    if (cfc == ControlFlowChange::CONTINUE && Target().ContinueLabel() == target_label) {
        return;
    }

    iterator_.Close(false);
}

void TryContext::InitFinalizer()
{
    ASSERT(try_stmt_);

    if (!has_finalizer_ || (try_stmt_->FinallyBlock() == nullptr)) {
        return;
    }

    auto *pg = static_cast<PandaGen *>(Cg());

    finalizer_run_ = pg->AllocReg();
    pg->StoreConst(try_stmt_, finalizer_run_, Constant::JS_UNDEFINED);
}

void CatchContext::InitCatchTable()
{
    auto *pg = static_cast<PandaGen *>(Cg());
    catch_table_ = pg->CreateCatchTable();
}

const TryLabelSet &CatchContext::LabelSet() const
{
    return catch_table_->LabelSet();
}

bool TryContext::HasFinalizer() const
{
    return has_finalizer_;
}

void TryContext::EmitFinalizer()
{
    if (!has_finalizer_ || in_finalizer_ || (try_stmt_->FinallyBlock() == nullptr)) {
        return;
    }

    auto *pg = static_cast<PandaGen *>(Cg());
    in_finalizer_ = true;
    try_stmt_->FinallyBlock()->Compile(pg);
    in_finalizer_ = false;
}

CatchTable *ETSCatchContext::AddNewCathTable(const util::StringView assembler_type)
{
    auto *cg = Cg();

    CatchTable *catch_table = cg->CreateCatchTable(assembler_type);
    catch_tables_.push_back(catch_table);

    return catch_table;
}

CatchTable *ETSCatchContext::AddNewCathTable(const util::StringView assembler_type, const LabelPair try_label_pair)
{
    auto *cg = Cg();

    CatchTable *catch_table = cg->CreateCatchTable(try_label_pair, assembler_type);
    catch_tables_.push_back(catch_table);

    return catch_table;
}

void ETSTryContext::EmitFinalizer(
    LabelPair trycatch_label_pair,
    const ArenaVector<std::pair<compiler::LabelPair, const ir::Statement *>> &finalizer_insertions)
{
    ASSERT(try_stmt_);

    if (!has_finalizer_ || (try_stmt_->FinallyBlock() == nullptr)) {
        return;
    }
    auto *etsg = static_cast<ETSGen *>(Cg());

    CatchTable *finalizer_table = AddNewCathTable("", trycatch_label_pair);
    // First compile of the finaly clause, executed if the statement executed normally
    try_stmt_->FinallyBlock()->Compile(etsg);

    etsg->Branch(try_stmt_, finalizer_table->LabelSet().CatchEnd());

    for (std::pair<compiler::LabelPair, const ir::Statement *> insertion : finalizer_insertions) {
        etsg->SetLabel(try_stmt_, insertion.first.Begin());

        ASSERT(insertion.second != nullptr);
        bool is_return = insertion.second->IsReturnStatement();

        compiler::RegScope rs(etsg);
        compiler::VReg res = etsg->AllocReg();

        if (is_return) {
            etsg->SetAccumulatorType(insertion.second->AsReturnStatement()->ReturnType());
            etsg->StoreAccumulator(try_stmt_, res);
            etsg->SetVRegType(res, insertion.second->AsReturnStatement()->ReturnType());
        }

        // Second compile of the finaly clause, executed if the statement executed normally, but abrupted by
        // return, break, or continue statements.
        try_stmt_->FinallyBlock()->Compile(etsg);

        if (is_return) {
            etsg->SetAccumulatorType(insertion.second->AsReturnStatement()->ReturnType());
            etsg->LoadAccumulator(try_stmt_, res);
        }

        if (insertion.first.End() != nullptr) {
            etsg->Branch(try_stmt_, insertion.first.End());
        } else if (is_return) {
            if (etsg->CheckControlFlowChange()) {
                etsg->StoreAccumulator(try_stmt_, res);
                etsg->ControlFlowChangeBreak();
                etsg->LoadAccumulator(try_stmt_, res);
            }

            if (insertion.second->AsReturnStatement()->ReturnType()->IsETSVoidType()) {
                etsg->EmitReturnVoid(try_stmt_);
            } else {
                etsg->ApplyConversion(try_stmt_, insertion.second->AsReturnStatement()->ReturnType());
                etsg->ReturnAcc(try_stmt_);
            }

        } else if (insertion.second->IsBreakStatement()) {
            compiler::Label *target = etsg->ControlFlowChangeBreak(insertion.second->AsBreakStatement()->Ident());
            etsg->Branch(try_stmt_, target);
        } else if (insertion.second->IsContinueStatement()) {
            compiler::Label *target = etsg->ControlFlowChangeContinue(insertion.second->AsContinueStatement()->Ident());
            etsg->Branch(try_stmt_, target);
        } else {
            UNREACHABLE();
        }
    }

    etsg->SetLabel(try_stmt_, finalizer_table->LabelSet().CatchBegin());

    compiler::VReg exception = etsg->StoreException(try_stmt_);
    // Third compile of the finaly clause, executed if the statement executed abruptly
    try_stmt_->FinallyBlock()->Compile(etsg);

    etsg->LoadAccumulator(try_stmt_, exception);
    etsg->EmitThrow(try_stmt_, exception);

    etsg->SetLabel(try_stmt_, finalizer_table->LabelSet().CatchEnd());
}

}  // namespace panda::es2panda::compiler
