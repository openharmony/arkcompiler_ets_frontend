/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "codeGen.h"

#include "compiler/core/emitter.h"
#include "compiler/core/regAllocator.h"
#include "compiler/core/regScope.h"
#include "compiler/core/compilerContext.h"
#include "compiler/core/dynamicContext.h"
#include "compiler/base/catchTable.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/identifier.h"

namespace panda::es2panda::compiler {

ArenaAllocator *CodeGen::Allocator() const noexcept
{
    return allocator_;
}

const ArenaVector<CatchTable *> &CodeGen::CatchList() const noexcept
{
    return catch_list_;
}

const binder::FunctionScope *CodeGen::TopScope() const noexcept
{
    return top_scope_;
}

const binder::Scope *CodeGen::Scope() const noexcept
{
    return scope_;
}

const ir::AstNode *CodeGen::RootNode() const noexcept
{
    return root_node_;
}

ArenaVector<IRNode *> &CodeGen::Insns() noexcept
{
    return insns_;
}

const ArenaVector<IRNode *> &CodeGen::Insns() const noexcept
{
    return insns_;
}

VReg CodeGen::NextReg() const noexcept
{
    return VReg {used_regs_};
}

std::uint32_t CodeGen::TotalRegsNum() const noexcept
{
    return total_regs_;
}

std::size_t CodeGen::LabelCount() const noexcept
{
    return label_id_;
}

const DebugInfo &CodeGen::Debuginfo() const noexcept
{
    return debug_info_;
}

VReg CodeGen::AllocReg()
{
    const VReg vreg(used_regs_--);
    SetVRegType(vreg, nullptr);
    return vreg;
}

VReg CodeGen::AllocRegWithType(const checker::Type *const type)
{
    const VReg vreg(used_regs_--);
    SetVRegType(vreg, type);
    return vreg;
}

void CodeGen::SetVRegType(const VReg vreg, const checker::Type *const type)
{
    type_map_.insert_or_assign(vreg, type);
}

const checker::Type *CodeGen::GetVRegType(const VReg vreg) const
{
    const auto it = type_map_.find(vreg);
    return it != type_map_.end() ? it->second : nullptr;
}

checker::Type const *CodeGen::TypeForVar(binder::Variable const *var) const noexcept
{
    return var->TsType();
}

Label *CodeGen::AllocLabel()
{
    std::string id = std::string {Label::PREFIX} + std::to_string(label_id_++);
    return sa_.AllocLabel(std::move(id));
}

bool CodeGen::IsDebug() const noexcept
{
    return context_->IsDebug();
}

std::uint32_t CodeGen::ParamCount() const noexcept
{
    if (root_node_->IsProgram()) {
        return 0U;
    }

    return root_node_->AsScriptFunction()->Params().size();
}

std::uint32_t CodeGen::FormalParametersCount() const noexcept
{
    if (root_node_->IsProgram()) {
        return 0U;
    }

    ASSERT(root_node_->IsScriptFunction());

    return root_node_->AsScriptFunction()->FormalParamsLength();
}

std::uint32_t CodeGen::InternalParamCount() const noexcept
{
    static constexpr std::uint32_t HIDDEN_PARAMS = 3U;
    return ParamCount() + HIDDEN_PARAMS;
}

const util::StringView &CodeGen::InternalName() const noexcept
{
    return top_scope_->InternalName();
}

const util::StringView &CodeGen::FunctionName() const noexcept
{
    return top_scope_->Name();
}

binder::Binder *CodeGen::Binder() const noexcept
{
    return context_->Binder();
}

std::int32_t CodeGen::AddLiteralBuffer(LiteralBuffer &&buf)
{
    program_element_->BuffStorage().emplace_back(std::move(buf));
    return literal_buffer_idx_++;
}

void CodeGen::LoadAccumulatorString(const ir::AstNode *node, const util::StringView &str)
{
    sa_.Emit<LdaStr>(node, str);
}

void CodeGen::SetLabel([[maybe_unused]] const ir::AstNode *node, Label *label)
{
    sa_.AddLabel(label);
}

void CodeGen::Branch(const ir::AstNode *node, Label *label)
{
    sa_.Emit<Jmp>(node, label);
}

bool CodeGen::CheckControlFlowChange() const
{
    const auto *iter = dynamic_context_;

    while (iter != nullptr) {
        if (iter->HasFinalizer()) {
            return true;
        }

        iter = iter->Prev();
    }

    return false;
}

Label *CodeGen::ControlFlowChangeBreak(const ir::Identifier *label)
{
    auto *iter = dynamic_context_;

    util::StringView label_name = label != nullptr ? label->Name() : LabelTarget::BREAK_LABEL;
    Label *break_target = nullptr;

    while (iter != nullptr) {
        iter->AbortContext(ControlFlowChange::BREAK, label_name);
        const auto *const_iter = iter;

        const auto &label_target_name = const_iter->Target().BreakLabel();

        if (const_iter->Target().BreakTarget() != nullptr) {
            break_target = const_iter->Target().BreakTarget();
        }

        if (label_target_name == label_name) {
            break;
        }

        iter = iter->Prev();
    }

    return break_target;
}

Label *CodeGen::ControlFlowChangeContinue(const ir::Identifier *label)
{
    auto *iter = dynamic_context_;
    util::StringView label_name = label != nullptr ? label->Name() : LabelTarget::CONTINUE_LABEL;
    Label *continue_target = nullptr;

    while (iter != nullptr) {
        iter->AbortContext(ControlFlowChange::CONTINUE, label_name);
        const auto *const_iter = iter;

        const auto &label_target_name = const_iter->Target().ContinueLabel();

        if (const_iter->Target().ContinueTarget() != nullptr) {
            continue_target = const_iter->Target().ContinueTarget();
        }

        if (label_target_name == label_name) {
            break;
        }

        iter = iter->Prev();
    }

    return continue_target;
}

std::uint32_t CodeGen::TryDepth() const
{
    const auto *iter = dynamic_context_;
    std::uint32_t depth = 0;

    while (iter != nullptr) {
        if (iter->HasTryCatch()) {
            depth++;
        }

        iter = iter->Prev();
    }

    return depth;
}

CatchTable *CodeGen::CreateCatchTable(const util::StringView exception_type)
{
    auto *catch_table = allocator_->New<CatchTable>(this, TryDepth(), exception_type);
    catch_list_.push_back(catch_table);
    return catch_table;
}

CatchTable *CodeGen::CreateCatchTable(const LabelPair try_label_pair, const util::StringView exception_type)
{
    auto *catch_table = allocator_->New<CatchTable>(this, TryDepth(), try_label_pair, exception_type);
    catch_list_.push_back(catch_table);
    return catch_table;
}

void CodeGen::SortCatchTables()
{
    std::stable_sort(catch_list_.begin(), catch_list_.end(),
                     [](const CatchTable *a, const CatchTable *b) { return b->Depth() < a->Depth(); });
}

void CodeGen::SetFirstStmt(const ir::Statement *stmt) noexcept
{
    debug_info_.first_stmt_ = stmt;
}

void CodeGen::Unimplemented()
{
    throw Error(ErrorType::GENERIC, "", "Unimplemented code path");
}

SimpleAllocator &CodeGen::Sa() noexcept
{
    return sa_;
}

const SimpleAllocator &CodeGen::Sa() const noexcept
{
    return sa_;
}

RegAllocator &CodeGen::Ra() noexcept
{
    return ra_;
}

const RegAllocator &CodeGen::Ra() const noexcept
{
    return ra_;
}

RangeRegAllocator &CodeGen::Rra() noexcept
{
    return rra_;
}

const RangeRegAllocator &CodeGen::Rra() const noexcept
{
    return rra_;
}

CompilerContext *CodeGen::Context() const noexcept
{
    return context_;
}

ProgramElement *CodeGen::ProgElement() const noexcept
{
    return program_element_;
}

CodeGen::TypeMap &CodeGen::GetTypeMap() noexcept
{
    return type_map_;
}

const CodeGen::TypeMap &CodeGen::GetTypeMap() const noexcept
{
    return type_map_;
}

}  // namespace panda::es2panda::compiler
