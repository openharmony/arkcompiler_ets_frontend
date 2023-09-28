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

#include "regAllocator.h"

#include "plugins/ecmascript/es2panda/compiler/core/codeGen.h"
#include "plugins/ecmascript/es2panda/checker/types/type.h"

#include <algorithm>
#include <vector>

namespace panda::es2panda::compiler {
// AllocatorBase

AllocatorBase::AllocatorBase(CodeGen *const cg) noexcept : cg_(cg) {}

void AllocatorBase::PushBack(IRNode *const ins) const
{
    cg_->Insns().push_back(ins);
}

CodeGen &AllocatorBase::GetCodeGen() noexcept
{
    return *cg_;
}

const CodeGen &AllocatorBase::GetCodeGen() const noexcept
{
    return *cg_;
}

ArenaAllocator &AllocatorBase::Allocator() noexcept
{
    return *cg_->Allocator();
}

const ArenaAllocator &AllocatorBase::Allocator() const noexcept
{
    return *cg_->Allocator();
}

// SimpleAllocator

SimpleAllocator::SimpleAllocator(CodeGen *const cg) noexcept : AllocatorBase(cg) {}

Label *SimpleAllocator::AllocLabel(std::string &&id)
{
    const auto *last_ins_node =
        GetCodeGen().Insns().empty() ? FIRST_NODE_OF_FUNCTION : GetCodeGen().Insns().back()->Node();
    return Alloc<Label>(last_ins_node, std::move(id));
}

void SimpleAllocator::AddLabel(Label *const label) const
{
    PushBack(label);
}

// RegAllocatorBase

RegAllocatorBase::RegAllocatorBase(CodeGen *const cg, RegSpiller *const spiller) noexcept
    : AllocatorBase(cg), spiller_(spiller)
{
}

RegSpiller &RegAllocatorBase::Spiller() noexcept
{
    return *spiller_;
}

const RegSpiller &RegAllocatorBase::Spiller() const noexcept
{
    return *spiller_;
}

std::pair<bool, std::size_t> RegAllocatorBase::RegIndicesValid(const IRNode *const ins, const Span<VReg *> &registers)
{
    const auto &formats = ins->GetFormats();
    std::size_t limit = 0;

    for (const auto &format : formats) {
        for (const auto &format_item : format.GetFormatItem()) {
            if (format_item.IsVReg()) {
                limit = 1U << format_item.BitWidth();
                break;
            }
        }

        if (std::all_of(registers.begin(), registers.end(),
                        [limit](const VReg *const reg) { return reg->IsValid(limit); })) {
            return {true, limit};
        }
    }

    return {false, limit};
}

VReg RegAllocatorBase::Spill(IRNode *const ins, const VReg reg) const
{
    const auto [spill_info, origin_type] = spiller_->New();

    if (origin_type != nullptr) {
        if (auto *const mov = spiller_->MoveReg(ins->Node(), spill_info.SpillReg(), spill_info.OriginReg(), true);
            mov != nullptr) {
            PushBack(mov);
        }
    }

    if (auto *const mov = spiller_->MoveReg(ins->Node(), spill_info.OriginReg(), reg, false); mov != nullptr) {
        PushBack(mov);
    }

    return spill_info.OriginReg();
}

void RegAllocatorBase::Restore(const IRNode *const ins) const
{
    const auto spill_info = spiller_->Restore();

    if (spiller_->GetCodeGen()->GetVRegType(spill_info.OriginReg()) == nullptr) {
        return;
    }

    if (auto *const mov = spiller_->MoveReg(ins->Node(), spill_info.OriginReg(), spill_info.SpillReg(), false);
        mov != nullptr) {
        PushBack(mov);
    }
}

// RegAllocator

RegAllocator::RegAllocator(CodeGen *const cg, RegSpiller *const spiller) noexcept : RegAllocatorBase(cg, spiller) {}

void RegAllocator::Run(IRNode *const ins, const int32_t spill_max)
{
    ASSERT(Spiller().Restored());
    std::array<VReg *, IRNode::MAX_REG_OPERAND> regs {};
    const auto reg_cnt = ins->Registers(&regs);
    const auto registers = Span<VReg *>(
        regs.data(), regs.data() + (spill_max == std::numeric_limits<int32_t>::max() ? reg_cnt : spill_max));

    std::array<OutVReg, IRNode::MAX_REG_OPERAND> dst_regs {};
    ins->OutRegisters(&dst_regs);

    const auto [indices_valid, limit] = RegIndicesValid(ins, registers);
    if (indices_valid) {
        PushBack(ins);
        return;
    }

    const auto rs = Spiller().Start(GetCodeGen());

    std::unordered_set<VReg> valid_regs;
    for (auto *const reg : registers) {
        if (!reg->IsValid(limit)) {
            continue;
        }

        valid_regs.insert(*reg);
    }

    std::vector<IRNode *> dst_moves;
    size_t i = 0;
    for (auto *const reg : registers) {
        if (reg->IsValid(limit)) {
            continue;
        }

        Spiller().Adjust(valid_regs);

        auto r = Spill(ins, *reg);

        auto dst_info = dst_regs[i++];
        if (dst_info.reg != nullptr) {
            dst_moves.push_back(GetCodeGen().AllocMov(ins->Node(), dst_info, r));
        }

        *reg = r;
    }

    PushBack(ins);

    for (auto *mov : dst_moves) {
        PushBack(mov);
    }

    while (!Spiller().Restored()) {
        Restore(ins);
    }

    Spiller().Finalize();
}

// RangeRegAllocator

RangeRegAllocator::RangeRegAllocator(CodeGen *const cg, RegSpiller *const spiller) noexcept
    : RegAllocatorBase(cg, spiller)
{
}

void RangeRegAllocator::Run(IRNode *const ins, VReg range_start, const std::size_t arg_count)
{
    ASSERT(Spiller().Restored());
    const auto range_end = range_start + arg_count;

    std::array<VReg *, IRNode::MAX_REG_OPERAND> regs {};
    const auto reg_cnt = ins->Registers(&regs);
    const auto registers = Span<VReg *>(regs.data(), regs.data() + reg_cnt);

    if (RegIndicesValid(ins, registers).first) {
        PushBack(ins);
        return;
    }

    const auto rs = Spiller().Start(GetCodeGen());

    auto reg_iter = registers.begin();
    const auto reg_iter_end =
        reg_iter + registers.size() - 1;  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    while (reg_iter != reg_iter_end) {
        auto *const reg = *reg_iter;

        *reg = Spill(ins, *reg);
        reg_iter++;  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    auto *const reg_start_reg = *reg_iter;
    auto reg = range_start++;
    *reg_start_reg = Spill(ins, reg);

    while (range_start != range_end) {
        reg = range_start++;
        Spill(ins, reg);
    }

    PushBack(ins);

    while (!Spiller().Restored()) {
        Restore(ins);
    }

    Spiller().Finalize();
}
}  // namespace panda::es2panda::compiler
