/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License GetReg
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitGetRegions under the License.
 */

#ifndef ES2PANDA_COMPILER_CORE_REG_SPILLER_H
#define ES2PANDA_COMPILER_CORE_REG_SPILLER_H

#include "ir/irnode.h"
#include "compiler/core/regScope.h"

namespace panda::es2panda::ir {
class AstNode;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::compiler {
class CodeGen;

class RegSpiller {
protected:
    class SpillInfo final {
    public:
        constexpr explicit SpillInfo(VReg origin_reg, VReg spill_reg) noexcept;

        [[nodiscard]] constexpr VReg OriginReg() const noexcept;
        [[nodiscard]] constexpr VReg SpillReg() const noexcept;
        [[nodiscard]] constexpr SpillInfo Reversed() const noexcept;

    private:
        VReg origin_reg_ {VReg::Invalid()};
        VReg spill_reg_ {VReg::Invalid()};
    };

public:
    explicit RegSpiller() = default;
    NO_COPY_SEMANTIC(RegSpiller);
    NO_MOVE_SEMANTIC(RegSpiller);
    virtual ~RegSpiller() = default;

    [[nodiscard]] virtual RegScope Start(CodeGen &cg) = 0;
    [[nodiscard]] virtual SpillInfo Restore() = 0;
    [[nodiscard]] virtual bool Restored() const = 0;
    [[nodiscard]] virtual IRNode *MoveReg(const ir::AstNode *node, VReg vd, VReg vs, bool spill_mov) = 0;
    virtual void Finalize() noexcept = 0;

    [[nodiscard]] CodeGen *GetCodeGen() const noexcept;
    [[nodiscard]] std::pair<SpillInfo, const checker::Type *> New() noexcept;
    void Adjust(const std::unordered_set<VReg> &regs) noexcept;

protected:
    void SetCodeGen(CodeGen &cg) noexcept;
    std::uint32_t SpillIndex() const noexcept;
    std::uint32_t &SpillIndex() noexcept;

private:
    CodeGen *cg_ {};
    std::uint32_t spill_index_ {0};
};

class DynamicRegSpiller final : public RegSpiller {
public:
    explicit DynamicRegSpiller() = default;
    NO_COPY_SEMANTIC(DynamicRegSpiller);
    NO_MOVE_SEMANTIC(DynamicRegSpiller);
    ~DynamicRegSpiller() override = default;

    [[nodiscard]] RegScope Start(CodeGen &cg) override;
    [[nodiscard]] SpillInfo Restore() override;
    [[nodiscard]] bool Restored() const override;
    [[nodiscard]] IRNode *MoveReg(const ir::AstNode *node, VReg vd, VReg vs, bool spill_mov) override;
    void Finalize() noexcept override;

private:
    std::uint32_t reg_end_ {0};
};

class StaticRegSpiller final : public RegSpiller {
public:
    explicit StaticRegSpiller() = default;
    NO_COPY_SEMANTIC(StaticRegSpiller);
    NO_MOVE_SEMANTIC(StaticRegSpiller);
    ~StaticRegSpiller() override = default;

    [[nodiscard]] RegScope Start(CodeGen &cg) override;
    [[nodiscard]] SpillInfo Restore() override;
    [[nodiscard]] bool Restored() const override;
    [[nodiscard]] IRNode *MoveReg(const ir::AstNode *node, VReg vd, VReg vs, bool spill_mov) override;
    void Finalize() noexcept override;

private:
    std::vector<SpillInfo> spills_ {};
};

constexpr RegSpiller::SpillInfo::SpillInfo(const VReg origin_reg, const VReg spill_reg) noexcept
    : origin_reg_(origin_reg), spill_reg_(spill_reg)
{
}

constexpr VReg RegSpiller::SpillInfo::OriginReg() const noexcept
{
    return origin_reg_;
}

constexpr VReg RegSpiller::SpillInfo::SpillReg() const noexcept
{
    return spill_reg_;
}

constexpr RegSpiller::SpillInfo RegSpiller::SpillInfo::Reversed() const noexcept
{
    return SpillInfo {spill_reg_, origin_reg_};
}

}  // namespace panda::es2panda::compiler

#endif
