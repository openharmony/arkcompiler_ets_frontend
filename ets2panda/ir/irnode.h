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

#ifndef ES2PANDA_COMPILER_IR_IRNODE_H
#define ES2PANDA_COMPILER_IR_IRNODE_H

#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/compiler/core/vReg.h"
#include "plugins/ecmascript/es2panda/compiler/core/programElement.h"
#include "plugins/ecmascript/es2panda/lexer/token/sourceLocation.h"
#include "macros.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"
#include "utils/span.h"

#include <cstdint>
#include <list>
#include <limits>
#include <sstream>
#include <utility>
#include <variant>
#include <vector>

namespace panda::es2panda::ir {
class AstNode;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::compiler {
enum class OperandKind {
    // the least significant bit indicates vreg
    // the second bit indicates src or dst
    SRC_VREG,
    DST_VREG,
    SRC_DST_VREG,
    IMM,
    ID,
    STRING_ID,
    LABEL
};

enum class OperandType {
    REF,  // ref
    B32,  // u1 u2 i8 u8 i16 u16 i32 u32 b32 f32
    B64,  // i64, f64, b64
    ANY,  // any
    NONE
};

struct OutVReg {
    const VReg *reg;
    OperandType type;
};

class FormatItem {
public:
    constexpr FormatItem(OperandKind kind, uint32_t bit_width) : kind_(kind), bit_width_(bit_width) {}

    OperandKind Kind() const
    {
        return kind_;
    };

    bool constexpr IsVReg() const
    {
        return kind_ == OperandKind::SRC_VREG || kind_ == OperandKind::DST_VREG || kind_ == OperandKind::SRC_DST_VREG;
    }

    uint32_t BitWidth() const
    {
        return bit_width_;
    };

private:
    OperandKind kind_;
    uint32_t bit_width_;
};

class Format {
public:
    constexpr Format(const FormatItem *item, size_t size) : item_(item), size_(size) {}

    panda::Span<const FormatItem> GetFormatItem() const
    {
        return panda::Span<const FormatItem>(item_, size_);
    }

private:
    const FormatItem *item_;
    size_t size_;
};

using Formats = panda::Span<const Format>;

class Label;
class IRNode;

using Operand = std::variant<compiler::VReg, double, int64_t, util::StringView, Label *>;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define FIRST_NODE_OF_FUNCTION (reinterpret_cast<ir::AstNode *>(0x1))

class IRNode {
public:
    explicit IRNode(const ir::AstNode *node) : node_(node) {};
    virtual ~IRNode() = default;

    NO_COPY_SEMANTIC(IRNode);
    NO_MOVE_SEMANTIC(IRNode);

    const ir::AstNode *Node() const
    {
        return node_;
    }

    static uint16_t MapRegister(uint32_t reg, uint32_t total_regs)
    {
        ASSERT(reg != VReg::Invalid().GetIndex());

        uint32_t reg_count = VReg::REG_START - total_regs;
        uint16_t new_reg = 0;

        if (reg >= VReg::PARAM_START) {
            new_reg = reg - VReg::PARAM_START + reg_count;
            // TODO(dbatiz) Remove this else if, and fix the regIndexes
        } else if (reg <= reg_count + VReg::MANDATORY_PARAM_NUM) {
            new_reg = VReg::REG_START - total_regs + VReg::MANDATORY_PARAM_NUM + reg;
        } else {
            uint32_t reg_offset = reg - total_regs;
            new_reg = std::abs(static_cast<int32_t>(reg_offset - reg_count));
        }

        return new_reg;
    }

    static constexpr auto MAX_REG_OPERAND = 5;

    virtual Formats GetFormats() const = 0;
    virtual size_t Registers([[maybe_unused]] std::array<VReg *, MAX_REG_OPERAND> *regs) = 0;
    virtual size_t Registers([[maybe_unused]] std::array<const VReg *, MAX_REG_OPERAND> *regs) const = 0;
    virtual size_t OutRegisters([[maybe_unused]] std::array<OutVReg, MAX_REG_OPERAND> *regs) const = 0;
    virtual void Transform(panda::pandasm::Ins *ins, [[maybe_unused]] ProgramElement *program_element,
                           [[maybe_unused]] uint32_t total_regs) const = 0;

private:
    const ir::AstNode *node_;
};
}  // namespace panda::es2panda::compiler

#endif
