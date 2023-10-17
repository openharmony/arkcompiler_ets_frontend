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

#ifndef ES2PANDA_COMPILER_CORE_CODEGEN_H
#define ES2PANDA_COMPILER_CORE_CODEGEN_H

#include "compiler/base/literals.h"
#include "compiler/core/regAllocator.h"
#include "compiler/core/regScope.h"
#include "compiler/core/dynamicContext.h"

namespace panda::es2panda::compiler {
class CatchTable;
class DynamicContext;

enum class Constant {
    JS_NAN,
    JS_HOLE,
    JS_INFINITY,
    JS_UNDEFINED,
    JS_NULL,
    JS_TRUE,
    JS_FALSE,
    JS_SYMBOL,
    JS_GLOBAL,
};

class DebugInfo {
public:
    explicit DebugInfo(ArenaAllocator *allocator) : variable_debug_info_(allocator->Adapter()) {};
    DEFAULT_COPY_SEMANTIC(DebugInfo);
    DEFAULT_MOVE_SEMANTIC(DebugInfo);
    ~DebugInfo() = default;

    ArenaVector<const binder::Scope *> &VariableDebugInfo()
    {
        return variable_debug_info_;
    }

    const ArenaVector<const binder::Scope *> &VariableDebugInfo() const
    {
        return variable_debug_info_;
    }

    const ir::Statement *FirstStatement() const
    {
        return first_stmt_;
    }

private:
    friend class CodeGen;

    ArenaVector<const binder::Scope *> variable_debug_info_;
    const ir::Statement *first_stmt_ {};
};

class CodeGen {
public:
    using TypeMap = ArenaUnorderedMap<VReg, const checker::Type *>;

    explicit CodeGen(ArenaAllocator *allocator, RegSpiller *spiller, CompilerContext *context,
                     binder::FunctionScope *scope, ProgramElement *program_element) noexcept
        : allocator_(allocator),
          context_(context),
          debug_info_(allocator_),
          top_scope_(scope),
          scope_(top_scope_),
          root_node_(scope->Node()),
          insns_(allocator_->Adapter()),
          catch_list_(allocator_->Adapter()),
          type_map_(allocator_->Adapter()),
          program_element_(program_element),
          sa_(this),
          ra_(this, spiller),
          rra_(this, spiller)
    {
    }
    virtual ~CodeGen() = default;
    NO_COPY_SEMANTIC(CodeGen);
    NO_MOVE_SEMANTIC(CodeGen);

    [[nodiscard]] virtual IRNode *AllocMov(const ir::AstNode *node, VReg vd, VReg vs) = 0;
    [[nodiscard]] virtual IRNode *AllocMov(const ir::AstNode *node, OutVReg vd, VReg vs) = 0;

    [[nodiscard]] ArenaAllocator *Allocator() const noexcept;
    [[nodiscard]] const ArenaVector<CatchTable *> &CatchList() const noexcept;
    [[nodiscard]] const binder::FunctionScope *TopScope() const noexcept;
    [[nodiscard]] const binder::Scope *Scope() const noexcept;
    [[nodiscard]] const ir::AstNode *RootNode() const noexcept;

    [[nodiscard]] ArenaVector<IRNode *> &Insns() noexcept;
    [[nodiscard]] const ArenaVector<IRNode *> &Insns() const noexcept;

    [[nodiscard]] VReg AllocReg();
    [[nodiscard]] VReg AllocRegWithType(const checker::Type *type);
    [[nodiscard]] VReg NextReg() const noexcept;

    [[nodiscard]] std::uint32_t TotalRegsNum() const noexcept;
    [[nodiscard]] std::size_t LabelCount() const noexcept;
    [[nodiscard]] const DebugInfo &Debuginfo() const noexcept;
    [[nodiscard]] constexpr std::uint32_t IcSize() const noexcept
    {
        return 0U;
    }

    [[nodiscard]] bool IsDebug() const noexcept;
    [[nodiscard]] std::uint32_t ParamCount() const noexcept;
    [[nodiscard]] std::uint32_t FormalParametersCount() const noexcept;
    [[nodiscard]] std::uint32_t InternalParamCount() const noexcept;
    [[nodiscard]] const util::StringView &InternalName() const noexcept;
    [[nodiscard]] const util::StringView &FunctionName() const noexcept;
    [[nodiscard]] binder::Binder *Binder() const noexcept;

    [[nodiscard]] Label *AllocLabel();
    [[nodiscard]] std::int32_t AddLiteralBuffer(LiteralBuffer &&buf);

    void LoadAccumulatorString(const ir::AstNode *node, const util::StringView &str);

    void SetLabel(const ir::AstNode *node, Label *label);
    void Branch(const ir::AstNode *node, class Label *label);
    [[nodiscard]] bool CheckControlFlowChange() const;
    Label *ControlFlowChangeBreak(const ir::Identifier *label = nullptr);
    [[nodiscard]] Label *ControlFlowChangeContinue(const ir::Identifier *label);

    uint32_t TryDepth() const;
    [[nodiscard]] CatchTable *CreateCatchTable(util::StringView exception_type = "");
    [[nodiscard]] CatchTable *CreateCatchTable(LabelPair try_label_pair, util::StringView exception_type = "");
    void SortCatchTables();

    void SetFirstStmt(const ir::Statement *stmt) noexcept;

    [[noreturn]] static void Unimplemented();

    void SetVRegType(VReg vreg, const checker::Type *type);

    [[nodiscard]] virtual const checker::Type *GetVRegType(VReg vreg) const;

    [[nodiscard]] CompilerContext *Context() const noexcept;

    [[nodiscard]] virtual checker::Type const *TypeForVar(binder::Variable const *var) const noexcept;

protected:
    [[nodiscard]] SimpleAllocator &Sa() noexcept;
    [[nodiscard]] const SimpleAllocator &Sa() const noexcept;
    [[nodiscard]] RegAllocator &Ra() noexcept;
    [[nodiscard]] const RegAllocator &Ra() const noexcept;
    [[nodiscard]] RangeRegAllocator &Rra() noexcept;
    [[nodiscard]] const RangeRegAllocator &Rra() const noexcept;
    [[nodiscard]] ProgramElement *ProgElement() const noexcept;
    [[nodiscard]] TypeMap &GetTypeMap() noexcept;
    [[nodiscard]] const TypeMap &GetTypeMap() const noexcept;

private:
    ArenaAllocator *allocator_ {};
    CompilerContext *context_ {};
    DebugInfo debug_info_;
    binder::FunctionScope *top_scope_ {};
    binder::Scope *scope_ {};
    const ir::AstNode *root_node_ {};
    ArenaVector<IRNode *> insns_;
    ArenaVector<CatchTable *> catch_list_;
    TypeMap type_map_;
    ProgramElement *program_element_ {};
    DynamicContext *dynamic_context_ {};

    SimpleAllocator sa_;
    RegAllocator ra_;
    RangeRegAllocator rra_;
    std::size_t label_id_ {0};
    std::int32_t literal_buffer_idx_ {0};

    std::uint32_t used_regs_ {VReg::REG_START};
    std::uint32_t total_regs_ {VReg::REG_START};
    friend class ScopeContext;
    friend class RegScope;
    friend class LocalRegScope;
    friend class LoopRegScope;
    friend class ParamRegScope;
    friend class FunctionRegScope;
    friend class DynamicContext;
};
}  // namespace panda::es2panda::compiler

#endif
