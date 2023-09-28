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

#ifndef ES2PANDA_COMPILER_CORE_DYNAMIC_CONTEXT_H
#define ES2PANDA_COMPILER_CORE_DYNAMIC_CONTEXT_H

#include "plugins/ecmascript/es2panda/util/ustring.h"
#include "plugins/ecmascript/es2panda/ir/irnode.h"
#include "plugins/ecmascript/es2panda/compiler/core/labelTarget.h"
#include "plugins/ecmascript/es2panda/compiler/base/iterators.h"

namespace panda::es2panda::ir {
class TryStatement;
class ForOfStatement;
class LabelledStatement;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::compiler {
class CodeGen;
class LoopEnvScope;
class CatchTable;
class TryLabelSet;

enum class DynamicContextType { NONE, LABEL, LEX_ENV, ITERATOR, TRY, TRAP };

class DynamicContext {
public:
    NO_COPY_SEMANTIC(DynamicContext);
    NO_MOVE_SEMANTIC(DynamicContext);
    ~DynamicContext();

    void *operator new(size_t) = delete;
    void *operator new[](size_t) = delete;

    virtual void AbortContext([[maybe_unused]] ControlFlowChange cfc,
                              [[maybe_unused]] const util::StringView &target_label) {};

    virtual bool HasTryCatch() const
    {
        return false;
    }

    virtual bool HasFinalizer() const
    {
        return HasTryCatch();
    }

    virtual DynamicContextType Type() const = 0;

    DynamicContext *Prev()
    {
        return prev_;
    }

    const DynamicContext *Prev() const
    {
        return prev_;
    }

    const LabelTarget &Target() const
    {
        return target_;
    }

protected:
    explicit DynamicContext(CodeGen *cg, LabelTarget target);

    LabelTarget &Target()
    {
        return target_;
    }

    CodeGen *Cg() const
    {
        return cg_;
    }

private:
    CodeGen *cg_;
    LabelTarget target_;
    DynamicContext *prev_ {};
};

class LabelContext : public DynamicContext {
public:
    explicit LabelContext(CodeGen *cg, LabelTarget target) : DynamicContext(cg, target) {}
    explicit LabelContext(CodeGen *cg, const ir::LabelledStatement *labelled_stmt);
    NO_COPY_SEMANTIC(LabelContext);
    NO_MOVE_SEMANTIC(LabelContext);
    ~LabelContext();

    DynamicContextType Type() const override
    {
        return DynamicContextType::LABEL;
    }

private:
    Label *label_ {};
    const ir::LabelledStatement *labelled_stmt_ {};
};

class LexEnvContext : public DynamicContext {
public:
    explicit LexEnvContext(LoopEnvScope *env_scope, PandaGen *pg, LabelTarget target);
    NO_COPY_SEMANTIC(LexEnvContext);
    NO_MOVE_SEMANTIC(LexEnvContext);
    ~LexEnvContext();

    DynamicContextType Type() const override
    {
        return DynamicContextType::LEX_ENV;
    }

    bool HasTryCatch() const override;
    void AbortContext([[maybe_unused]] ControlFlowChange cfc,
                      [[maybe_unused]] const util::StringView &target_label) override;

protected:
    PandaGen *AsPandaGen() const;

private:
    LoopEnvScope *env_scope_;
    CatchTable *catch_table_ {};
};

class IteratorContext : public DynamicContext {
public:
    explicit IteratorContext(PandaGen *pg, const Iterator &iterator, LabelTarget target);
    NO_COPY_SEMANTIC(IteratorContext);
    NO_MOVE_SEMANTIC(IteratorContext);
    ~IteratorContext();

    DynamicContextType Type() const override
    {
        return DynamicContextType::ITERATOR;
    }

    const Iterator &GetIterator() const
    {
        return iterator_;
    }

    bool HasTryCatch() const override
    {
        return true;
    }

    void AbortContext([[maybe_unused]] ControlFlowChange cfc,
                      [[maybe_unused]] const util::StringView &target_label) override;

private:
    const Iterator &iterator_;
    CatchTable *catch_table_;
};

class CatchContext : public DynamicContext {
public:
    NO_COPY_SEMANTIC(CatchContext);
    NO_MOVE_SEMANTIC(CatchContext);
    ~CatchContext() = default;

    CatchTable *GetCatchTable() const
    {
        return catch_table_;
    }

    const TryLabelSet &LabelSet() const;

    bool HasTryCatch() const override
    {
        return true;
    }

protected:
    explicit CatchContext(CodeGen *cg) : DynamicContext(cg, {})
    {
        InitCatchTable();
    }

private:
    void InitCatchTable();
    CatchTable *catch_table_ {};
};

class TryContext : public CatchContext {
public:
    explicit TryContext(CodeGen *cg, const ir::TryStatement *try_stmt, bool has_finalizer = true)
        : CatchContext(cg), try_stmt_(try_stmt), has_finalizer_(has_finalizer)

    {
        InitFinalizer();
    }

    explicit TryContext(CodeGen *cg) : CatchContext(cg) {}

    NO_COPY_SEMANTIC(TryContext);
    NO_MOVE_SEMANTIC(TryContext);
    ~TryContext() = default;

    DynamicContextType Type() const override
    {
        return DynamicContextType::TRY;
    }

    VReg FinalizerRun() const
    {
        return finalizer_run_;
    }

    bool HasFinalizer() const override;
    void InitFinalizer();
    void EmitFinalizer();

    void AbortContext([[maybe_unused]] ControlFlowChange cfc,
                      [[maybe_unused]] const util::StringView &target_label) override
    {
        EmitFinalizer();
    }

private:
    const ir::TryStatement *try_stmt_ {};
    VReg finalizer_run_ {};
    bool has_finalizer_ {};
    bool in_finalizer_ {};
};

class ETSCatchContext : public DynamicContext {
public:
    NO_COPY_SEMANTIC(ETSCatchContext);
    NO_MOVE_SEMANTIC(ETSCatchContext);
    ~ETSCatchContext() = default;

    ArenaVector<const CatchTable *> GetETSCatchTable() const
    {
        return catch_tables_;
    }

    bool HasTryCatch() const override
    {
        return true;
    }

    CatchTable *AddNewCathTable(util::StringView assembler_type);
    CatchTable *AddNewCathTable(util::StringView assembler_type, LabelPair try_label_pair);

protected:
    explicit ETSCatchContext(CodeGen *cg, ArenaAllocator *allocator)
        : DynamicContext(cg, {}), catch_tables_(allocator->Adapter())
    {
    }

private:
    ArenaVector<const CatchTable *> catch_tables_;
};

class ETSTryContext : public ETSCatchContext {
public:
    explicit ETSTryContext(CodeGen *cg, ArenaAllocator *allocator, const ir::TryStatement *try_stmt,
                           bool has_finalizer = true)
        : ETSCatchContext(cg, allocator), try_stmt_(try_stmt), has_finalizer_(has_finalizer)

    {
    }

    explicit ETSTryContext(CodeGen *cg, ArenaAllocator *allocator) : ETSCatchContext(cg, allocator) {}

    NO_COPY_SEMANTIC(ETSTryContext);
    NO_MOVE_SEMANTIC(ETSTryContext);
    ~ETSTryContext() = default;

    DynamicContextType Type() const override
    {
        return DynamicContextType::TRY;
    }

    void EmitFinalizer(LabelPair trycatch_label_pair,
                       const ArenaVector<std::pair<compiler::LabelPair, const ir::Statement *>> &finalizer_insertions);

private:
    const ir::TryStatement *try_stmt_ {};
    const bool has_finalizer_ {};
};

}  // namespace panda::es2panda::compiler

#endif
