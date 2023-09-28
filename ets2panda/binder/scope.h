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

#ifndef ES2PANDA_COMPILER_SCOPES_SCOPE_H
#define ES2PANDA_COMPILER_SCOPES_SCOPE_H

#include "plugins/ecmascript/es2panda/binder/declaration.h"
#include "plugins/ecmascript/es2panda/binder/variable.h"
#include "plugins/ecmascript/es2panda/es2panda.h"
#include "plugins/ecmascript/es2panda/util/enumbitops.h"
#include "plugins/ecmascript/es2panda/util/ustring.h"

#include <map>
#include <unordered_map>
#include <vector>

namespace panda::es2panda::compiler {
class IRNode;
class CompilerContext;
}  // namespace panda::es2panda::compiler

namespace panda::es2panda::binder {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CLASSES(type, className) class className;
SCOPE_TYPES(DECLARE_CLASSES)
#undef DECLARE_CLASSES

class Scope;
class VariableScope;
class Variable;

template <typename ScopeT,
          std::enable_if_t<std::is_pointer_v<ScopeT> && std::is_base_of_v<Scope, std::remove_pointer_t<ScopeT>>, bool> =
              true>
class ScopeFindResultT {
public:
    ScopeFindResultT() = default;
    ScopeFindResultT(util::StringView n, ScopeT s, uint32_t l, Variable *v) : ScopeFindResultT(n, s, l, l, v) {}
    ScopeFindResultT(ScopeT s, uint32_t l, uint32_t ll, Variable *v) : scope(s), level(l), lex_level(ll), variable(v) {}
    ScopeFindResultT(util::StringView n, ScopeT s, uint32_t l, uint32_t ll, Variable *v)
        : name(n), scope(s), level(l), lex_level(ll), variable(v)
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    util::StringView name {};
    ScopeT scope {};
    uint32_t level {};
    uint32_t lex_level {};
    Variable *variable {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

using ConstScopeFindResult = ScopeFindResultT<const Scope *>;
using ScopeFindResult = ScopeFindResultT<Scope *>;

class Scope {
public:
    virtual ~Scope() = default;
    NO_COPY_SEMANTIC(Scope);
    NO_MOVE_SEMANTIC(Scope);

    using VariableMap = ArenaUnorderedMap<util::StringView, Variable *>;
    using InsertResult = std::pair<VariableMap::iterator, bool>;

    virtual ScopeType Type() const = 0;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_CHECKS_CASTS(scopeType, className)        \
    bool Is##className() const                            \
    {                                                     \
        return Type() == ScopeType::scopeType;            \
    }                                                     \
    className *As##className()                            \
    {                                                     \
        ASSERT(Is##className());                          \
        return reinterpret_cast<className *>(this);       \
    }                                                     \
    const className *As##className() const                \
    {                                                     \
        ASSERT(Is##className());                          \
        return reinterpret_cast<const className *>(this); \
    }
    SCOPE_TYPES(DECLARE_CHECKS_CASTS)
#undef DECLARE_CHECKS_CASTS

    bool IsVariableScope() const
    {
        return Type() > ScopeType::LOCAL;
    }

    bool IsFunctionVariableScope() const
    {
        return Type() >= ScopeType::FUNCTION;
    }

    FunctionScope *AsFunctionVariableScope()
    {
        ASSERT(IsFunctionVariableScope());
        return reinterpret_cast<FunctionScope *>(this);
    }

    const FunctionScope *AsFunctionVariableScope() const
    {
        ASSERT(IsFunctionVariableScope());
        return reinterpret_cast<const FunctionScope *>(this);
    }

    VariableScope *AsVariableScope()
    {
        ASSERT(IsVariableScope());
        return reinterpret_cast<VariableScope *>(this);
    }

    const VariableScope *AsVariableScope() const
    {
        ASSERT(IsVariableScope());
        return reinterpret_cast<const VariableScope *>(this);
    }

    VariableScope *EnclosingVariableScope();

    const VariableScope *EnclosingVariableScope() const;

    void AddFlag(ScopeFlags flag)
    {
        flags_ |= flag;
    }

    void ClearFlag(ScopeFlags flag)
    {
        flags_ &= ~flag;
    }

    bool HasFlag(ScopeFlags flag) const
    {
        return (flags_ & flag) != 0;
    }

    ArenaVector<Decl *> &Decls()
    {
        return decls_;
    }

    const ArenaVector<Decl *> &Decls() const
    {
        return decls_;
    }

    void SetParent(Scope *parent)
    {
        parent_ = parent;
    }

    Scope *Parent()
    {
        return parent_;
    }

    const Scope *Parent() const
    {
        return parent_;
    }

    const compiler::IRNode *ScopeStart() const
    {
        return start_ins_;
    }

    const compiler::IRNode *ScopeEnd() const
    {
        return end_ins_;
    }

    void SetScopeStart(const compiler::IRNode *ins)
    {
        start_ins_ = ins;
    }

    void SetScopeEnd(const compiler::IRNode *ins)
    {
        end_ins_ = ins;
    }

    ir::AstNode *Node()
    {
        return node_;
    }

    const ir::AstNode *Node() const
    {
        return node_;
    }

    void BindNode(ir::AstNode *node)
    {
        node_ = node;
    }

    Variable *AddDecl(ArenaAllocator *allocator, Decl *decl, [[maybe_unused]] ScriptExtension extension)
    {
        decls_.push_back(decl);
        return AddBinding(allocator, FindLocal(decl->Name()), decl, extension);
    }

    Variable *AddTsDecl(ArenaAllocator *allocator, Decl *decl, [[maybe_unused]] ScriptExtension extension)
    {
        decls_.push_back(decl);
        return AddBinding(allocator, FindLocal(decl->Name(), ResolveBindingOptions::ALL), decl, extension);
    }

    template <typename T, typename... Args>
    T *NewDecl(ArenaAllocator *allocator, Args &&...args);

    template <typename DeclType, typename VariableType>
    VariableType *AddDecl(ArenaAllocator *allocator, util::StringView name, VariableFlags flags);

    template <typename DeclType = binder::LetDecl, typename VariableType = binder::LocalVariable>
    static VariableType *CreateVar(ArenaAllocator *allocator, util::StringView name, VariableFlags flags,
                                   ir::AstNode *node);

    template <typename T, typename... Args>
    Variable *PropagateBinding(ArenaAllocator *allocator, util::StringView name, Args &&...args);

    virtual InsertResult InsertBinding(const util::StringView &name, Variable *var);
    virtual InsertResult TryInsertBinding(const util::StringView &name, Variable *var);
    virtual void ReplaceBindings(VariableMap bindings);
    virtual VariableMap::size_type EraseBinding(const util::StringView &name);

    const VariableMap &Bindings() const
    {
        return bindings_;
    }

    virtual Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                 [[maybe_unused]] ScriptExtension extension) = 0;

    // NOLINTNEXTLINE(google-default-arguments)
    virtual Variable *FindLocal(const util::StringView &name,
                                ResolveBindingOptions options = ResolveBindingOptions::BINDINGS) const;

    ConstScopeFindResult Find(const util::StringView &name,
                              ResolveBindingOptions options = ResolveBindingOptions::BINDINGS) const;

    ScopeFindResult Find(const util::StringView &name, ResolveBindingOptions options = ResolveBindingOptions::BINDINGS);

    ConstScopeFindResult FindInGlobal(const util::StringView &name,
                                      ResolveBindingOptions options = ResolveBindingOptions::BINDINGS) const;

    ConstScopeFindResult FindInFunctionScope(const util::StringView &name,
                                             ResolveBindingOptions options = ResolveBindingOptions::BINDINGS) const;

    Decl *FindDecl(const util::StringView &name) const;

protected:
    explicit Scope(ArenaAllocator *allocator, Scope *parent)
        : parent_(parent), decls_(allocator->Adapter()), bindings_(allocator->Adapter())
    {
    }

    explicit Scope(ArenaAllocator *allocator, Scope *parent, ScopeFlags flags)
        : parent_(parent), decls_(allocator->Adapter()), bindings_(allocator->Adapter()), flags_(flags)
    {
    }

    /**
     * @return true - if the variable is shadowed
     *         false - otherwise
     */
    using VariableVisitor = std::function<bool(const Variable *)>;

    /**
     * @return true - if the variable is shadowed
     *         false - otherwise
     */
    std::tuple<Scope *, bool> IterateShadowedVariables(const util::StringView &name, const VariableVisitor &visitor);

    Variable *AddLocal(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                       [[maybe_unused]] ScriptExtension extension);

private:
    template <
        typename ResultT, typename ScopeT,
        std::enable_if_t<std::is_same_v<ResultT, ConstScopeFindResult> || std::is_same_v<ResultT, ScopeFindResult>,
                         bool> = true,
        std::enable_if_t<std::is_pointer_v<ScopeT> && std::is_base_of_v<Scope, std::remove_pointer_t<ScopeT>>, bool> =
            true>
    static ResultT FindImpl(ScopeT &&scope, const util::StringView &name, const ResolveBindingOptions options)
    {
        uint32_t level = 0;
        uint32_t lex_level = 0;
        // iter will be the EXACT type of scope with cv-qualifiers
        auto &&iter = scope;

        if (iter->IsFunctionParamScope()) {
            auto *const v = iter->FindLocal(name, options);

            if (v != nullptr) {
                return {name, iter, level, lex_level, v};
            }

            level++;
            const auto *const func_variable_scope = iter->AsFunctionParamScope()->GetFunctionScope();

            if (func_variable_scope != nullptr && func_variable_scope->NeedLexEnv()) {
                lex_level++;
            }

            iter = iter->Parent();
        }

        while (iter != nullptr) {
            auto *const v = iter->FindLocal(name, options);

            if (v != nullptr) {
                return {name, iter, level, lex_level, v};
            }

            if (iter->IsVariableScope()) {
                level++;

                if (iter->AsVariableScope()->NeedLexEnv()) {
                    lex_level++;
                }
            }

            iter = iter->Parent();
        }

        return {name, nullptr, 0, 0, nullptr};
    }

    Scope *parent_ {};
    ArenaVector<Decl *> decls_;
    VariableMap bindings_;
    ir::AstNode *node_ {};
    ScopeFlags flags_ {};
    const compiler::IRNode *start_ins_ {};
    const compiler::IRNode *end_ins_ {};
};

class VariableScope : public Scope {
public:
    ~VariableScope() override = default;
    NO_COPY_SEMANTIC(VariableScope);
    NO_MOVE_SEMANTIC(VariableScope);

    uint32_t NextSlot()
    {
        return slot_index_++;
    }

    uint32_t LexicalSlots() const
    {
        return slot_index_;
    }

    bool NeedLexEnv() const
    {
        return slot_index_ != 0;
    }

    uint32_t EvalBindings() const
    {
        return eval_bindings_;
    }

    void CheckDirectEval(compiler::CompilerContext *ctx);

protected:
    explicit VariableScope(ArenaAllocator *allocator, Scope *parent) : Scope(allocator, parent) {}

    template <typename T>
    Variable *AddVar(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl);

    template <typename T>
    Variable *AddFunction(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                          [[maybe_unused]] ScriptExtension extension);

    template <typename T>
    Variable *AddTSBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl, VariableFlags flags);

    template <typename T>
    Variable *AddLexical(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    uint32_t eval_bindings_ {};
    uint32_t slot_index_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class ParamScope : public Scope {
public:
    ScopeType Type() const override
    {
        return ScopeType::PARAM;
    }

    ArenaVector<LocalVariable *> &Params()
    {
        return params_;
    }

    const ArenaVector<LocalVariable *> &Params() const
    {
        return params_;
    }

    std::tuple<ParameterDecl *, ir::AstNode *, Variable *> AddParamDecl(ArenaAllocator *allocator, ir::AstNode *param);

protected:
    explicit ParamScope(ArenaAllocator *allocator, Scope *parent)
        : Scope(allocator, parent), params_(allocator->Adapter())
    {
    }

    Variable *AddParam(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl, VariableFlags flags);

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    ArenaVector<LocalVariable *> params_;
};

class FunctionScope;

class FunctionParamScope : public ParamScope {
public:
    explicit FunctionParamScope(ArenaAllocator *allocator, Scope *parent) : ParamScope(allocator, parent) {}

    FunctionScope *GetFunctionScope() const
    {
        return function_scope_;
    }

    void BindFunctionScope(FunctionScope *func_scope)
    {
        function_scope_ = func_scope;
    }

    LocalVariable *NameVar() const
    {
        return name_var_;
    }

    void BindName(ArenaAllocator *allocator, util::StringView name);

    ScopeType Type() const override
    {
        return ScopeType::FUNCTION_PARAM;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

    friend class FunctionScope;
    template <typename E, typename T>
    friend class ScopeWithParamScope;

private:
    FunctionScope *function_scope_ {};
    LocalVariable *name_var_ {};
};

template <typename E, typename T>
class ScopeWithParamScope : public E {
public:
    explicit ScopeWithParamScope(ArenaAllocator *allocator, Scope *parent) : E(allocator, parent) {}

    void BindParamScope(T *param_scope)
    {
        AssignParamScope(param_scope);
        this->ReplaceBindings(param_scope->Bindings());
    }

    void AssignParamScope(T *param_scope)
    {
        ASSERT(this->Parent() == param_scope);
        ASSERT(this->Bindings().empty());

        param_scope_ = param_scope;
    }

    T *ParamScope()
    {
        return param_scope_;
    }

    const T *ParamScope() const
    {
        return param_scope_;
    }

protected:
    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    T *param_scope_;
};

class FunctionScope : public ScopeWithParamScope<VariableScope, FunctionParamScope> {
public:
    explicit FunctionScope(ArenaAllocator *allocator, Scope *parent) : ScopeWithParamScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return ScopeType::FUNCTION;
    }

    void BindName(util::StringView name)
    {
        name_ = name;
    }

    void BindInternalName(util::StringView internal_name)
    {
        internal_name_ = internal_name;
    }

    const util::StringView &Name() const
    {
        return name_;
    }

    const util::StringView &InternalName() const
    {
        return internal_name_;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

private:
    util::StringView name_ {};
    util::StringView internal_name_ {};
};

class LocalScope : public Scope {
public:
    explicit LocalScope(ArenaAllocator *allocator, Scope *parent) : Scope(allocator, parent) {}
    explicit LocalScope(ArenaAllocator *allocator, Scope *parent, ScopeFlags flags) : Scope(allocator, parent, flags) {}

    ScopeType Type() const override
    {
        return ScopeType::LOCAL;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;
};

class ClassScope : public LocalScope {
public:
    explicit ClassScope(ArenaAllocator *allocator, Scope *parent)
        : LocalScope(allocator, parent),
          type_alias_scope_(allocator->New<LocalScope>(allocator, this, ScopeFlags::TYPE_ALIAS)),
          static_decl_scope_(allocator->New<LocalScope>(allocator, type_alias_scope_, ScopeFlags::STATIC_DECL_SCOPE)),
          static_field_scope_(
              allocator->New<LocalScope>(allocator, static_decl_scope_, ScopeFlags::STATIC_FIELD_SCOPE)),
          static_method_scope_(
              allocator->New<LocalScope>(allocator, static_field_scope_, ScopeFlags::STATIC_METHOD_SCOPE)),
          instance_decl_scope_(allocator->New<LocalScope>(allocator, static_method_scope_, ScopeFlags::DECL_SCOPE)),
          instance_field_scope_(allocator->New<LocalScope>(allocator, instance_decl_scope_, ScopeFlags::FIELD_SCOPE)),
          instance_method_scope_(allocator->New<LocalScope>(allocator, instance_field_scope_, ScopeFlags::METHOD_SCOPE))
    {
    }

    ScopeType Type() const override
    {
        return ScopeType::CLASS;
    }

    LocalScope *StaticDeclScope()
    {
        return static_decl_scope_;
    }

    const LocalScope *StaticDeclScope() const
    {
        return static_decl_scope_;
    }

    LocalScope *StaticFieldScope()
    {
        return static_field_scope_;
    }

    const LocalScope *StaticFieldScope() const
    {
        return static_field_scope_;
    }

    LocalScope *StaticMethodScope()
    {
        return static_method_scope_;
    }

    const LocalScope *StaticMethodScope() const
    {
        return static_method_scope_;
    }

    LocalScope *InstanceFieldScope()
    {
        return instance_field_scope_;
    }

    const LocalScope *InstanceFieldScope() const
    {
        return instance_field_scope_;
    }

    LocalScope *InstanceMethodScope()
    {
        return instance_method_scope_;
    }

    const LocalScope *InstanceMethodScope() const
    {
        return instance_method_scope_;
    }

    LocalScope *InstanceDeclScope()
    {
        return instance_decl_scope_;
    }

    const LocalScope *InstanceDeclScope() const
    {
        return instance_decl_scope_;
    }

    uint32_t GetAndIncrementAnonymousClassIdx() const
    {
        return anonymous_class_idx_++;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    Variable *FindLocal(const util::StringView &name,
                        ResolveBindingOptions options = ResolveBindingOptions::BINDINGS) const override;

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

private:
    LocalScope *type_alias_scope_;
    LocalScope *static_decl_scope_;
    LocalScope *static_field_scope_;
    LocalScope *static_method_scope_;
    LocalScope *instance_decl_scope_;
    LocalScope *instance_field_scope_;
    LocalScope *instance_method_scope_;
    mutable uint32_t anonymous_class_idx_ {1};
};

class CatchParamScope : public ParamScope {
public:
    explicit CatchParamScope(ArenaAllocator *allocator, Scope *parent) : ParamScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return ScopeType::CATCH_PARAM;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

    friend class CatchScope;
};

class CatchScope : public ScopeWithParamScope<LocalScope, CatchParamScope> {
public:
    explicit CatchScope(ArenaAllocator *allocator, Scope *parent) : ScopeWithParamScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return ScopeType::CATCH;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;
};

class LoopScope;

class LoopDeclarationScope : public VariableScope {
public:
    explicit LoopDeclarationScope(ArenaAllocator *allocator, Scope *parent) : VariableScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return loop_type_;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override
    {
        return AddLocal(allocator, current_variable, new_decl, extension);
    }

    Scope *InitScope()
    {
        if (NeedLexEnv()) {
            return init_scope_;
        }

        return this;
    }

    void ConvertToVariableScope(ArenaAllocator *allocator);

private:
    friend class LoopScope;
    LoopScope *loop_scope_ {};
    LocalScope *init_scope_ {};
    ScopeType loop_type_ {ScopeType::LOCAL};
};

class LoopScope : public VariableScope {
public:
    explicit LoopScope(ArenaAllocator *allocator, Scope *parent) : VariableScope(allocator, parent) {}

    LoopDeclarationScope *DeclScope()
    {
        return decl_scope_;
    }

    void BindDecls(LoopDeclarationScope *decl_scope)
    {
        decl_scope_ = decl_scope;
        decl_scope_->loop_scope_ = this;
    }

    ScopeType Type() const override
    {
        return loop_type_;
    }

    void ConvertToVariableScope(ArenaAllocator *allocator);

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override
    {
        return AddLocal(allocator, current_variable, new_decl, extension);
    }

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    LoopDeclarationScope *decl_scope_ {};
    ScopeType loop_type_ {ScopeType::LOCAL};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class GlobalScope : public FunctionScope {
public:
    explicit GlobalScope(ArenaAllocator *allocator)
        : FunctionScope(allocator, nullptr), foreign_bindings_(allocator->Adapter())
    {
        auto *param_scope = allocator->New<FunctionParamScope>(allocator, this);
        param_scope_ = param_scope;
        param_scope_->BindFunctionScope(this);
    }

    ScopeType Type() const override
    {
        return ScopeType::GLOBAL;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

    InsertResult InsertBinding(const util::StringView &name, Variable *var) override;
    InsertResult TryInsertBinding(const util::StringView &name, Variable *var) override;
    void ReplaceBindings(VariableMap bindings) override;
    VariableMap::size_type EraseBinding(const util::StringView &name) override;

    InsertResult InsertForeignBinding(const util::StringView &name, Variable *var);
    [[nodiscard]] bool IsForeignBinding(const util::StringView &name) const;

    InsertResult InsertDynamicBinding(const util::StringView &name, Variable *var);

private:
    InsertResult InsertImpl(const util::StringView &name, Variable *var, bool is_foreign, bool is_dynamic);

    ArenaUnorderedMap<util::StringView, bool> foreign_bindings_;
};

class ModuleScope : public GlobalScope {
public:
    template <typename K, typename V>
    using ModuleEntry = ArenaVector<std::pair<K, V>>;
    using ImportDeclList = ArenaVector<ImportDecl *>;
    using ExportDeclList = ArenaVector<ExportDecl *>;
    using LocalExportNameMap = ArenaMultiMap<binder::Variable *, util::StringView>;

    explicit ModuleScope(ArenaAllocator *allocator)
        : GlobalScope(allocator),
          allocator_(allocator),
          imports_(allocator_->Adapter()),
          exports_(allocator_->Adapter()),
          local_exports_(allocator_->Adapter())
    {
    }

    ScopeType Type() const override
    {
        return ScopeType::MODULE;
    }

    const ModuleEntry<ir::ImportDeclaration *, ImportDeclList> &Imports() const
    {
        return imports_;
    }

    const ModuleEntry<ir::AstNode *, ExportDeclList> &Exports() const
    {
        return exports_;
    }

    const LocalExportNameMap &LocalExports() const
    {
        return local_exports_;
    }

    void AddImportDecl(ir::ImportDeclaration *import_decl, ImportDeclList &&decls);

    void AddExportDecl(ir::AstNode *export_decl, ExportDecl *decl);

    void AddExportDecl(ir::AstNode *export_decl, ExportDeclList &&decls);

    Variable *AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                         [[maybe_unused]] ScriptExtension extension) override;

    bool ExportAnalysis();

private:
    Variable *AddImport(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl);

    ArenaAllocator *allocator_;
    ModuleEntry<ir::ImportDeclaration *, ImportDeclList> imports_;
    ModuleEntry<ir::AstNode *, ExportDeclList> exports_;
    LocalExportNameMap local_exports_;
};

template <typename T>
Variable *VariableScope::AddVar(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl)
{
    if (!current_variable) {
        return InsertBinding(new_decl->Name(), allocator->New<T>(new_decl, VariableFlags::HOIST_VAR)).first->second;
    }

    switch (current_variable->Declaration()->Type()) {
        case DeclType::VAR: {
            current_variable->Reset(new_decl, VariableFlags::HOIST_VAR);
            [[fallthrough]];
        }
        case DeclType::PARAM:
        case DeclType::FUNC: {
            return current_variable;
        }
        default: {
            return nullptr;
        }
    }
}

template <typename T>
Variable *VariableScope::AddFunction(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                     [[maybe_unused]] ScriptExtension extension)
{
    VariableFlags flags = (extension == ScriptExtension::JS) ? VariableFlags::HOIST_VAR : VariableFlags::HOIST;

    if (!current_variable) {
        return InsertBinding(new_decl->Name(), allocator->New<T>(new_decl, flags)).first->second;
    }

    if (extension != ScriptExtension::JS || IsModuleScope()) {
        return nullptr;
    }

    switch (current_variable->Declaration()->Type()) {
        case DeclType::VAR:
        case DeclType::FUNC: {
            current_variable->Reset(new_decl, VariableFlags::HOIST_VAR);
            return current_variable;
        }
        default: {
            return nullptr;
        }
    }
}

template <typename T>
Variable *VariableScope::AddTSBinding(ArenaAllocator *allocator, [[maybe_unused]] Variable *current_variable,
                                      Decl *new_decl, VariableFlags flags)
{
    ASSERT(!current_variable);
    return InsertBinding(new_decl->Name(), allocator->New<T>(new_decl, flags)).first->second;
}

template <typename T>
Variable *VariableScope::AddLexical(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl)
{
    if (current_variable) {
        return nullptr;
    }

    return InsertBinding(new_decl->Name(), allocator->New<T>(new_decl, VariableFlags::NONE)).first->second;
}

template <typename T, typename... Args>
T *Scope::NewDecl(ArenaAllocator *allocator, Args &&...args)
{
    T *decl = allocator->New<T>(std::forward<Args>(args)...);
    decls_.push_back(decl);

    return decl;
}

template <typename DeclType, typename VariableType>
VariableType *Scope::AddDecl(ArenaAllocator *allocator, util::StringView name, VariableFlags flags)
{
    if (FindLocal(name)) {
        return nullptr;
    }

    auto *decl = allocator->New<DeclType>(name);
    auto *variable = allocator->New<VariableType>(decl, flags);

    decls_.push_back(decl);
    bindings_.insert({decl->Name(), variable});

    return variable;
}

template <typename DeclType, typename VariableType>
VariableType *Scope::CreateVar(ArenaAllocator *allocator, util::StringView name, VariableFlags flags, ir::AstNode *node)
{
    auto *decl = allocator->New<DeclType>(name);
    auto *variable = allocator->New<VariableType>(decl, flags);
    decl->BindNode(node);
    return variable;
}

template <typename T, typename... Args>
Variable *Scope::PropagateBinding(ArenaAllocator *allocator, util::StringView name, Args &&...args)
{
    auto res = bindings_.find(name);
    if (res == bindings_.end()) {
        return bindings_.insert({name, allocator->New<T>(std::forward<Args>(args)...)}).first->second;
    }

    res->second->Reset(std::forward<Args>(args)...);
    return res->second;
}
}  // namespace panda::es2panda::binder

#endif
