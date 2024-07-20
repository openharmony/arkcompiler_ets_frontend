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

#ifndef ES2PANDA_COMPILER_SCOPES_SCOPE_H
#define ES2PANDA_COMPILER_SCOPES_SCOPE_H

#include "varbinder/declaration.h"
#include "varbinder/variable.h"
#include "es2panda.h"
#include "util/enumbitops.h"
#include "util/ustring.h"

#include <map>
#include <unordered_map>
#include <vector>

namespace ark::es2panda::public_lib {
struct Context;
}  // namespace ark::es2panda::public_lib

namespace ark::es2panda::compiler {
class IRNode;
}  // namespace ark::es2panda::compiler

namespace ark::es2panda::varbinder {
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
    ScopeFindResultT(ScopeT s, uint32_t l, uint32_t ll, Variable *v) : scope(s), level(l), lexLevel(ll), variable(v) {}
    ScopeFindResultT(util::StringView n, ScopeT s, uint32_t l, uint32_t ll, Variable *v)
        : name(n), scope(s), level(l), lexLevel(ll), variable(v)
    {
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    util::StringView name {};
    ScopeT scope {};
    uint32_t level {};
    uint32_t lexLevel {};
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
    using InsertResult = std::pair<VariableMap::const_iterator, bool>;

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

    ClassScope *EnclosingClassScope();
    const ClassScope *EnclosingClassScope() const;

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
        return startIns_;
    }

    const compiler::IRNode *ScopeEnd() const
    {
        return endIns_;
    }

    void SetScopeStart(const compiler::IRNode *ins)
    {
        startIns_ = ins;
    }

    void SetScopeEnd(const compiler::IRNode *ins)
    {
        endIns_ = ins;
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
        auto options = decl->IsTypeAliasDecl() ? varbinder::ResolveBindingOptions::TYPE_ALIASES
                                               : varbinder::ResolveBindingOptions::BINDINGS;
        return AddBinding(allocator, FindLocal(decl->Name(), options), decl, extension);
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

    template <typename DeclType = varbinder::LetDecl, typename VariableType = varbinder::LocalVariable>
    static VariableType *CreateVar(ArenaAllocator *allocator, util::StringView name, VariableFlags flags,
                                   ir::AstNode *node);

    template <typename T, typename... Args>
    Variable *PropagateBinding(ArenaAllocator *allocator, util::StringView name, Args &&...args);

    virtual InsertResult InsertBinding(const util::StringView &name, Variable *var);
    virtual InsertResult TryInsertBinding(const util::StringView &name, Variable *var);
    virtual void MergeBindings(VariableMap const &bindings);
    virtual VariableMap::size_type EraseBinding(const util::StringView &name);

    const VariableMap &Bindings() const
    {
        return bindings_;
    }

    ArenaMap<util::StringView, Variable *> OrderedBindings(ArenaAllocator *allocator) const
    {
        ArenaMap<util::StringView, Variable *> result(allocator->Adapter());
        result.insert(bindings_.begin(), bindings_.end());
        return result;
    }

    virtual Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                 [[maybe_unused]] ScriptExtension extension) = 0;

    virtual Variable *FindLocal(const util::StringView &name, ResolveBindingOptions options) const;

    bool IsSuperscopeOf(const varbinder::Scope *subscope) const;

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

    Variable *AddLocal(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                       [[maybe_unused]] ScriptExtension extension);

    Variable *AddLocalVar(ArenaAllocator *allocator, Decl *newDecl);

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
        uint32_t lexLevel = 0;
        // iter will be the EXACT type of scope with cv-qualifiers
        auto &&iter = scope;

        if (iter->IsFunctionParamScope()) {
            auto *const v = iter->FindLocal(name, options);

            if (v != nullptr) {
                return {name, iter, level, lexLevel, v};
            }

            level++;
            const auto *const funcVariableScope = iter->AsFunctionParamScope()->GetFunctionScope();

            if (funcVariableScope != nullptr && funcVariableScope->NeedLexEnv()) {
                lexLevel++;
            }

            iter = iter->Parent();
        }

        while (iter != nullptr) {
            auto *const v = iter->FindLocal(name, options);

            if (v != nullptr) {
                return {name, iter, level, lexLevel, v};
            }

            if (iter->IsVariableScope()) {
                level++;

                if (iter->AsVariableScope()->NeedLexEnv()) {
                    lexLevel++;
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
    const compiler::IRNode *startIns_ {};
    const compiler::IRNode *endIns_ {};
};

class VariableScope : public Scope {
public:
    ~VariableScope() override = default;
    NO_COPY_SEMANTIC(VariableScope);
    NO_MOVE_SEMANTIC(VariableScope);

    uint32_t NextSlot()
    {
        return slotIndex_++;
    }

    uint32_t LexicalSlots() const
    {
        return slotIndex_;
    }

    bool NeedLexEnv() const
    {
        return slotIndex_ != 0;
    }

    uint32_t EvalBindings() const
    {
        return evalBindings_;
    }

    void CheckDirectEval(public_lib::Context *context);

protected:
    explicit VariableScope(ArenaAllocator *allocator, Scope *parent) : Scope(allocator, parent) {}

    template <typename T>
    Variable *AddVar(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl);

    template <typename T>
    Variable *AddFunction(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                          [[maybe_unused]] ScriptExtension extension);

    template <typename T>
    Variable *AddTSBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl, VariableFlags flags);

    template <typename T>
    Variable *AddLexical(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    uint32_t evalBindings_ {};
    uint32_t slotIndex_ {};
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

    Variable *AddParam(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl, VariableFlags flags);

    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    ArenaVector<LocalVariable *> params_;
};

class FunctionScope;

class FunctionParamScope : public ParamScope {
public:
    explicit FunctionParamScope(ArenaAllocator *allocator, Scope *parent) : ParamScope(allocator, parent) {}

    FunctionScope *GetFunctionScope() const
    {
        return functionScope_;
    }

    void BindFunctionScope(FunctionScope *funcScope)
    {
        functionScope_ = funcScope;
    }

    LocalVariable *NameVar() const
    {
        return nameVar_;
    }

    void BindName(ArenaAllocator *allocator, util::StringView name);

    ScopeType Type() const override
    {
        return ScopeType::FUNCTION_PARAM;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    friend class FunctionScope;
    template <typename E, typename T>
    friend class ScopeWithParamScope;

private:
    FunctionScope *functionScope_ {};
    LocalVariable *nameVar_ {};
};

template <typename E, typename T>
class ScopeWithParamScope : public E {
public:
    explicit ScopeWithParamScope(ArenaAllocator *allocator, Scope *parent) : E(allocator, parent), paramScope_(nullptr)
    {
    }

    void BindParamScope(T *paramScope)
    {
        AssignParamScope(paramScope);
        this->MergeBindings(paramScope->Bindings());
    }

    void AssignParamScope(T *paramScope)
    {
        ASSERT(this->Parent() == paramScope);
        paramScope_ = paramScope;
    }

    T *ParamScope()
    {
        return paramScope_;
    }

    const T *ParamScope() const
    {
        return paramScope_;
    }

protected:
    // NOLINTNEXTLINE(misc-non-private-member-variables-in-classes)
    T *paramScope_;
};

class LocalScope : public Scope {
public:
    explicit LocalScope(ArenaAllocator *allocator, Scope *parent) : Scope(allocator, parent) {}
    explicit LocalScope(ArenaAllocator *allocator, Scope *parent, ScopeFlags flags) : Scope(allocator, parent, flags) {}

    ScopeType Type() const override
    {
        return ScopeType::LOCAL;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;
};

class LocalScopeWithTypeAlias : public LocalScope {
public:
    explicit LocalScopeWithTypeAlias(ArenaAllocator *allocator, Scope *parent)
        : LocalScope(allocator, parent),
          typeAliasScope_(allocator->New<LocalScope>(allocator, this, ScopeFlags::TYPE_ALIAS))
    {
    }
    explicit LocalScopeWithTypeAlias(ArenaAllocator *allocator, Scope *parent, ScopeFlags flags)
        : LocalScope(allocator, parent, flags),
          typeAliasScope_(allocator->New<LocalScope>(allocator, this, ScopeFlags::TYPE_ALIAS))
    {
    }

    Variable *FindLocal(const util::StringView &name, ResolveBindingOptions options) const override;

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    const LocalScope *TypeAliasScope() const
    {
        return typeAliasScope_;
    }

    LocalScope *TypeAliasScope()
    {
        return typeAliasScope_;
    }

private:
    LocalScope *typeAliasScope_;
};

class FunctionScope : public ScopeWithParamScope<VariableScope, FunctionParamScope> {
public:
    explicit FunctionScope(ArenaAllocator *allocator, Scope *parent)
        : ScopeWithParamScope(allocator, parent),
          typeAliasScope_(allocator->New<LocalScope>(allocator, this, ScopeFlags::TYPE_ALIAS))
    {
    }

    ScopeType Type() const override
    {
        return ScopeType::FUNCTION;
    }

    void BindName(util::StringView name)
    {
        name_ = name;
    }

    void BindInternalName(util::StringView internalName)
    {
        internalName_ = internalName;
    }

    const util::StringView &Name() const
    {
        return name_;
    }

    const util::StringView &InternalName() const
    {
        return internalName_;
    }

    const LocalScope *TypeAliasScope() const
    {
        return typeAliasScope_;
    }

    Variable *FindLocal(const util::StringView &name, ResolveBindingOptions options) const override;

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

private:
    util::StringView name_ {};
    util::StringView internalName_ {};
    LocalScope *typeAliasScope_;
};

class ClassScope : public LocalScopeWithTypeAlias {
public:
    explicit ClassScope(ArenaAllocator *allocator, Scope *parent)
        : LocalScopeWithTypeAlias(allocator, parent),
          staticDeclScope_(allocator->New<LocalScope>(allocator, this, ScopeFlags::STATIC_DECL_SCOPE)),
          staticFieldScope_(allocator->New<LocalScope>(allocator, staticDeclScope_, ScopeFlags::STATIC_FIELD_SCOPE)),
          staticMethodScope_(allocator->New<LocalScope>(allocator, staticFieldScope_, ScopeFlags::STATIC_METHOD_SCOPE)),
          instanceDeclScope_(allocator->New<LocalScope>(allocator, staticMethodScope_, ScopeFlags::DECL_SCOPE)),
          instanceFieldScope_(allocator->New<LocalScope>(allocator, instanceDeclScope_, ScopeFlags::FIELD_SCOPE)),
          instanceMethodScope_(allocator->New<LocalScope>(allocator, instanceFieldScope_, ScopeFlags::METHOD_SCOPE))
    {
    }

    ScopeType Type() const override
    {
        return ScopeType::CLASS;
    }

    LocalScope *StaticDeclScope()
    {
        return staticDeclScope_;
    }

    const LocalScope *StaticDeclScope() const
    {
        return staticDeclScope_;
    }

    LocalScope *StaticFieldScope()
    {
        return staticFieldScope_;
    }

    const LocalScope *StaticFieldScope() const
    {
        return staticFieldScope_;
    }

    LocalScope *StaticMethodScope()
    {
        return staticMethodScope_;
    }

    const LocalScope *StaticMethodScope() const
    {
        return staticMethodScope_;
    }

    LocalScope *InstanceFieldScope()
    {
        return instanceFieldScope_;
    }

    const LocalScope *InstanceFieldScope() const
    {
        return instanceFieldScope_;
    }

    LocalScope *InstanceMethodScope()
    {
        return instanceMethodScope_;
    }

    const LocalScope *InstanceMethodScope() const
    {
        return instanceMethodScope_;
    }

    LocalScope *InstanceDeclScope()
    {
        return instanceDeclScope_;
    }

    const LocalScope *InstanceDeclScope() const
    {
        return instanceDeclScope_;
    }

    uint32_t GetAndIncrementAnonymousClassIdx() const
    {
        return anonymousClassIdx_++;
    }

    Variable *FindLocal(const util::StringView &name, ResolveBindingOptions options) const override;

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    class BindingProps {
    public:
        BindingProps() = default;

        void SetFlagsType(VariableFlags flagsType)
        {
            flags_ |= flagsType;
        }
        void SetBindingProps(VariableFlags flags, ir::Identifier *ident, LocalScope *targetScope)
        {
            flags_ |= flags;
            ident_ = ident;
            targetScope_ = targetScope;
        }
        VariableFlags GetFlags() const
        {
            return flags_;
        }
        ir::Identifier *GetIdent()
        {
            return ident_;
        }
        LocalScope *GetTargetScope()
        {
            return targetScope_;
        }

    private:
        VariableFlags flags_ = VariableFlags::NONE;
        ir::Identifier *ident_ {};
        LocalScope *targetScope_ {};
    };

    void SetBindingProps(Decl *newDecl, BindingProps *props, bool isStatic);

private:
    LocalScope *staticDeclScope_;
    LocalScope *staticFieldScope_;
    LocalScope *staticMethodScope_;
    LocalScope *instanceDeclScope_;
    LocalScope *instanceFieldScope_;
    LocalScope *instanceMethodScope_;
    mutable uint32_t anonymousClassIdx_ {1};
};

class CatchParamScope : public ParamScope {
public:
    explicit CatchParamScope(ArenaAllocator *allocator, Scope *parent) : ParamScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return ScopeType::CATCH_PARAM;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    friend class CatchScope;
};

class CatchScope : public ScopeWithParamScope<LocalScopeWithTypeAlias, CatchParamScope> {
public:
    explicit CatchScope(ArenaAllocator *allocator, Scope *parent) : ScopeWithParamScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return ScopeType::CATCH;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;
};

class LoopScope;

class LoopDeclarationScope : public VariableScope {
public:
    explicit LoopDeclarationScope(ArenaAllocator *allocator, Scope *parent) : VariableScope(allocator, parent) {}

    ScopeType Type() const override
    {
        return loopType_;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override
    {
        return AddLocal(allocator, currentVariable, newDecl, extension);
    }

    Scope *InitScope()
    {
        if (NeedLexEnv()) {
            return initScope_;
        }

        return this;
    }

    void ConvertToVariableScope(ArenaAllocator *allocator);

private:
    friend class LoopScope;
    LoopScope *loopScope_ {};
    LocalScope *initScope_ {};
    ScopeType loopType_ {ScopeType::LOCAL};
};

class LoopScope : public VariableScope {
public:
    explicit LoopScope(ArenaAllocator *allocator, Scope *parent) : VariableScope(allocator, parent) {}

    LoopDeclarationScope *DeclScope()
    {
        return declScope_;
    }

    void BindDecls(LoopDeclarationScope *declScope)
    {
        declScope_ = declScope;
        declScope_->loopScope_ = this;
    }

    ScopeType Type() const override
    {
        return loopType_;
    }

    void ConvertToVariableScope(ArenaAllocator *allocator);

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override
    {
        return AddLocal(allocator, currentVariable, newDecl, extension);
    }

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    LoopDeclarationScope *declScope_ {};
    ScopeType loopType_ {ScopeType::LOCAL};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class GlobalScope : public FunctionScope {
public:
    explicit GlobalScope(ArenaAllocator *allocator)
        : FunctionScope(allocator, nullptr), foreignBindings_(allocator->Adapter())
    {
        auto *paramScope = allocator->New<FunctionParamScope>(allocator, this);
        paramScope_ = paramScope;
        paramScope_->BindFunctionScope(this);
    }

    ScopeType Type() const override
    {
        return ScopeType::GLOBAL;
    }

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    InsertResult InsertBinding(const util::StringView &name, Variable *var) override;
    InsertResult TryInsertBinding(const util::StringView &name, Variable *var) override;
    void MergeBindings(VariableMap const &bindings) override;
    VariableMap::size_type EraseBinding(const util::StringView &name) override;

    InsertResult InsertForeignBinding(const util::StringView &name, Variable *var);
    [[nodiscard]] bool IsForeignBinding(const util::StringView &name) const;

    InsertResult InsertDynamicBinding(const util::StringView &name, Variable *var);

private:
    InsertResult InsertImpl(const util::StringView &name, Variable *var, bool isForeign, bool isDynamic);

    ArenaUnorderedMap<util::StringView, bool> foreignBindings_;
};

class ModuleScope : public GlobalScope {
public:
    template <typename K, typename V>
    using ModuleEntry = ArenaVector<std::pair<K, V>>;
    using ImportDeclList = ArenaVector<ImportDecl *>;
    using ExportDeclList = ArenaVector<ExportDecl *>;
    using LocalExportNameMap = ArenaMultiMap<varbinder::Variable *, util::StringView>;

    explicit ModuleScope(ArenaAllocator *allocator)
        : GlobalScope(allocator),
          allocator_(allocator),
          imports_(allocator_->Adapter()),
          exports_(allocator_->Adapter()),
          localExports_(allocator_->Adapter())
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
        return localExports_;
    }

    void AddImportDecl(ir::ImportDeclaration *importDecl, ImportDeclList &&decls);

    void AddExportDecl(ir::AstNode *exportDecl, ExportDecl *decl);

    void AddExportDecl(ir::AstNode *exportDecl, ExportDeclList &&decls);

    Variable *AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                         [[maybe_unused]] ScriptExtension extension) override;

    bool ExportAnalysis();

private:
    Variable *AddImport(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl);

    ArenaAllocator *allocator_;
    ModuleEntry<ir::ImportDeclaration *, ImportDeclList> imports_;
    ModuleEntry<ir::AstNode *, ExportDeclList> exports_;
    LocalExportNameMap localExports_;
};

template <typename T>
Variable *VariableScope::AddVar(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl)
{
    if (!currentVariable) {
        return InsertBinding(newDecl->Name(), allocator->New<T>(newDecl, VariableFlags::HOIST_VAR)).first->second;
    }

    switch (currentVariable->Declaration()->Type()) {
        case DeclType::VAR: {
            currentVariable->Reset(newDecl, VariableFlags::HOIST_VAR);
            [[fallthrough]];
        }
        case DeclType::PARAM:
        case DeclType::FUNC: {
            return currentVariable;
        }
        default: {
            return nullptr;
        }
    }
}

template <typename T>
Variable *VariableScope::AddFunction(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                     [[maybe_unused]] ScriptExtension extension)
{
    VariableFlags flags = (extension == ScriptExtension::JS) ? VariableFlags::HOIST_VAR : VariableFlags::HOIST;

    if (!currentVariable) {
        return InsertBinding(newDecl->Name(), allocator->New<T>(newDecl, flags)).first->second;
    }

    if (extension != ScriptExtension::JS || IsModuleScope()) {
        return nullptr;
    }

    switch (currentVariable->Declaration()->Type()) {
        case DeclType::VAR:
        case DeclType::FUNC: {
            currentVariable->Reset(newDecl, VariableFlags::HOIST_VAR);
            return currentVariable;
        }
        default: {
            return nullptr;
        }
    }
}

template <typename T>
Variable *VariableScope::AddTSBinding(ArenaAllocator *allocator, [[maybe_unused]] Variable *currentVariable,
                                      Decl *newDecl, VariableFlags flags)
{
    ASSERT(!currentVariable);
    return InsertBinding(newDecl->Name(), allocator->New<T>(newDecl, flags)).first->second;
}

template <typename T>
Variable *VariableScope::AddLexical(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl)
{
    if (currentVariable) {
        return nullptr;
    }

    return InsertBinding(newDecl->Name(), allocator->New<T>(newDecl, VariableFlags::NONE)).first->second;
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
    if (FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS)) {
        return nullptr;
    }

    auto *decl = allocator->New<DeclType>(name);
    auto *variable = allocator->New<VariableType>(decl, flags);

    decls_.push_back(decl);
    bindings_.insert({decl->Name(), variable});
    variable->SetScope(this);

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
}  // namespace ark::es2panda::varbinder

#endif
