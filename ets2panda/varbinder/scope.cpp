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

#include "scope.h"

#include "varbinder/declaration.h"
#include "util/helpers.h"
#include "varbinder/tsBinding.h"
#include "varbinder/variable.h"
#include "varbinder/variableFlags.h"
#include "ir/astNode.h"
#include "ir/expressions/identifier.h"
#include "ir/statements/annotationDeclaration.h"
#include "ir/statements/classDeclaration.h"
#include "ir/base/classDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/module/exportAllDeclaration.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/exportSpecifier.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "compiler/base/literals.h"
#include "macros.h"
#include "util/ustring.h"
#include "generated/signatures.h"
#include "public/public.h"

namespace ark::es2panda::varbinder {
VariableScope *Scope::EnclosingVariableScope()
{
    Scope *iter = this;

    while (iter != nullptr) {
        if (iter->IsVariableScope()) {
            return iter->AsVariableScope();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const VariableScope *Scope::EnclosingVariableScope() const
{
    const auto *iter = this;

    while (iter != nullptr) {
        if (iter->IsVariableScope()) {
            return iter->AsVariableScope();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

bool Scope::IsSuperscopeOf(const varbinder::Scope *subscope) const
{
    while (subscope != nullptr) {
        if (subscope == this) {
            return true;
        }
        subscope = ir::AstNode::EnclosingScope(subscope->Node()->Parent());
    }
    return false;
}

// NOTE(psiket): Duplication
ClassScope *Scope::EnclosingClassScope()
{
    Scope *iter = this;

    while (iter != nullptr) {
        if (iter->IsClassScope()) {
            return iter->AsClassScope();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

const ClassScope *Scope::EnclosingClassScope() const
{
    const auto *iter = this;

    while (iter != nullptr) {
        if (iter->IsVariableScope()) {
            return iter->AsClassScope();
        }

        iter = iter->Parent();
    }

    return nullptr;
}

Variable *Scope::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::INTERFACES) != 0) {
        std::string tsBindingName = varbinder::TSBinding::ToTSBinding(name);
        util::StringView interfaceNameView(tsBindingName);

        auto res = bindings_.find(interfaceNameView);
        if (res != bindings_.end()) {
            return res->second;
        }

        if ((options & ResolveBindingOptions::BINDINGS) == 0) {
            return nullptr;
        }
    }

    auto res = bindings_.find(name);
    if (res == bindings_.end()) {
        return nullptr;
    }

    return res->second;
}

Scope::InsertResult Scope::InsertBinding(const util::StringView &name, Variable *const var)
{
    ASSERT(var != nullptr);
    auto insertResult = bindings_.emplace(name, var);
    if (insertResult.second) {
        decls_.push_back(var->Declaration());
    }

    return insertResult;
}

Scope::InsertResult Scope::TryInsertBinding(const util::StringView &name, Variable *const var)
{
    ASSERT(var != nullptr);
    return bindings_.try_emplace(name, var);
}

void Scope::MergeBindings(VariableMap const &bindings)
{
    for (auto &[k, v] : bindings) {
        bindings_.try_emplace(k, v);
    }
}

Scope::VariableMap::size_type Scope::EraseBinding(const util::StringView &name)
{
    if (auto toBeErased = bindings_.find(name);
        toBeErased == bindings_.end() ||
        (toBeErased->second->IsLocalVariable() &&
         toBeErased->second->AsLocalVariable()->Declaration()->Node()->IsImportNamespaceSpecifier())) {
        return 0;
    }

    return bindings_.erase(name);
}

ConstScopeFindResult Scope::FindInGlobal(const util::StringView &name, const ResolveBindingOptions options) const
{
    const auto *scopeIter = this;
    const auto *scopeParent = this->Parent();
    // One scope below true global is ETSGLOBAL
    while (scopeParent != nullptr && !scopeParent->IsGlobalScope()) {
        scopeIter = scopeParent;
        scopeParent = scopeIter->Parent();
    }

    auto *resolved = scopeIter->FindLocal(name, options);
    if (resolved == nullptr && scopeParent != nullptr) {
        // If the variable cannot be found in the scope of the local ETSGLOBAL, than we still need to check the true
        // global scope which contains all the imported ETSGLOBALs
        resolved = scopeParent->FindLocal(name, options);
    }

    return {name, scopeIter, 0, 0, resolved};
}

ConstScopeFindResult Scope::FindInFunctionScope(const util::StringView &name, const ResolveBindingOptions options) const
{
    const auto *scopeIter = this;
    while (scopeIter != nullptr && !scopeIter->IsGlobalScope()) {
        if (!scopeIter->IsClassScope()) {
            if (auto *const resolved = scopeIter->FindLocal(name, options); resolved != nullptr) {
                return ConstScopeFindResult(name, scopeIter, 0, 0, resolved);
            }
        }
        scopeIter = scopeIter->Parent();
    }

    return ConstScopeFindResult(name, scopeIter, 0, 0, nullptr);
}

ScopeFindResult Scope::Find(const util::StringView &name, const ResolveBindingOptions options)
{
    return FindImpl<ScopeFindResult>(this, name, options);
}

ConstScopeFindResult Scope::Find(const util::StringView &name, const ResolveBindingOptions options) const
{
    return FindImpl<ConstScopeFindResult>(this, name, options);
}

Decl *Scope::FindDecl(const util::StringView &name) const
{
    for (auto *it : decls_) {
        if (it->Name() == name) {
            return it;
        }
    }

    return nullptr;
}

std::tuple<Scope *, bool> Scope::IterateShadowedVariables(const util::StringView &name, const VariableVisitor &visitor)
{
    auto *iter = this;

    while (iter != nullptr) {
        auto *v = iter->FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS);

        if (v != nullptr && visitor(v)) {
            return {iter, true};
        }

        if (iter->IsFunctionVariableScope()) {
            break;
        }

        iter = iter->Parent();
    }

    return {iter, false};
}

Variable *Scope::AddLocalVar(ArenaAllocator *allocator, Decl *newDecl)
{
    auto [scope, shadowed] =
        IterateShadowedVariables(newDecl->Name(), [](const Variable *v) { return !v->HasFlag(VariableFlags::VAR); });

    if (shadowed) {
        return nullptr;
    }

    VariableFlags varFlags = VariableFlags::HOIST_VAR | VariableFlags::LEXICAL_VAR;
    if (scope->IsGlobalScope()) {
        return scope->InsertBinding(newDecl->Name(), allocator->New<GlobalVariable>(newDecl, varFlags)).first->second;
    }

    return scope->PropagateBinding<LocalVariable>(allocator, newDecl->Name(), newDecl, varFlags);
}

Variable *Scope::AddLocal(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                          [[maybe_unused]] ScriptExtension extension)
{
    VariableFlags flags = VariableFlags::LEXICAL;
    switch (newDecl->Type()) {
        case DeclType::VAR: {
            return AddLocalVar(allocator, newDecl);
        }
        case DeclType::ENUM: {
            return bindings_.insert({newDecl->Name(), allocator->New<EnumVariable>(newDecl, false)}).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            auto *var =
                bindings_.insert({newDecl->Name(), allocator->New<LocalVariable>(newDecl, VariableFlags::ENUM_LITERAL)})
                    .first->second;
            newDecl->Node()->AsTSEnumDeclaration()->Key()->SetVariable(var);
            return var;
        }
        case DeclType::INTERFACE: {
            return bindings_.insert({newDecl->Name(), allocator->New<LocalVariable>(newDecl, VariableFlags::INTERFACE)})
                .first->second;
        }
        case DeclType::CLASS: {
            auto *var =
                bindings_.insert({newDecl->Name(), allocator->New<LocalVariable>(newDecl, VariableFlags::CLASS)})
                    .first->second;
            newDecl->Node()->AsClassDefinition()->Ident()->SetVariable(var);
            return var;
        }
        case DeclType::TYPE_PARAMETER: {
            return bindings_
                .insert({newDecl->Name(), allocator->New<LocalVariable>(newDecl, VariableFlags::TYPE_PARAMETER)})
                .first->second;
        }
        case DeclType::FUNC: {
            flags = VariableFlags::HOIST;
            [[fallthrough]];
        }
        default: {
            if (currentVariable != nullptr) {
                return nullptr;
            }

            auto [_, shadowed] = IterateShadowedVariables(
                newDecl->Name(), [](const Variable *v) { return v->HasFlag(VariableFlags::LEXICAL_VAR); });
            (void)_;

            if (shadowed) {
                return nullptr;
            }

            return bindings_.insert({newDecl->Name(), allocator->New<LocalVariable>(newDecl, flags)}).first->second;
        }
    }
}

void VariableScope::CheckDirectEval(public_lib::Context *context)
{
    ASSERT(context);
    const auto &varMap = Bindings();

    if (!HasFlag(ScopeFlags::NO_REG_STORE) || varMap.empty()) {
        evalBindings_ = compiler::INVALID_LITERAL_BUFFER_ID;
        return;
    }

    size_t constBindings = 0;
    for (const auto &[name, var] : varMap) {
        (void)name;
        var->SetLexical(this);

        if (var->LexicalBound() && var->Declaration()->IsConstDecl()) {
            constBindings++;
        }
    }

    std::vector<compiler::Literal> literals(LexicalSlots() + constBindings, compiler::Literal(util::StringView()));

    if (constBindings == 0U) {
        for (const auto &[name, variable] : varMap) {
            if (!variable->LexicalBound()) {
                continue;
            }

            literals[variable->AsLocalVariable()->LexIdx()] = compiler::Literal(name);
        }
    } else {
        std::vector<varbinder::Variable *> bindings(LexicalSlots());

        for (const auto &[name, variable] : varMap) {
            (void)name;
            if (!variable->LexicalBound()) {
                continue;
            }

            bindings[variable->AsLocalVariable()->LexIdx()] = variable;
        }

        uint32_t buffIndex = 0;
        for (const auto *variable : bindings) {
            if (variable == nullptr) {
                ASSERT(literals[buffIndex].GetString().empty());
                buffIndex++;
                continue;
            }
            if (variable->Declaration()->IsConstDecl()) {
                literals[buffIndex++] = compiler::Literal(true);
            }
            literals[buffIndex++] = compiler::Literal(variable->Name());
        }
    }
    context->contextLiterals.emplace_back(literals);
    evalBindings_ = context->contextLiterals.size() - 1;
}

Variable *ParamScope::AddParam(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl, VariableFlags flags)
{
    ASSERT(newDecl->IsParameterDecl());

    if (currentVariable != nullptr) {
        return nullptr;
    }

    auto *param = allocator->New<LocalVariable>(newDecl, flags);
    param->SetScope(this);

    params_.push_back(param);
    InsertBinding(newDecl->Name(), param);
    return param;
}

std::tuple<ParameterDecl *, ir::AstNode *, Variable *> ParamScope::AddParamDecl(ArenaAllocator *allocator,
                                                                                ir::AstNode *param)
{
    const auto [name, pattern] = util::Helpers::ParamName(allocator, param, params_.size());

    auto *decl = NewDecl<ParameterDecl>(allocator, name);
    auto *var = AddParam(allocator, FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS), decl,
                         VariableFlags::VAR | VariableFlags::LOCAL);

    if (var == nullptr) {
        return {decl, param, nullptr};
    }

    if (!pattern) {
        decl->BindNode(param);
        return {decl, nullptr, var};
    }

    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(param);

    for (auto *binding : bindings) {
        auto *varDecl = NewDecl<VarDecl>(allocator, binding->Name());
        varDecl->BindNode(binding);

        if (FindLocal(varDecl->Name(), varbinder::ResolveBindingOptions::BINDINGS) != nullptr) {
            return {decl, binding, nullptr};
        }

        auto *paramVar = allocator->New<LocalVariable>(varDecl, VariableFlags::VAR | VariableFlags::LOCAL);
        TryInsertBinding(varDecl->Name(), paramVar);
    }

    return {decl, nullptr, var};
}

void FunctionParamScope::BindName(ArenaAllocator *allocator, util::StringView name)
{
    nameVar_ = AddDecl<ConstDecl, LocalVariable>(allocator, name, VariableFlags::INITIALIZED);
    if (!functionScope_->InsertBinding(name, nameVar_).second) {
        nameVar_ = nullptr;
    }
}

Variable *FunctionParamScope::AddBinding([[maybe_unused]] ArenaAllocator *allocator,
                                         [[maybe_unused]] Variable *currentVariable, [[maybe_unused]] Decl *newDecl,
                                         [[maybe_unused]] ScriptExtension extension)
{
    UNREACHABLE();
}

Variable *AnnotationParamScope::AddBinding([[maybe_unused]] ArenaAllocator *allocator,
                                           [[maybe_unused]] Variable *currentVariable, [[maybe_unused]] Decl *newDecl,
                                           [[maybe_unused]] ScriptExtension extension)
{
    auto *ident = newDecl->Node()->AsClassProperty()->Id();
    auto annoVar = allocator->New<LocalVariable>(newDecl, VariableFlags::PROPERTY);
    auto var = InsertBinding(ident->Name(), annoVar).first->second;
    if (var != nullptr) {
        var->SetScope(this);
        if (ident != nullptr) {
            ident->SetVariable(var);
        }
    }
    return var;
}

Variable *FunctionScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                    [[maybe_unused]] ScriptExtension extension)
{
    ir::Identifier *ident {};
    Variable *var {};
    switch (newDecl->Type()) {
        case DeclType::VAR: {
            return AddVar<LocalVariable>(allocator, currentVariable, newDecl);
        }
        case DeclType::FUNC: {
            return AddFunction<LocalVariable>(allocator, currentVariable, newDecl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(newDecl->Name(), allocator->New<EnumVariable>(newDecl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            var = AddTSBinding<LocalVariable>(allocator, currentVariable, newDecl, VariableFlags::ENUM_LITERAL);
            ident = newDecl->Node()->AsTSEnumDeclaration()->Key();
            break;
        }
        // NOTE(psiket):Duplication
        case DeclType::INTERFACE: {
            ident = newDecl->Node()->AsTSInterfaceDeclaration()->Id();
            auto interfaceVar = allocator->New<LocalVariable>(newDecl, VariableFlags::INTERFACE);
            var = InsertBinding(newDecl->Name(), interfaceVar).first->second;
            break;
        }
        case DeclType::CLASS: {
            ident = newDecl->Node()->AsClassDefinition()->Ident();
            auto classVar = allocator->New<LocalVariable>(newDecl, VariableFlags::CLASS);
            var = InsertBinding(newDecl->Name(), classVar).first->second;
            break;
        }
        case DeclType::TYPE_ALIAS: {
            ident = newDecl->Node()->AsTSTypeAliasDeclaration()->Id();
            var = typeAliasScope_->AddBinding(allocator, currentVariable, newDecl, extension);
            break;
        }
        default: {
            return AddLexical<LocalVariable>(allocator, currentVariable, newDecl);
        }
    }
    if (var != nullptr) {
        var->SetScope(this);
        if (ident != nullptr) {
            ident->SetVariable(var);
        }
    }
    return var;
}

Variable *GlobalScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                  [[maybe_unused]] ScriptExtension extension)
{
    switch (newDecl->Type()) {
        case DeclType::VAR: {
            return AddVar<GlobalVariable>(allocator, currentVariable, newDecl);
        }
        case DeclType::FUNC: {
            return AddFunction<GlobalVariable>(allocator, currentVariable, newDecl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(newDecl->Name(), allocator->New<EnumVariable>(newDecl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return AddTSBinding<LocalVariable>(allocator, currentVariable, newDecl, VariableFlags::ENUM_LITERAL);
        }
        case DeclType::INTERFACE: {
            return AddTSBinding<LocalVariable>(allocator, currentVariable, newDecl, VariableFlags::INTERFACE);
        }
        default: {
            return AddLexical<LocalVariable>(allocator, currentVariable, newDecl);
        }
    }
}

Scope::InsertResult GlobalScope::InsertBinding(const util::StringView &name, Variable *const var)
{
    return GlobalScope::InsertImpl(name, var, false, false);
}

Scope::InsertResult GlobalScope::TryInsertBinding(const util::StringView &name, Variable *const var)
{
    const auto insRes = Scope::TryInsertBinding(name, var);
    if (insRes.second) {
        [[maybe_unused]] const bool insertSuccess = std::get<1>(foreignBindings_.try_emplace(name, var));
        ASSERT(insertSuccess);
    }

    return insRes;
}

void GlobalScope::MergeBindings([[maybe_unused]] const VariableMap &bindings)
{
    UNREACHABLE();
}

Scope::VariableMap::size_type GlobalScope::EraseBinding(const util::StringView &name)
{
    const auto erased = Scope::EraseBinding(name);
    if (erased != 0) {
        [[maybe_unused]] const auto erasedForeign = foreignBindings_.erase(name);
        ASSERT(erasedForeign != 0);
    }

    return erased;
}

Scope::InsertResult GlobalScope::InsertForeignBinding(const util::StringView &name, Variable *const var)
{
    return GlobalScope::InsertImpl(name, var, true, false);
}

Scope::InsertResult GlobalScope::InsertImpl(const util::StringView &name, Variable *const var, const bool isForeign,
                                            const bool isDynamic)
{
    if (!isDynamic && isForeign && !var->Declaration()->Name().Is(compiler::Signatures::ETS_GLOBAL)) {
        const auto *const node = var->Declaration()->Node();

        if (!(node->IsExported() || node->IsDefaultExported() || node->IsExportedType())) {
            return Scope::InsertResult {Bindings().end(), false};
        }
    }

    const auto insRes = Scope::InsertBinding(name, var);
    if (insRes.second) {
        [[maybe_unused]] const bool insertSuccess = std::get<1>(foreignBindings_.emplace(name, isForeign));
        ASSERT(insertSuccess);
    }

    return insRes;
}

bool GlobalScope::IsForeignBinding(const util::StringView &name) const
{
    // Asserts make sure that the passed in key comes from this scope
    ASSERT(Bindings().find(name) != Bindings().end());
    ASSERT(foreignBindings_.find(name) != foreignBindings_.end());

    return foreignBindings_.at(name);
}

Scope::InsertResult GlobalScope::InsertDynamicBinding(const util::StringView &name, Variable *const var)
{
    return InsertImpl(name, var, true, true);
}

// ModuleScope

Variable *ModuleScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                  [[maybe_unused]] ScriptExtension extension)
{
    switch (newDecl->Type()) {
        case DeclType::VAR: {
            return AddVar<LocalVariable>(allocator, currentVariable, newDecl);
        }
        case DeclType::FUNC: {
            return AddFunction<LocalVariable>(allocator, currentVariable, newDecl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(newDecl->Name(), allocator->New<EnumVariable>(newDecl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return AddTSBinding<LocalVariable>(allocator, currentVariable, newDecl, VariableFlags::ENUM_LITERAL);
        }
        case DeclType::INTERFACE: {
            return AddTSBinding<LocalVariable>(allocator, currentVariable, newDecl, VariableFlags::INTERFACE);
        }
        case DeclType::IMPORT: {
            return AddImport(allocator, currentVariable, newDecl);
        }
        case DeclType::EXPORT: {
            return allocator->New<LocalVariable>(newDecl, VariableFlags::NONE);
        }
        default: {
            return AddLexical<LocalVariable>(allocator, currentVariable, newDecl);
        }
    }
}

void ModuleScope::AddImportDecl(ir::ImportDeclaration *importDecl, ImportDeclList &&decls)
{
    auto res = imports_.emplace_back(importDecl, decls);

    for (auto &decl : res.second) {
        decl->BindNode(importDecl);
    }
}

void ModuleScope::AddExportDecl(ir::AstNode *exportDecl, ExportDecl *decl)
{
    decl->BindNode(exportDecl);

    ArenaVector<ExportDecl *> decls(allocator_->Adapter());
    decls.push_back(decl);

    AddExportDecl(exportDecl, std::move(decls));
}

void ModuleScope::AddExportDecl(ir::AstNode *exportDecl, ExportDeclList &&decls)
{
    auto res = exports_.emplace_back(exportDecl, decls);

    for (auto &decl : res.second) {
        decl->BindNode(exportDecl);
    }
}

Variable *ModuleScope::AddImport(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl)
{
    if (currentVariable != nullptr && currentVariable->Declaration()->Type() != DeclType::VAR) {
        return nullptr;
    }

    if (newDecl->Node()->IsImportNamespaceSpecifier()) {
        return InsertBinding(newDecl->Name(), allocator->New<LocalVariable>(newDecl, VariableFlags::READONLY))
            .first->second;
    }

    auto *variable = allocator->New<ModuleVariable>(newDecl, VariableFlags::NONE);
    variable->ExoticName() = newDecl->AsImportDecl()->ImportName();
    InsertBinding(newDecl->Name(), variable);
    return variable;
}

bool ModuleScope::ExportAnalysis()
{
    std::set<util::StringView> exportedNames;

    for (const auto &[exportDecl, decls] : exports_) {
        if (exportDecl->IsExportAllDeclaration()) {
            const auto *exportAllDecl = exportDecl->AsExportAllDeclaration();

            if (exportAllDecl->Exported() == nullptr) {
                continue;
            }

            auto result = exportedNames.insert(exportAllDecl->Exported()->Name());
            if (!result.second) {
                return false;
            }

            continue;
        }

        if (exportDecl->IsExportNamedDeclaration()) {
            const auto *exportNamedDecl = exportDecl->AsExportNamedDeclaration();

            if (exportNamedDecl->Source() != nullptr) {
                continue;
            }
        }

        for (const auto *decl : decls) {
            varbinder::Variable *variable = FindLocal(decl->LocalName(), varbinder::ResolveBindingOptions::BINDINGS);

            if (variable == nullptr) {
                continue;
            }

            auto result = exportedNames.insert(decl->ExportName());
            if (!result.second) {
                return false;
            }

            if (!variable->IsModuleVariable()) {
                variable->AddFlag(VariableFlags::LOCAL_EXPORT);
                localExports_.insert({variable, decl->ExportName()});
            }
        }
    }

    return true;
}

Variable *FunctionScope::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::TYPE_ALIASES) != 0) {
        auto found = typeAliasScope_->Bindings().find(name);
        if (found != typeAliasScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::ALL_NON_TYPE) == 0) {
        return nullptr;
    }

    if ((options & ResolveBindingOptions::INTERFACES) != 0) {
        std::string tsBindingName = varbinder::TSBinding::ToTSBinding(name);
        util::StringView interfaceNameView(tsBindingName);

        auto res = Bindings().find(interfaceNameView);
        if (res != Bindings().end()) {
            return res->second;
        }

        if ((options & ResolveBindingOptions::BINDINGS) == 0) {
            return nullptr;
        }
    }

    auto res = Bindings().find(name);
    if (res == Bindings().end()) {
        return nullptr;
    }

    return res->second;
}

// LocalScope

Variable *LocalScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    return AddLocal(allocator, currentVariable, newDecl, extension);
}

Variable *LocalScopeWithTypeAlias::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                              [[maybe_unused]] ScriptExtension extension)
{
    if (newDecl->IsTypeAliasDecl()) {
        auto *ident = newDecl->Node()->AsTSTypeAliasDeclaration()->Id();
        auto *var = typeAliasScope_->AddBinding(allocator, currentVariable, newDecl, extension);
        if (var != nullptr) {
            var->SetScope(this);
            if (ident != nullptr) {
                ident->SetVariable(var);
            }
        }
        return var;
    }
    return AddLocal(allocator, currentVariable, newDecl, extension);
}

Variable *LocalScopeWithTypeAlias::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::TYPE_ALIASES) != 0) {
        auto found = typeAliasScope_->Bindings().find(name);
        if (found != typeAliasScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::ALL_NON_TYPE) == 0) {
        return nullptr;
    }

    if ((options & ResolveBindingOptions::INTERFACES) != 0) {
        std::string tsBindingName = varbinder::TSBinding::ToTSBinding(name);
        util::StringView interfaceNameView(tsBindingName);

        auto res = Bindings().find(interfaceNameView);
        if (res != Bindings().end()) {
            return res->second;
        }

        if ((options & ResolveBindingOptions::BINDINGS) == 0) {
            return nullptr;
        }
    }

    auto res = Bindings().find(name);
    if (res == Bindings().end()) {
        return nullptr;
    }

    return res->second;
}

Variable *ClassScope::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::TYPE_ALIASES) != 0) {
        auto found = TypeAliasScope()->Bindings().find(name);
        if (found != TypeAliasScope()->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::VARIABLES) != 0) {
        auto found = instanceFieldScope_->Bindings().find(name);
        if (found != instanceFieldScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_VARIABLES) != 0) {
        auto found = staticFieldScope_->Bindings().find(name);
        if (found != staticFieldScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::DECLARATION) != 0) {
        auto found = instanceDeclScope_->Bindings().find(name);
        if (found != instanceDeclScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_DECLARATION) != 0) {
        auto found = staticDeclScope_->Bindings().find(name);
        if (found != staticDeclScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::METHODS) != 0) {
        auto found = instanceMethodScope_->Bindings().find(name);
        if (found != instanceMethodScope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_METHODS) != 0) {
        auto found = staticMethodScope_->Bindings().find(name);
        if (found != staticMethodScope_->Bindings().end()) {
            return found->second;
        }
    }

    return nullptr;
}

void ClassScope::SetBindingProps(Decl *newDecl, BindingProps *props, bool isStatic)
{
    switch (newDecl->Type()) {
        case DeclType::CONST:
        case DeclType::READONLY:
        case DeclType::LET: {
            props->SetBindingProps(VariableFlags::PROPERTY, newDecl->Node()->AsClassProperty()->Id(),
                                   isStatic ? staticFieldScope_ : instanceFieldScope_);
            break;
        }
        case DeclType::INTERFACE: {
            props->SetBindingProps(VariableFlags::INTERFACE, newDecl->Node()->AsTSInterfaceDeclaration()->Id(),
                                   isStatic ? staticDeclScope_ : instanceDeclScope_);
            break;
        }
        case DeclType::CLASS: {
            props->SetBindingProps(VariableFlags::CLASS, newDecl->Node()->AsClassDefinition()->Ident(),
                                   isStatic ? staticDeclScope_ : instanceDeclScope_);
            break;
        }
        case DeclType::ENUM_LITERAL: {
            props->SetBindingProps(VariableFlags::ENUM_LITERAL, newDecl->Node()->AsTSEnumDeclaration()->Key(),
                                   isStatic ? staticDeclScope_ : instanceDeclScope_);
            break;
        }
        case DeclType::TYPE_ALIAS: {
            props->SetBindingProps(VariableFlags::TYPE_ALIAS, newDecl->Node()->AsTSTypeAliasDeclaration()->Id(),
                                   TypeAliasScope());
            break;
        }
        case DeclType::ANNOTATIONDECL: {
            props->SetBindingProps(VariableFlags::ANNOTATIONDECL,
                                   newDecl->Node()->AsAnnotationDeclaration()->GetBaseName(),
                                   isStatic ? staticDeclScope_ : instanceDeclScope_);
            break;
        }
        case DeclType::ANNOTATIONUSAGE: {
            props->SetBindingProps(VariableFlags::ANNOTATIONUSAGE, newDecl->Node()->AsAnnotationUsage()->GetBaseName(),
                                   isStatic ? staticDeclScope_ : instanceDeclScope_);
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }
}

Variable *ClassScope::AddBinding(ArenaAllocator *allocator, [[maybe_unused]] Variable *currentVariable, Decl *newDecl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    bool isStatic = newDecl->Node()->IsStatic();
    BindingProps props;

    if (isStatic) {
        props.SetFlagsType(VariableFlags::STATIC);
    }

    SetBindingProps(newDecl, &props, isStatic);

    auto options = newDecl->Type() != DeclType::TYPE_ALIAS ? ResolveBindingOptions::ALL_NON_TYPE
                                                           : ResolveBindingOptions::TYPE_ALIASES;

    const auto *foundVar = FindLocal(newDecl->Name(), options);
    if (foundVar != nullptr) {
        if (!newDecl->IsLetOrConstDecl()) {
            return nullptr;
        }

        foundVar = FindLocal(newDecl->Name(),
                             ResolveBindingOptions::ALL ^ (isStatic ? ResolveBindingOptions::VARIABLES
                                                                    : ResolveBindingOptions::STATIC_VARIABLES));
        if (foundVar != nullptr) {
            return nullptr;
        }
    }

    auto *var = props.GetTargetScope()->AddBinding(allocator, nullptr, newDecl, extension);
    if (var == nullptr) {
        return nullptr;
    }

    if (auto node = newDecl->Node();
        node->IsStatement() &&
        (node->AsStatement()->IsMethodDefinition() || node->IsClassProperty() || node->IsClassStaticBlock()) &&
        node->AsStatement()->AsClassElement()->Value() != nullptr) {
        props.SetFlagsType(VariableFlags::INITIALIZED);
    }

    var->SetScope(this);
    var->AddFlag(props.GetFlags());

    if (props.GetIdent() != nullptr) {
        props.GetIdent()->SetVariable(var);
    }

    return var;
}

void LoopDeclarationScope::ConvertToVariableScope(ArenaAllocator *allocator)
{
    if (NeedLexEnv()) {
        return;
    }

    const auto &bindings = Bindings();
    for (auto &[name, var] : bindings) {
        if (!var->LexicalBound() || !var->Declaration()->IsLetOrConstDecl()) {
            continue;
        }

        slotIndex_++;
        loopType_ = ScopeType::LOOP_DECL;
        auto *copiedVar = var->AsLocalVariable()->Copy(allocator, var->Declaration());
        copiedVar->AddFlag(VariableFlags::INITIALIZED | VariableFlags::PER_ITERATION);
        var->AddFlag(VariableFlags::LOOP_DECL);
        loopScope_->InsertBinding(name, copiedVar);
    }

    if (loopType_ == ScopeType::LOOP_DECL) {
        auto *parentVarScope = Parent()->EnclosingVariableScope();
        slotIndex_ = std::max(slotIndex_, parentVarScope->LexicalSlots());
        evalBindings_ = parentVarScope->EvalBindings();
        initScope_ = allocator->New<LocalScope>(allocator, Parent());
        initScope_->BindNode(Node());
        initScope_->MergeBindings(bindings);
    }
}

void LoopScope::ConvertToVariableScope(ArenaAllocator *allocator)
{
    declScope_->ConvertToVariableScope(allocator);

    if (loopType_ != ScopeType::LOCAL) {
        return;
    }

    for (const auto &[_, var] : Bindings()) {
        (void)_;
        if (var->LexicalBound() && var->Declaration()->IsLetDecl()) {
            ASSERT(declScope_->NeedLexEnv());
            loopType_ = ScopeType::LOOP;
            break;
        }
    }

    if (loopType_ == ScopeType::LOOP) {
        slotIndex_ = std::max(slotIndex_, declScope_->LexicalSlots());
        evalBindings_ = declScope_->EvalBindings();
    }
}

Variable *CatchParamScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                      [[maybe_unused]] ScriptExtension extension)
{
    return AddParam(allocator, currentVariable, newDecl, VariableFlags::INITIALIZED);
}

Variable *CatchScope::AddBinding(ArenaAllocator *allocator, Variable *currentVariable, Decl *newDecl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    if (!newDecl->IsVarDecl() &&
        (paramScope_->FindLocal(newDecl->Name(), varbinder::ResolveBindingOptions::BINDINGS) != nullptr)) {
        return nullptr;
    }

    if (newDecl->IsTypeAliasDecl()) {
        auto *ident = newDecl->Node()->AsTSTypeAliasDeclaration()->Id();
        auto *var = TypeAliasScope()->AddBinding(allocator, currentVariable, newDecl, extension);
        if (var != nullptr) {
            var->SetScope(this);
            if (ident != nullptr) {
                ident->SetVariable(var);
            }
        }
        return var;
    }

    return AddLocal(allocator, currentVariable, newDecl, extension);
}
}  // namespace ark::es2panda::varbinder
