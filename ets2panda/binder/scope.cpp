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

#include "scope.h"

#include "binder/declaration.h"
#include "util/helpers.h"
#include "binder/tsBinding.h"
#include "binder/variable.h"
#include "binder/variableFlags.h"
#include "ir/astNode.h"
#include "ir/expressions/identifier.h"
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
#include "compiler/core/compilerContext.h"
#include "macros.h"
#include "util/ustring.h"
#include "generated/signatures.h"

#include <algorithm>
#include <sstream>

namespace panda::es2panda::binder {
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

// NOLINTNEXTLINE(google-default-arguments)
Variable *Scope::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::INTERFACES) != 0) {
        std::string ts_binding_name = binder::TSBinding::ToTSBinding(name);
        util::StringView interface_name_view(ts_binding_name);

        auto res = bindings_.find(interface_name_view);
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
    return bindings_.emplace(name, var);
}

Scope::InsertResult Scope::TryInsertBinding(const util::StringView &name, Variable *const var)
{
    return bindings_.try_emplace(name, var);
}

void Scope::ReplaceBindings(VariableMap bindings)
{
    bindings_ = std::move(bindings);
}

Scope::VariableMap::size_type Scope::EraseBinding(const util::StringView &name)
{
    return bindings_.erase(name);
}

ConstScopeFindResult Scope::FindInGlobal(const util::StringView &name, const ResolveBindingOptions options) const
{
    const auto *scope_iter = this;
    // One scope below true global is ETSGLOBAL
    while (!scope_iter->Parent()->IsGlobalScope()) {
        scope_iter = scope_iter->Parent();
    }

    auto *resolved = scope_iter->FindLocal(name, options);
    if (resolved == nullptr) {
        // If the variable cannot be found in the scope of the local ETSGLOBAL, than we still need to check the true
        // global scope which contains all the imported ETSGLOBALs
        resolved = scope_iter->Parent()->FindLocal(name, options);
    }

    return {name, scope_iter, 0, 0, resolved};
}

ConstScopeFindResult Scope::FindInFunctionScope(const util::StringView &name, const ResolveBindingOptions options) const
{
    const auto *scope_iter = this;
    while (scope_iter != nullptr && !scope_iter->IsClassScope() && !scope_iter->IsGlobalScope()) {
        if (auto *const resolved = scope_iter->FindLocal(name, options); resolved != nullptr) {
            return {name, scope_iter, 0, 0, resolved};
        }
        scope_iter = scope_iter->Parent();
    }

    return {name, scope_iter, 0, 0, nullptr};
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

    while (true) {
        auto *v = iter->FindLocal(name);

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

Variable *Scope::AddLocal(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                          [[maybe_unused]] ScriptExtension extension)
{
    VariableFlags flags = VariableFlags::LEXICAL;
    switch (new_decl->Type()) {
        case DeclType::VAR: {
            auto [scope, shadowed] = IterateShadowedVariables(
                new_decl->Name(), [](const Variable *v) { return !v->HasFlag(VariableFlags::VAR); });

            if (shadowed) {
                return nullptr;
            }

            VariableFlags var_flags = VariableFlags::HOIST_VAR | VariableFlags::LEXICAL_VAR;
            if (scope->IsGlobalScope()) {
                return scope->InsertBinding(new_decl->Name(), allocator->New<GlobalVariable>(new_decl, var_flags))
                    .first->second;
            }

            return scope->PropagateBinding<LocalVariable>(allocator, new_decl->Name(), new_decl, var_flags);
        }
        case DeclType::ENUM: {
            return bindings_.insert({new_decl->Name(), allocator->New<EnumVariable>(new_decl, false)}).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return bindings_
                .insert({new_decl->Name(), allocator->New<LocalVariable>(new_decl, VariableFlags::ENUM_LITERAL)})
                .first->second;
        }
        case DeclType::INTERFACE: {
            return bindings_
                .insert({new_decl->Name(), allocator->New<LocalVariable>(new_decl, VariableFlags::INTERFACE)})
                .first->second;
        }
        case DeclType::TYPE_PARAMETER: {
            return bindings_
                .insert({new_decl->Name(), allocator->New<LocalVariable>(new_decl, VariableFlags::TYPE_PARAMETER)})
                .first->second;
        }
        case DeclType::FUNC: {
            flags = VariableFlags::HOIST;
            [[fallthrough]];
        }
        default: {
            if (current_variable != nullptr) {
                return nullptr;
            }

            auto [_, shadowed] = IterateShadowedVariables(
                new_decl->Name(), [](const Variable *v) { return v->HasFlag(VariableFlags::LEXICAL_VAR); });
            (void)_;

            if (shadowed) {
                return nullptr;
            }

            return bindings_.insert({new_decl->Name(), allocator->New<LocalVariable>(new_decl, flags)}).first->second;
        }
    }
}

void VariableScope::CheckDirectEval(compiler::CompilerContext *compiler_ctx)
{
    ASSERT(compiler_ctx);
    const auto &var_map = Bindings();

    if (!HasFlag(ScopeFlags::NO_REG_STORE) || var_map.empty()) {
        eval_bindings_ = compiler::INVALID_LITERAL_BUFFER_ID;
        return;
    }

    size_t const_bindings = 0;
    for (const auto &[name, var] : var_map) {
        (void)name;
        var->SetLexical(this);

        if (var->LexicalBound() && var->Declaration()->IsConstDecl()) {
            const_bindings++;
        }
    }

    std::vector<compiler::Literal> literals(LexicalSlots() + const_bindings, compiler::Literal(util::StringView()));

    if (const_bindings == 0U) {
        for (const auto &[name, variable] : var_map) {
            if (!variable->LexicalBound()) {
                continue;
            }

            literals[variable->AsLocalVariable()->LexIdx()] = compiler::Literal(name);
        }
    } else {
        std::vector<binder::Variable *> bindings(LexicalSlots());

        for (const auto &[name, variable] : var_map) {
            (void)name;
            if (!variable->LexicalBound()) {
                continue;
            }

            bindings[variable->AsLocalVariable()->LexIdx()] = variable;
        }

        uint32_t buff_index = 0;
        for (const auto *variable : bindings) {
            if (variable == nullptr) {
                ASSERT(literals[buff_index].GetString().empty());
                buff_index++;
                continue;
            }
            if (variable->Declaration()->IsConstDecl()) {
                literals[buff_index++] = compiler::Literal(true);
            }
            literals[buff_index++] = compiler::Literal(variable->Name());
        }
    }

    eval_bindings_ = compiler_ctx->AddContextLiteral(std::move(literals));
}

Variable *ParamScope::AddParam(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                               VariableFlags flags)
{
    ASSERT(new_decl->IsParameterDecl());

    if (current_variable != nullptr) {
        return nullptr;
    }

    auto *param = allocator->New<LocalVariable>(new_decl, flags);

    params_.push_back(param);
    InsertBinding(new_decl->Name(), param);
    return param;
}

std::tuple<ParameterDecl *, ir::AstNode *, Variable *> ParamScope::AddParamDecl(ArenaAllocator *allocator,
                                                                                ir::AstNode *param)
{
    const auto [name, pattern] = util::Helpers::ParamName(allocator, param, params_.size());

    auto *decl = NewDecl<ParameterDecl>(allocator, name);
    auto *var = AddParam(allocator, FindLocal(name), decl, VariableFlags::VAR | VariableFlags::LOCAL);

    if (var == nullptr) {
        return {decl, param, nullptr};
    }

    if (!pattern) {
        decl->BindNode(param);
        return {decl, nullptr, var};
    }

    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(param);

    for (auto *binding : bindings) {
        auto *var_decl = NewDecl<VarDecl>(allocator, binding->Name());
        var_decl->BindNode(binding);

        if (FindLocal(var_decl->Name()) != nullptr) {
            return {decl, binding, nullptr};
        }

        auto *param_var = allocator->New<LocalVariable>(var_decl, VariableFlags::VAR | VariableFlags::LOCAL);
        TryInsertBinding(var_decl->Name(), param_var);
    }

    return {decl, nullptr, var};
}

void FunctionParamScope::BindName(ArenaAllocator *allocator, util::StringView name)
{
    name_var_ = AddDecl<ConstDecl, LocalVariable>(allocator, name, VariableFlags::INITIALIZED);
    if (!function_scope_->InsertBinding(name, name_var_).second) {
        name_var_ = nullptr;
    }
}

Variable *FunctionParamScope::AddBinding([[maybe_unused]] ArenaAllocator *allocator,
                                         [[maybe_unused]] Variable *current_variable, [[maybe_unused]] Decl *new_decl,
                                         [[maybe_unused]] ScriptExtension extension)
{
    UNREACHABLE();
}

Variable *FunctionScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                    [[maybe_unused]] ScriptExtension extension)
{
    switch (new_decl->Type()) {
        case DeclType::VAR: {
            return AddVar<LocalVariable>(allocator, current_variable, new_decl);
        }
        case DeclType::FUNC: {
            return AddFunction<LocalVariable>(allocator, current_variable, new_decl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(new_decl->Name(), allocator->New<EnumVariable>(new_decl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::ENUM_LITERAL);
        }
        case DeclType::INTERFACE: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::INTERFACE);
        }
        default: {
            return AddLexical<LocalVariable>(allocator, current_variable, new_decl);
        }
    }
}

Variable *GlobalScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                  [[maybe_unused]] ScriptExtension extension)
{
    switch (new_decl->Type()) {
        case DeclType::VAR: {
            return AddVar<GlobalVariable>(allocator, current_variable, new_decl);
        }
        case DeclType::FUNC: {
            return AddFunction<GlobalVariable>(allocator, current_variable, new_decl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(new_decl->Name(), allocator->New<EnumVariable>(new_decl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::ENUM_LITERAL);
        }
        case DeclType::INTERFACE: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::INTERFACE);
        }
        default: {
            return AddLexical<LocalVariable>(allocator, current_variable, new_decl);
        }
    }
}

Scope::InsertResult GlobalScope::InsertBinding(const util::StringView &name, Variable *const var)
{
    return GlobalScope::InsertImpl(name, var, false, false);
}

Scope::InsertResult GlobalScope::TryInsertBinding(const util::StringView &name, Variable *const var)
{
    const auto ins_res = Scope::TryInsertBinding(name, var);
    if (ins_res.second) {
        [[maybe_unused]] const bool insert_success = std::get<1>(foreign_bindings_.try_emplace(name, var));
        ASSERT(insert_success);
    }

    return ins_res;
}

void GlobalScope::ReplaceBindings([[maybe_unused]] const VariableMap bindings)
{
    UNREACHABLE();
}

Scope::VariableMap::size_type GlobalScope::EraseBinding(const util::StringView &name)
{
    const auto erased = Scope::EraseBinding(name);
    if (erased != 0) {
        [[maybe_unused]] const auto erased_foreign = foreign_bindings_.erase(name);
        ASSERT(erased_foreign != 0);
    }

    return erased;
}

Scope::InsertResult GlobalScope::InsertForeignBinding(const util::StringView &name, Variable *const var)
{
    return GlobalScope::InsertImpl(name, var, true, false);
}

Scope::InsertResult GlobalScope::InsertImpl(const util::StringView &name, Variable *const var, const bool is_foreign,
                                            const bool is_dynamic)
{
    if (!is_dynamic && is_foreign && !var->Declaration()->Name().Is(compiler::Signatures::ETS_GLOBAL)) {
        const auto *const node = var->Declaration()->Node();

        if (const bool exported = node->IsClassDefinition() ? node->Parent()->IsExported() : node->IsExported();
            !exported) {
            if (!node->IsDefaultExported()) {
                return Scope::InsertResult {{}, false};
            }
        }
    }

    const auto ins_res = Scope::InsertBinding(name, var);
    if (ins_res.second) {
        [[maybe_unused]] const bool insert_success = std::get<1>(foreign_bindings_.emplace(name, is_foreign));
        ASSERT(insert_success);
    }

    return ins_res;
}

bool GlobalScope::IsForeignBinding(const util::StringView &name) const
{
    // Asserts make sure that the passed in key comes from this scope
    ASSERT(Bindings().find(name) != Bindings().end());
    ASSERT(foreign_bindings_.find(name) != foreign_bindings_.end());

    return foreign_bindings_.at(name);
}

Scope::InsertResult GlobalScope::InsertDynamicBinding(const util::StringView &name, Variable *const var)
{
    return InsertImpl(name, var, true, true);
}

// ModuleScope

Variable *ModuleScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                  [[maybe_unused]] ScriptExtension extension)
{
    switch (new_decl->Type()) {
        case DeclType::VAR: {
            return AddVar<LocalVariable>(allocator, current_variable, new_decl);
        }
        case DeclType::FUNC: {
            return AddFunction<LocalVariable>(allocator, current_variable, new_decl, extension);
        }
        case DeclType::ENUM: {
            return InsertBinding(new_decl->Name(), allocator->New<EnumVariable>(new_decl, false)).first->second;
        }
        case DeclType::ENUM_LITERAL: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::ENUM_LITERAL);
        }
        case DeclType::INTERFACE: {
            return AddTSBinding<LocalVariable>(allocator, current_variable, new_decl, VariableFlags::INTERFACE);
        }
        case DeclType::IMPORT: {
            return AddImport(allocator, current_variable, new_decl);
        }
        case DeclType::EXPORT: {
            return allocator->New<LocalVariable>(new_decl, VariableFlags::NONE);
        }
        default: {
            return AddLexical<LocalVariable>(allocator, current_variable, new_decl);
        }
    }
}

void ModuleScope::AddImportDecl(ir::ImportDeclaration *import_decl, ImportDeclList &&decls)
{
    auto res = imports_.emplace_back(import_decl, decls);

    for (auto &decl : res.second) {
        decl->BindNode(import_decl);
    }
}

void ModuleScope::AddExportDecl(ir::AstNode *export_decl, ExportDecl *decl)
{
    decl->BindNode(export_decl);

    ArenaVector<ExportDecl *> decls(allocator_->Adapter());
    decls.push_back(decl);

    AddExportDecl(export_decl, std::move(decls));
}

void ModuleScope::AddExportDecl(ir::AstNode *export_decl, ExportDeclList &&decls)
{
    auto res = exports_.emplace_back(export_decl, decls);

    for (auto &decl : res.second) {
        decl->BindNode(export_decl);
    }
}

Variable *ModuleScope::AddImport(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl)
{
    if (current_variable != nullptr && current_variable->Declaration()->Type() != DeclType::VAR) {
        return nullptr;
    }

    if (new_decl->Node()->IsImportNamespaceSpecifier()) {
        return InsertBinding(new_decl->Name(), allocator->New<LocalVariable>(new_decl, VariableFlags::READONLY))
            .first->second;
    }

    auto *variable = allocator->New<ModuleVariable>(new_decl, VariableFlags::NONE);
    variable->ExoticName() = new_decl->AsImportDecl()->ImportName();
    InsertBinding(new_decl->Name(), variable);
    return variable;
}

bool ModuleScope::ExportAnalysis()
{
    std::set<util::StringView> exported_names;

    for (const auto &[exportDecl, decls] : exports_) {
        if (exportDecl->IsExportAllDeclaration()) {
            const auto *export_all_decl = exportDecl->AsExportAllDeclaration();

            if (export_all_decl->Exported() != nullptr) {
                auto result = exported_names.insert(export_all_decl->Exported()->Name());
                if (!result.second) {
                    return false;
                }
            }

            continue;
        }

        if (exportDecl->IsExportNamedDeclaration()) {
            const auto *export_named_decl = exportDecl->AsExportNamedDeclaration();

            if (export_named_decl->Source() != nullptr) {
                continue;
            }
        }

        for (const auto *decl : decls) {
            binder::Variable *variable = FindLocal(decl->LocalName());

            if (variable == nullptr) {
                continue;
            }

            auto result = exported_names.insert(decl->ExportName());
            if (!result.second) {
                return false;
            }

            if (!variable->IsModuleVariable()) {
                variable->AddFlag(VariableFlags::LOCAL_EXPORT);
                local_exports_.insert({variable, decl->ExportName()});
            }
        }
    }

    return true;
}

// LocalScope

Variable *LocalScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    return AddLocal(allocator, current_variable, new_decl, extension);
}

// NOLINTNEXTLINE(google-default-arguments)
Variable *ClassScope::FindLocal(const util::StringView &name, ResolveBindingOptions options) const
{
    if ((options & ResolveBindingOptions::TYPE_ALIASES) != 0) {
        auto found = type_alias_scope_->Bindings().find(name);
        if (found != type_alias_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::VARIABLES) != 0) {
        auto found = instance_field_scope_->Bindings().find(name);
        if (found != instance_field_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_VARIABLES) != 0) {
        auto found = static_field_scope_->Bindings().find(name);
        if (found != static_field_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::DECLARATION) != 0) {
        auto found = instance_decl_scope_->Bindings().find(name);
        if (found != instance_decl_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_DECLARATION) != 0) {
        auto found = static_decl_scope_->Bindings().find(name);
        if (found != static_decl_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::METHODS) != 0) {
        auto found = instance_method_scope_->Bindings().find(name);
        if (found != instance_method_scope_->Bindings().end()) {
            return found->second;
        }
    }

    if ((options & ResolveBindingOptions::STATIC_METHODS) != 0) {
        auto found = static_method_scope_->Bindings().find(name);
        if (found != static_method_scope_->Bindings().end()) {
            return found->second;
        }
    }

    return nullptr;
}

Variable *ClassScope::AddBinding(ArenaAllocator *allocator, [[maybe_unused]] Variable *current_variable, Decl *new_decl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    VariableFlags flags = VariableFlags::NONE;
    bool is_static = new_decl->Node()->IsStatic();
    ir::Identifier *ident {};
    LocalScope *target_scope {};

    if (is_static) {
        flags |= VariableFlags::STATIC;
    }

    const auto decl_type = new_decl->Type();
    switch (decl_type) {
        case DeclType::CONST:
        case DeclType::LET: {
            target_scope = is_static ? static_field_scope_ : instance_field_scope_;
            ident = new_decl->Node()->AsClassProperty()->Id();
            flags |= VariableFlags::PROPERTY;
            break;
        }
        case DeclType::INTERFACE: {
            target_scope = is_static ? static_decl_scope_ : instance_decl_scope_;
            ident = new_decl->Node()->AsTSInterfaceDeclaration()->Id();
            flags |= VariableFlags::INTERFACE;
            break;
        }
        case DeclType::CLASS: {
            target_scope = is_static ? static_decl_scope_ : instance_decl_scope_;
            ident = new_decl->Node()->AsClassDefinition()->Ident();
            flags |= VariableFlags::CLASS;
            break;
        }
        case DeclType::ENUM_LITERAL: {
            target_scope = is_static ? static_decl_scope_ : instance_decl_scope_;
            ident = new_decl->Node()->AsTSEnumDeclaration()->Key();
            flags |= VariableFlags::ENUM_LITERAL;
            break;
        }
        case DeclType::TYPE_ALIAS: {
            target_scope = type_alias_scope_;
            ident = new_decl->Node()->AsTSTypeAliasDeclaration()->Id();
            flags |= VariableFlags::TYPE_ALIAS;
            break;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    if (FindLocal(new_decl->Name(), ResolveBindingOptions::ALL) != nullptr) {
        return nullptr;
    }

    auto *var = target_scope->AddBinding(allocator, nullptr, new_decl, extension);

    if (var == nullptr) {
        return nullptr;
    }

    var->SetScope(this);
    var->AddFlag(flags);

    if (ident != nullptr) {
        ident->SetVariable(var);
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

        slot_index_++;
        loop_type_ = ScopeType::LOOP_DECL;
        auto *copied_var = var->AsLocalVariable()->Copy(allocator, var->Declaration());
        copied_var->AddFlag(VariableFlags::INITIALIZED | VariableFlags::PER_ITERATION);
        var->AddFlag(VariableFlags::LOOP_DECL);
        loop_scope_->InsertBinding(name, copied_var);
    }

    if (loop_type_ == ScopeType::LOOP_DECL) {
        auto *parent_var_scope = Parent()->EnclosingVariableScope();
        slot_index_ = std::max(slot_index_, parent_var_scope->LexicalSlots());
        eval_bindings_ = parent_var_scope->EvalBindings();
        init_scope_ = allocator->New<LocalScope>(allocator, Parent());
        init_scope_->BindNode(Node());
        init_scope_->ReplaceBindings(bindings);
    }
}

void LoopScope::ConvertToVariableScope(ArenaAllocator *allocator)
{
    decl_scope_->ConvertToVariableScope(allocator);

    if (loop_type_ != ScopeType::LOCAL) {
        return;
    }

    for (const auto &[_, var] : Bindings()) {
        (void)_;
        if (var->LexicalBound() && var->Declaration()->IsLetDecl()) {
            ASSERT(decl_scope_->NeedLexEnv());
            loop_type_ = ScopeType::LOOP;
            break;
        }
    }

    if (loop_type_ == ScopeType::LOOP) {
        slot_index_ = std::max(slot_index_, decl_scope_->LexicalSlots());
        eval_bindings_ = decl_scope_->EvalBindings();
    }
}

Variable *CatchParamScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                      [[maybe_unused]] ScriptExtension extension)
{
    return AddParam(allocator, current_variable, new_decl, VariableFlags::INITIALIZED);
}

Variable *CatchScope::AddBinding(ArenaAllocator *allocator, Variable *current_variable, Decl *new_decl,
                                 [[maybe_unused]] ScriptExtension extension)
{
    if (!new_decl->IsVarDecl() && (param_scope_->FindLocal(new_decl->Name()) != nullptr)) {
        return nullptr;
    }

    return AddLocal(allocator, current_variable, new_decl, extension);
}
}  // namespace panda::es2panda::binder
