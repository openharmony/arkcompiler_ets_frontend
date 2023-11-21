/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "scopesInitPhase.h"

namespace panda::es2panda::compiler {
bool ScopesInitPhase::Perform(PhaseContext *ctx, parser::Program *program)
{
    Prepare(ctx, program);
    HandleBlockStmt(program->Ast(), GetScope());
    Finalize();
    return true;
}

void ScopesInitPhase::VisitScriptFunction(ir::ScriptFunction *script_function)
{
    HandleFunction(script_function);
}

void ScopesInitPhase::VisitBlockStatement(ir::BlockStatement *block_stmt)
{
    auto local_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    HandleBlockStmt(block_stmt, GetScope());
}

void ScopesInitPhase::VisitImportDeclaration(ir::ImportDeclaration *import_declaration)
{
    ImportDeclarationContext import_ctx(VarBinder());
    Iterate(import_declaration);
    import_ctx.BindImportDecl(import_declaration);
}

void ScopesInitPhase::VisitClassStaticBlock(ir::ClassStaticBlock *static_block)
{
    Iterate(static_block);
}

void ScopesInitPhase::VisitMethodDefinition(ir::MethodDefinition *method_definition)
{
    Iterate(method_definition);
}

varbinder::FunctionParamScope *ScopesInitPhase::HandleFunctionSig(ir::TSTypeParameterDeclaration *type_params,
                                                                  const ir::FunctionSignature::FunctionParams &params,
                                                                  ir::TypeNode *return_type)
{
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(type_params);

    auto lexical_scope = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());
    CallFuncParams(params);
    CallNode(return_type);

    return lexical_scope.GetScope();
}

void ScopesInitPhase::HandleFunction(ir::ScriptFunction *function)
{
    CallNode(function->Id());
    auto func_param_scope =
        HandleFunctionSig(function->TypeParams(), function->Params(), function->ReturnTypeAnnotation());
    auto param_ctx =
        varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), func_param_scope, false);

    auto function_ctx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
    auto *function_scope = function_ctx.GetScope();
    BindFunctionScopes(function_scope, func_param_scope);

    if (function->Body() != nullptr && function->Body()->IsBlockStatement()) {
        HandleBlockStmt(function->Body()->AsBlockStatement(), function_scope);
    } else {
        Iterate(function->Body());
    }
    BindScopeNode(function_scope, function);
    func_param_scope->BindNode(function);
}

void ScopesInitPhase::HandleBlockStmt(ir::BlockStatement *block, varbinder::Scope *scope)
{
    BindScopeNode(scope, block);
    Iterate(block);
}

void ScopesInitPhase::VisitClassDefinition(ir::ClassDefinition *class_def)
{
    auto class_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    VarBinder()->AddDecl<varbinder::ConstDecl>(class_def->Start(), class_def->PrivateId());
    BindClassName(class_def);

    auto *class_scope = class_ctx.GetScope();
    BindScopeNode(class_scope, class_def);
    Iterate(class_def);
}

void ScopesInitPhase::VisitForUpdateStatement(ir::ForUpdateStatement *for_update_stmt)
{
    auto decl_ctx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(for_update_stmt->Init());

    varbinder::LexicalScope<varbinder::LoopScope> lexical_scope(VarBinder());
    CallNode(for_update_stmt->Test());
    CallNode(for_update_stmt->Update());
    CallNode(for_update_stmt->Body());
    lexical_scope.GetScope()->BindDecls(decl_ctx.GetScope());
    HandleFor(decl_ctx.GetScope(), lexical_scope.GetScope(), for_update_stmt);
}

void ScopesInitPhase::VisitForInStatement(ir::ForInStatement *for_in_stmt)
{
    auto decl_ctx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(for_in_stmt->Left());

    varbinder::LexicalScope<varbinder::LoopScope> lexical_scope(VarBinder());
    CallNode(for_in_stmt->Right());
    CallNode(for_in_stmt->Body());
    HandleFor(decl_ctx.GetScope(), lexical_scope.GetScope(), for_in_stmt);
}
void ScopesInitPhase::VisitForOfStatement(ir::ForOfStatement *for_of_stmt)
{
    auto decl_ctx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(for_of_stmt->Left());

    varbinder::LexicalScope<varbinder::LoopScope> lexical_scope(VarBinder());
    CallNode(for_of_stmt->Right());
    CallNode(for_of_stmt->Body());
    HandleFor(decl_ctx.GetScope(), lexical_scope.GetScope(), for_of_stmt);
}

void ScopesInitPhase::VisitCatchClause(ir::CatchClause *catch_clause)
{
    auto catch_param_ctx = varbinder::LexicalScope<varbinder::CatchParamScope>(VarBinder());
    auto *catch_param_scope = catch_param_ctx.GetScope();
    auto *param = catch_clause->Param();

    CallNode(param);

    if (param != nullptr) {
        auto [param_decl, var] = VarBinder()->AddParamDecl(param);
        (void)param_decl;
        if (param->IsIdentifier()) {
            var->SetScope(catch_param_scope);
            param->AsIdentifier()->SetVariable(var);
        }
    }
    catch_param_scope->BindNode(param);

    auto catch_ctx = varbinder::LexicalScope<varbinder::CatchScope>(VarBinder());
    auto *catch_scope = catch_ctx.GetScope();

    catch_scope->AssignParamScope(catch_param_scope);
    auto body = catch_clause->Body();
    HandleBlockStmt(body, catch_scope);

    BindScopeNode(catch_scope, catch_clause);
}

void ScopesInitPhase::VisitVariableDeclarator(ir::VariableDeclarator *var_decl)
{
    auto init = var_decl->Id();
    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(init);
    for (auto *binding : bindings) {
        auto [decl, var] = AddVarDecl(var_decl->Flag(), var_decl->Start(), binding->Name());
        BindVarDecl(binding, init, decl, var);
    }
    Iterate(var_decl);
}

void ScopesInitPhase::VisitSwitchStatement(ir::SwitchStatement *switch_stmt)
{
    CallNode(switch_stmt->Discriminant());
    auto local_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindScopeNode(local_ctx.GetScope(), switch_stmt);
    CallNode(switch_stmt->Cases());
}

void ScopesInitPhase::VisitWhileStatement(ir::WhileStatement *while_stmt)
{
    CallNode(while_stmt->Test());
    varbinder::LexicalScope<varbinder::LoopScope> lexical_scope(VarBinder());
    BindScopeNode(lexical_scope.GetScope(), while_stmt);
    CallNode(while_stmt->Body());
}

void ScopesInitPhase::VisitETSStructDeclaration(ir::ETSStructDeclaration *struct_decl)
{
    Iterate(struct_decl);
    BindClassDefinition(struct_decl->Definition());
}

void ScopesInitPhase::VisitClassDeclaration(ir::ClassDeclaration *class_decl)
{
    Iterate(class_decl);
    BindClassDefinition(class_decl->Definition());
}

void ScopesInitPhase::VisitDoWhileStatement(ir::DoWhileStatement *do_while_stmt)
{
    varbinder::LexicalScope<varbinder::LoopScope> lexical_scope(VarBinder());
    BindScopeNode(lexical_scope.GetScope(), do_while_stmt);
    Iterate(do_while_stmt);
}

void ScopesInitPhase::VisitFunctionDeclaration(ir::FunctionDeclaration *func_decl)
{
    const auto func = func_decl->Function();
    if (!func_decl->IsAnonymous()) {
        CreateFuncDecl(func);
    }
    Iterate(func_decl);
}

void ScopesInitPhase::VisitExportAllDeclaration(ir::ExportAllDeclaration *export_all_decl)
{
    Iterate(export_all_decl);
    const auto name = export_all_decl->Exported() != nullptr ? export_all_decl->Exported()->Name() : "*";
    auto *decl = VarBinder()->AddDecl<varbinder::ExportDecl>(export_all_decl->Start(), name, "*");
    VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(export_all_decl, decl);
}

void ScopesInitPhase::VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *import_spec)
{
    Iterate(import_spec);
    VarBinder()->AddDecl<varbinder::ImportDecl>(import_spec->Start(), "*", import_spec->Local()->Name(), import_spec);
}

void ScopesInitPhase::VisitImportSpecifier(ir::ImportSpecifier *import_spec)
{
    Iterate(import_spec);
    const auto *imported = import_spec->Imported();
    VarBinder()->AddDecl<varbinder::ImportDecl>(import_spec->Start(), imported->Name(), import_spec->Local()->Name(),
                                                import_spec);
}

void ScopesInitPhase::VisitImportDefaultSpecifier(ir::ImportDefaultSpecifier *import_spec)
{
    Iterate(import_spec);
    const auto *local = import_spec->Local();
    VarBinder()->AddDecl<varbinder::ImportDecl>(local->Start(), "default", local->Name(), import_spec);
}

void ScopesInitPhase::VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *export_decl)
{
    ExportDeclarationContext export_decl_ctx(VarBinder());
    Iterate(export_decl);
    export_decl_ctx.BindExportDecl(export_decl);
}

void ScopesInitPhase::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_expr)
{
    Iterate(arrow_expr);
}

void ScopesInitPhase::VisitDirectEvalExpression(ir::DirectEvalExpression *direct_call_expr)
{
    VarBinder()->PropagateDirectEval();
    Iterate(direct_call_expr);
}

void ScopesInitPhase::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl)
{
    if (export_decl->Decl() != nullptr) {
        ExportDeclarationContext export_decl_ctx(VarBinder());
        Iterate(export_decl);
        export_decl_ctx.BindExportDecl(export_decl);
    } else {
        varbinder::ModuleScope::ExportDeclList export_decls(program_->Allocator()->Adapter());

        for (auto *spec : export_decl->Specifiers()) {
            auto *decl = VarBinder()->AddDecl<varbinder::ExportDecl>(export_decl->Start(), spec->Exported()->Name(),
                                                                     spec->Local()->Name(), spec);
            export_decls.push_back(decl);
        }
        VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(export_decl, std::move(export_decls));
    }
}

void ScopesInitPhase::VisitTSFunctionType(ir::TSFunctionType *func_type)
{
    varbinder::LexicalScope<varbinder::FunctionParamScope> lexical_scope(VarBinder());
    auto *func_param_scope = lexical_scope.GetScope();
    BindScopeNode(func_param_scope, func_type);
    Iterate(func_type);
}

void ScopesInitPhase::SetProgram(parser::Program *program) noexcept
{
    program_ = program;
}

void ScopesInitPhase::CallFuncParams(const ArenaVector<ir::Expression *> &params)
{
    // NOTE: extract params to separate class
    for (auto *param : params) {
        if (!param->IsETSParameterExpression()) {
            VarBinder()->AddParamDecl(param);
        }
    }
    CallNode(params);
}

void ScopesInitPhase::IterateNoTParams(ir::ClassDefinition *class_def)
{
    CallNode(class_def->Super());
    CallNode(class_def->SuperTypeParams());
    CallNode(class_def->Implements());
    CallNode(class_def->Ctor());
    CallNode(class_def->Body());
}

void ScopesInitPhase::ThrowSyntaxError(std::string_view error_message, const lexer::SourcePosition &pos) const
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::SYNTAX, program_->SourceFile().Utf8(), error_message, loc.line, loc.col};
}

void ScopesInitPhase::CreateFuncDecl(ir::ScriptFunction *func)
{
    VarBinder()->AddDecl<varbinder::FunctionDecl>(func->Id()->Start(), Allocator(), func->Id()->Name(), func);
}

util::StringView ScopesInitPhase::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    return id->Name();
}

varbinder::Decl *ScopesInitPhase::BindClassName(ir::ClassDefinition *class_def)
{
    const auto ident_node = class_def->Ident();
    if (ident_node == nullptr) {
        return nullptr;
    }

    auto ident_decl = VarBinder()->AddDecl<varbinder::ConstDecl>(ident_node->Start(), ident_node->Name());
    if (ident_decl != nullptr) {
        ident_decl->BindNode(class_def);
    }
    return ident_decl;
}

void ScopesInitPhase::BindFunctionScopes(varbinder::FunctionScope *scope, varbinder::FunctionParamScope *param_scope)
{
    scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(scope);
}

void ScopesInitPhase::BindClassDefinition(ir::ClassDefinition *class_def)
{
    if (class_def->IsGlobal()) {
        return;  // We handle it in ClassDeclaration
    }
    const auto loc_start = class_def->Ident()->Start();
    const auto &class_name = class_def->Ident()->Name();
    if ((class_def->Modifiers() & ir::ClassDefinitionModifiers::CLASS_DECL) != 0U) {
        VarBinder()->AddDecl<varbinder::ClassDecl>(loc_start, class_name, class_def);
    } else {
        VarBinder()->AddDecl<varbinder::LetDecl>(loc_start, class_name, class_def);
    }
}

std::tuple<varbinder::Decl *, varbinder::Variable *> ScopesInitPhase::AddVarDecl(ir::VariableDeclaratorFlag flag,
                                                                                 lexer::SourcePosition start_loc,
                                                                                 const util::StringView &name)
{
    switch (flag) {
        case ir::VariableDeclaratorFlag::LET:
            return VarBinder()->NewVarDecl<varbinder::LetDecl>(start_loc, name);
        case ir::VariableDeclaratorFlag::VAR:
            return VarBinder()->NewVarDecl<varbinder::VarDecl>(start_loc, name);
        case ir::VariableDeclaratorFlag::CONST:
            return VarBinder()->NewVarDecl<varbinder::ConstDecl>(start_loc, name);
        default:
            UNREACHABLE();
    }
}

void ScopesInitPhase::BindVarDecl([[maybe_unused]] ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                                  [[maybe_unused]] varbinder::Variable *var)
{
    decl->BindNode(init);
}

void ScopesInitPhase::VisitFunctionExpression(ir::FunctionExpression *func_expr)
{
    Iterate(func_expr);
    if (!func_expr->IsAnonymous()) {
        auto func = func_expr->Function();
        auto id = func_expr->Id();
        auto *func_param_scope = func->Scope()->ParamScope();
        func_param_scope->BindName(Allocator(), id->Name());
        func->SetIdent(id);
    }
}

void ScopesInitPhase::Prepare(ScopesInitPhase::PhaseContext *ctx, parser::Program *program)
{
    ctx_ = ctx;
    program_ = program;
}

void ScopesInitPhase::Finalize()
{
    AnalyzeExports();
}

void ScopesInitPhase::AnalyzeExports()
{
    if (Program()->Kind() == parser::ScriptKind::MODULE && VarBinder()->TopScope()->IsModuleScope() &&
        !VarBinder()->TopScope()->AsModuleScope()->ExportAnalysis()) {
        ThrowSyntaxError("Invalid exported binding", Program()->Ast()->End());
    }
}

void ScopeInitTyped::VisitTSModuleDeclaration(ir::TSModuleDeclaration *module_decl)
{
    if (!module_decl->IsExternalOrAmbient()) {
        auto *decl = VarBinder()->AddDecl<varbinder::VarDecl>(module_decl->Name()->Start(),
                                                              module_decl->Name()->AsIdentifier()->Name());
        decl->BindNode(module_decl);
    }
    auto local_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindScopeNode(local_ctx.GetScope(), module_decl);
    Iterate(module_decl);
}

void ScopeInitTyped::VisitTSModuleBlock(ir::TSModuleBlock *block)
{
    auto local_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(block);
    BindScopeNode(local_ctx.GetScope(), block);
}

void ScopeInitTyped::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *type_alias_decl)
{
    const auto id = type_alias_decl->Id();
    varbinder::TSBinding ts_binding(Allocator(), id->Name());
    auto *decl = VarBinder()->AddTsDecl<varbinder::TypeAliasDecl>(id->Start(), ts_binding.View());
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    decl->BindNode(type_alias_decl);
    Iterate(type_alias_decl);
}

util::StringView ScopeInitTyped::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    varbinder::TSBinding ts_binding(Allocator(), id->Name());
    return ts_binding.View();
}

void ScopeInitTyped::VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interf_decl)
{
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    const auto ident = interf_decl->Id();
    const auto name = FormInterfaceOrEnumDeclarationIdBinding(ident);
    auto res = bindings.find(name);

    varbinder::InterfaceDecl *decl {};

    bool already_exists = false;
    if (res == bindings.end()) {
        decl = VarBinder()->AddTsDecl<varbinder::InterfaceDecl>(ident->Start(), Allocator(), name);
    } else if (!AllowInterfaceRedeclaration()) {
        ThrowSyntaxError("Interface redeclaration is not allowed", interf_decl->Start());
    } else if (!res->second->Declaration()->IsInterfaceDecl()) {
        VarBinder()->ThrowRedeclaration(ident->Start(), ident->Name());
    } else {
        decl = res->second->Declaration()->AsInterfaceDecl();
        already_exists = true;
    }

    CallNode(ident);
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(interf_decl->TypeParams());
    CallNode(interf_decl->Extends());

    auto local_scope = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    auto *ident_decl = VarBinder()->AddDecl<varbinder::ConstDecl>(ident->Start(), ident->Name());
    ident_decl->BindNode(interf_decl);
    BindScopeNode(local_scope.GetScope(), interf_decl);

    CallNode(interf_decl->Body());
    if (!already_exists) {
        decl->BindNode(interf_decl);
    }
    decl->Add(interf_decl);
}

void ScopeInitTyped::VisitTSEnumMember(ir::TSEnumMember *enum_member)
{
    const auto key = enum_member->Key();
    util::StringView name;
    if (key->IsIdentifier()) {
        name = key->AsIdentifier()->Name();
    } else if (key->IsStringLiteral()) {
        name = key->AsStringLiteral()->Str();
    } else {
        UNREACHABLE();
    }
    auto *decl = VarBinder()->AddDecl<varbinder::EnumDecl>(key->Start(), name);
    decl->BindNode(enum_member);
}

void ScopeInitTyped::VisitTSEnumDeclaration(ir::TSEnumDeclaration *enum_decl)
{
    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(enum_decl->Key());
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    auto res = bindings.find(ident);

    varbinder::EnumLiteralDecl *decl {};
    if (res == bindings.end()) {
        decl = VarBinder()->AddTsDecl<varbinder::EnumLiteralDecl>(enum_decl->Start(), ident, enum_decl->IsConst());
        varbinder::LexicalScope enum_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
        decl->BindScope(enum_ctx.GetScope());
        BindScopeNode(VarBinder()->GetScope()->AsLocalScope(), enum_decl);
    } else if (!res->second->Declaration()->IsEnumLiteralDecl() ||
               (enum_decl->IsConst() ^ res->second->Declaration()->AsEnumLiteralDecl()->IsConst()) != 0) {
        auto loc = enum_decl->Key()->End();
        loc.index++;
        VarBinder()->ThrowRedeclaration(loc, enum_decl->Key()->Name());
    } else {
        decl = res->second->Declaration()->AsEnumLiteralDecl();

        auto scope_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), decl->Scope());
    }
    decl->BindNode(enum_decl);
    Iterate(enum_decl);
}

void ScopeInitTyped::VisitTSTypeParameter(ir::TSTypeParameter *type_param)
{
    auto decl = VarBinder()->AddDecl<varbinder::TypeParameterDecl>(type_param->Start(), type_param->Name()->Name());
    decl->BindNode(type_param);
    Iterate(type_param);
}

void ScopeInitTyped::VisitTSTypeParameterDeclaration(ir::TSTypeParameterDeclaration *param_decl)
{
    BindScopeNode(VarBinder()->GetScope()->AsLocalScope(), param_decl);
    Iterate(param_decl);
}

void ScopeInitTyped::VisitClassDefinition(ir::ClassDefinition *class_def)
{
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(class_def->TypeParams());

    auto class_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindClassName(class_def);
    VarBinder()->AddDecl<varbinder::ConstDecl>(class_def->Start(), class_def->PrivateId());
    BindScopeNode(class_ctx.GetScope(), class_def);
    IterateNoTParams(class_def);
}

void ScopesInitPhaseTs::VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *export_decl)
{
    ExportDeclarationContext export_decl_ctx(VarBinder());
    Iterate(export_decl);
}

void ScopesInitPhaseTs::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl)
{
    ExportDeclarationContext export_decl_ctx(VarBinder());
    Iterate(export_decl);
}

void ScopesInitPhaseTs::VisitImportDeclaration(ir::ImportDeclaration *import_declaration)
{
    ImportDeclarationContext import_ctx(VarBinder());
    Iterate(import_declaration);
}

void ScopesInitPhaseTs::VisitTSFunctionType(ir::TSFunctionType *constr_type)
{
    auto lexical_scope = HandleFunctionSig(constr_type->TypeParams(), constr_type->Params(), constr_type->ReturnType());
    BindScopeNode(lexical_scope, constr_type);
}

void ScopesInitPhaseTs::CreateFuncDecl(ir::ScriptFunction *func)
{
    const auto ident_node = func->Id();
    const auto start_loc = ident_node->Start();
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    auto res = bindings.find(ident_node->Name());
    varbinder::FunctionDecl *decl {};

    if (res == bindings.end()) {
        decl = VarBinder()->AddDecl<varbinder::FunctionDecl>(start_loc, Allocator(), ident_node->Name(), func);
    } else {
        varbinder::Decl *current_decl = res->second->Declaration();

        if (!current_decl->IsFunctionDecl() ||
            !current_decl->AsFunctionDecl()->Node()->AsScriptFunction()->IsOverload()) {
            VarBinder()->ThrowRedeclaration(start_loc, current_decl->Name());
        }
        decl = current_decl->AsFunctionDecl();
    }

    decl->Add(func);
}

void ScopesInitPhaseTs::VisitTSConstructorType(ir::TSConstructorType *constr_t)
{
    auto func_param_scope = HandleFunctionSig(constr_t->TypeParams(), constr_t->Params(), constr_t->ReturnType());
    BindScopeNode(func_param_scope, constr_t);
}

void ScopesInitPhaseTs::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_f_expr)
{
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(arrow_f_expr);
}

void ScopesInitPhaseTs::VisitTSSignatureDeclaration(ir::TSSignatureDeclaration *sign_decl)
{
    auto func_param_scope =
        HandleFunctionSig(sign_decl->TypeParams(), sign_decl->Params(), sign_decl->ReturnTypeAnnotation());
    BindScopeNode(func_param_scope, sign_decl);
}

void ScopesInitPhaseTs::VisitTSMethodSignature(ir::TSMethodSignature *method_sign)
{
    auto func_param_scope =
        HandleFunctionSig(method_sign->TypeParams(), method_sign->Params(), method_sign->ReturnTypeAnnotation());
    BindScopeNode(func_param_scope, method_sign);
}

void ScopesInitPhaseETS::RunExternalNode(ir::AstNode *node, varbinder::VarBinder *varbinder)
{
    auto program = parser::Program(varbinder->Allocator(), varbinder);
    RunExternalNode(node, &program);
}

void ScopesInitPhaseETS::RunExternalNode(ir::AstNode *node, parser::Program *ctx)
{
    auto scopes_phase = ScopesInitPhaseETS();
    scopes_phase.SetProgram(ctx);
    scopes_phase.CallNode(node);
}

bool ScopesInitPhaseETS::Perform(PhaseContext *ctx, parser::Program *program)
{
    Prepare(ctx, program);

    if (program->VarBinder()->TopScope() == nullptr) {
        program->VarBinder()->InitTopScope();
        BindScopeNode(GetScope(), program->Ast());
        AddGlobalToBinder(program);
    }
    HandleProgram(program);
    Finalize();
    return true;
}

void ScopesInitPhaseETS::HandleProgram(parser::Program *program)
{
    for (auto &[_, prog_list] : program->ExternalSources()) {
        (void)_;
        auto saved_top_scope(program->VarBinder()->TopScope());
        auto main_prog = prog_list.front();
        main_prog->VarBinder()->InitTopScope();
        AddGlobalToBinder(main_prog);
        BindScopeNode(main_prog->VarBinder()->GetScope(), main_prog->Ast());
        auto global_class = main_prog->GlobalClass();
        auto global_scope = main_prog->GlobalScope();
        for (auto &prog : prog_list) {
            prog->SetGlobalClass(global_class);
            BindScopeNode(prog->VarBinder()->GetScope(), prog->Ast());
            prog->VarBinder()->ResetTopScope(global_scope);
            if (main_prog->Ast() != nullptr) {
                ScopesInitPhaseETS().Perform(Context(), prog);
            }
        }
        program->VarBinder()->ResetTopScope(saved_top_scope);
    }
    ASSERT(program->Ast() != nullptr);

    HandleETSScript(program->Ast());
}

void ScopesInitPhaseETS::BindVarDecl(ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                                     varbinder::Variable *var)
{
    binding->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::LOCAL);
    decl->BindNode(init);
}

void ScopesInitPhaseETS::VisitClassStaticBlock(ir::ClassStaticBlock *static_block)
{
    const auto func = static_block->Function();

    {
        auto func_param_ctx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());
        auto *func_param_scope = func_param_ctx.GetScope();
        auto func_ctx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
        auto *func_scope = func_ctx.GetScope();

        func->Body()->AsBlockStatement()->SetScope(func_scope);
        BindScopeNode(func_scope, func);
        func_param_scope->BindNode(func);
        BindFunctionScopes(func_scope, func_param_scope);
        Iterate(func->Body()->AsBlockStatement());
    }

    auto class_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        VarBinder(), VarBinder()->GetScope()->AsClassScope()->StaticMethodScope());

    auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(static_block->Start(), Allocator(),
                                                                     func->Id()->Name(), static_block);
    (void)_;
    var->AddFlag(varbinder::VariableFlags::METHOD);
    func->Id()->SetVariable(var);
}

void ScopesInitPhaseETS::VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *import_spec)
{
    if (import_spec->Local()->Name().Empty()) {
        return;
    }
    VarBinder()->AddDecl<varbinder::ImportDecl>(import_spec->Start(), import_spec->Local()->Name(),
                                                import_spec->Local()->Name(), import_spec);
    Iterate(import_spec);
}

void ScopesInitPhaseETS::DeclareClassMethod(ir::MethodDefinition *method)
{
    const auto method_name = method->Id();

    ASSERT(VarBinder()->GetScope()->IsClassScope());

    if (method->AsMethodDefinition()->Function()->IsDefaultParamProxy()) {
        return;
    }

    auto *const cls_scope = VarBinder()->GetScope()->AsClassScope();
    if (cls_scope->FindLocal(method_name->Name(), varbinder::ResolveBindingOptions::VARIABLES |
                                                      varbinder::ResolveBindingOptions::DECLARATION) != nullptr) {
        VarBinder()->ThrowRedeclaration(method_name->Start(), method_name->Name());
    }

    varbinder::LocalScope *target_scope {};
    if (method->IsStatic() || method->IsConstructor()) {
        target_scope = cls_scope->StaticMethodScope();
    } else {
        target_scope = cls_scope->InstanceMethodScope();
    }
    auto *found = target_scope->FindLocal(method_name->Name(), varbinder::ResolveBindingOptions::BINDINGS);

    auto add_overload = [](ir::MethodDefinition *overload, varbinder::Variable *of) {
        auto *current_node = of->Declaration()->Node();
        current_node->AsMethodDefinition()->AddOverload(overload);
        overload->Id()->SetVariable(of);
        overload->SetParent(current_node);
    };

    if (found == nullptr) {
        auto class_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), target_scope);
        auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(method_name->Start(), Allocator(),
                                                                         method_name->Name(), method);
        (void)_;
        var->SetScope(cls_scope);
        var->AddFlag(varbinder::VariableFlags::METHOD);
        method_name->SetVariable(var);
        for (auto *overload : method->Overloads()) {
            ASSERT(overload->Function()->IsDefaultParamProxy());
            overload->Id()->SetVariable(var);
            overload->SetParent(var->Declaration()->Node());
        }
    } else {
        if (method_name->Name().Is(compiler::Signatures::MAIN) && cls_scope->Parent()->IsGlobalScope()) {
            ThrowSyntaxError("Main overload is not enabled", method_name->Start());
        }
        add_overload(method, found);
        method->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);

        // default params proxy
        for (auto *overload : method->Overloads()) {
            ASSERT(overload->Function()->IsDefaultParamProxy());
            add_overload(overload, found);
        }
        method->ClearOverloads();
    }
}

void ScopesInitPhaseETS::VisitETSParameterExpression(ir::ETSParameterExpression *param_expr)
{
    auto *const var = std::get<1>(VarBinder()->AddParamDecl(param_expr));
    param_expr->Ident()->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    Iterate(param_expr);
}

void ScopesInitPhaseETS::VisitETSImportDeclaration(ir::ETSImportDeclaration *import_decl)
{
    ImportDeclarationContext import_ctx(VarBinder());
    if (import_decl->Language().IsDynamic()) {
        VarBinder()->AsETSBinder()->AddDynamicImport(import_decl);
    }
    Iterate(import_decl);
}

void ScopesInitPhaseETS::VisitTSEnumMember(ir::TSEnumMember *enum_member)
{
    auto ident = enum_member->Key()->AsIdentifier();
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(ident->Start(), ident->Name());
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::STATIC);
    ident->SetVariable(var);
    decl->BindNode(enum_member);
    Iterate(enum_member);
}

void ScopesInitPhaseETS::VisitMethodDefinition(ir::MethodDefinition *method)
{
    auto *cur_scope = VarBinder()->GetScope();
    const auto method_name = method->Id();
    auto res = cur_scope->Find(method_name->Name(), varbinder::ResolveBindingOptions::ALL);
    if (res.variable != nullptr && !res.variable->Declaration()->IsFunctionDecl() && res.scope == cur_scope) {
        VarBinder()->ThrowRedeclaration(method_name->Start(), res.name);
    }
    Iterate(method);
    DeclareClassMethod(method);
}

void ScopesInitPhaseETS::VisitETSFunctionType(ir::ETSFunctionType *func_type)
{
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    varbinder::LexicalScope<varbinder::FunctionParamScope> lexical_scope(VarBinder());
    auto *func_param_scope = lexical_scope.GetScope();
    BindScopeNode(func_param_scope, func_type);
    Iterate(func_type);
}

void ScopesInitPhaseETS::VisitETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *new_class_expr)
{
    CallNode(new_class_expr->GetArguments());
    CallNode(new_class_expr->GetTypeRef());
    if (new_class_expr->ClassDefinition() != nullptr) {
        const auto class_def = new_class_expr->ClassDefinition();
        auto *parent_class_scope = VarBinder()->GetScope();
        while (!parent_class_scope->IsClassScope()) {
            ASSERT(parent_class_scope->Parent());
            parent_class_scope = parent_class_scope->Parent();
        }
        auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
        auto *class_scope = class_ctx.GetScope();
        util::UString anonymous_name(util::StringView("#"), Allocator());
        anonymous_name.Append(std::to_string(parent_class_scope->AsClassScope()->GetAndIncrementAnonymousClassIdx()));
        BindScopeNode(class_scope, class_def);
        class_def->SetInternalName(anonymous_name.View());
        class_def->Ident()->SetName(anonymous_name.View());
        CallNode(class_def);
    }
}

void ScopesInitPhaseETS::VisitTSTypeParameter(ir::TSTypeParameter *type_param)
{
    auto [decl, var] =
        VarBinder()->NewVarDecl<varbinder::TypeParameterDecl>(type_param->Name()->Start(), type_param->Name()->Name());
    type_param->Name()->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::TYPE_PARAMETER);
    decl->BindNode(type_param);
}

void ScopesInitPhaseETS::VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interface_decl)
{
    {
        auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
        CallNode(interface_decl->TypeParams());
        CallNode(interface_decl->Extends());
        auto local_scope = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
        CallNode(interface_decl->Body());
        BindScopeNode(local_scope.GetScope(), interface_decl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(interface_decl->Id());
    auto *decl =
        VarBinder()->AddDecl<varbinder::InterfaceDecl>(interface_decl->Start(), Allocator(), name, interface_decl);
    decl->AsInterfaceDecl()->Add(interface_decl);
}

void ScopesInitPhaseETS::VisitTSEnumDeclaration(ir::TSEnumDeclaration *enum_decl)
{
    {
        const auto enum_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
        BindScopeNode(enum_ctx.GetScope(), enum_decl);
        Iterate(enum_decl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(enum_decl->Key());
    auto *decl =
        VarBinder()->AddDecl<varbinder::EnumLiteralDecl>(enum_decl->Start(), name, enum_decl, enum_decl->IsConst());
    decl->BindScope(enum_decl->Scope());
}

void ScopesInitPhaseETS::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *type_alias)
{
    VarBinder()->AddDecl<varbinder::TypeAliasDecl>(type_alias->Id()->Start(), type_alias->Id()->Name(), type_alias);
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(type_alias);
}

void ScopesInitPhaseETS::AddGlobalToBinder(parser::Program *program)
{
    auto global_id = program->GlobalClass()->Ident();

    auto [decl2, var] = program->VarBinder()->NewVarDecl<varbinder::ClassDecl>(global_id->Start(), global_id->Name());

    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(program->VarBinder());
    class_ctx.GetScope()->BindNode(program->GlobalClass());
    program->GlobalClass()->SetScope(class_ctx.GetScope());

    auto *class_decl = program->GlobalClass()->Parent();
    decl2->BindNode(class_decl);
    global_id->SetVariable(var);
}

void ScopesInitPhaseETS::HandleETSScript(ir::BlockStatement *script)
{
    for (auto decl : script->Statements()) {
        if (decl->IsETSImportDeclaration()) {
            CallNode(decl);
        } else {
            auto class_ctx =
                varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), Program()->GlobalClassScope());
            CallNode(decl);
        }
    }
    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), Program()->GlobalClassScope());

    for (auto decl : script->Statements()) {
        AddGlobalDeclaration(decl);
    }
}

void ScopesInitPhaseETS::VisitClassDefinition(ir::ClassDefinition *class_def)
{
    if (class_def->IsGlobal()) {
        ParseGlobalClass(class_def);
        return;
    }
    auto type_params_ctx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(class_def->TypeParams());
    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());

    IterateNoTParams(class_def);
    FilterOverloads(class_def->Body());
    auto *class_scope = class_ctx.GetScope();
    BindScopeNode(class_scope, class_def);
}

void ScopesInitPhaseETS::VisitTSInterfaceBody(ir::TSInterfaceBody *interf_body)
{
    Iterate(interf_body);
    FilterInterfaceOverloads(interf_body->Body());
}

void ScopesInitPhaseETS::FilterInterfaceOverloads(ArenaVector<ir::AstNode *, false> &props)
{
    auto condition = [](ir::AstNode *prop) {
        if (prop->IsMethodDefinition()) {
            const auto func = prop->AsMethodDefinition()->Function();
            return func->IsOverload() && func->Body() != nullptr;
        }
        return false;
    };
    props.erase(std::remove_if(props.begin(), props.end(), condition), props.end());
}

void ScopesInitPhaseETS::FilterOverloads(ArenaVector<ir::AstNode *, false> &props)
{
    auto condition = [](ir::AstNode *prop) {
        if (prop->IsMethodDefinition()) {
            const auto func = prop->AsMethodDefinition()->Function();
            return func->IsOverload();
        }
        return false;
    };
    props.erase(std::remove_if(props.begin(), props.end(), condition), props.end());
}

void ScopesInitPhaseETS::VisitClassProperty(ir::ClassProperty *class_prop)
{
    auto cur_scope = VarBinder()->GetScope();
    if (class_prop->IsClassStaticBlock()) {
        ASSERT(cur_scope->IsClassScope());
        auto class_ctx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
            VarBinder(), cur_scope->AsClassScope()->StaticMethodScope());
        auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(class_prop->Start(), Allocator(),
                                                                         class_prop->Id()->Name(), class_prop);
        (void)_;
        var->AddFlag(varbinder::VariableFlags::METHOD);
        class_prop->AsClassStaticBlock()->Function()->Id()->SetVariable(var);
    } else if (class_prop->IsConst()) {
        ASSERT(cur_scope->Parent() != nullptr);
        const auto initializer = class_prop->Value();
        if (initializer == nullptr && cur_scope->Parent()->IsGlobalScope() && !class_prop->IsDeclare()) {
            auto pos = class_prop->End();
            // NOTE: Just use property Name?
            if (!class_prop->TypeAnnotation()->IsETSPrimitiveType()) {
                pos.index--;
            }
            ThrowSyntaxError("Missing initializer in const declaration", pos);
        }
        VarBinder()->AddDecl<varbinder::ConstDecl>(class_prop->Key()->Start(),
                                                   class_prop->Key()->AsIdentifier()->Name(), class_prop);
    } else {
        VarBinder()->AddDecl<varbinder::LetDecl>(class_prop->Key()->Start(), class_prop->Key()->AsIdentifier()->Name(),
                                                 class_prop);
    }
    Iterate(class_prop);
}

void ScopesInitPhaseETS::ParseGlobalClass(ir::ClassDefinition *global)
{
    for (auto decl : global->Body()) {
        if (decl->IsDefaultExported()) {
            if (VarBinder()->AsETSBinder()->DefaultExport() != nullptr) {
                ThrowSyntaxError("Only one default export is allowed in a module", decl->Start());
            }
            VarBinder()->AsETSBinder()->SetDefaultExport(decl);
        }
        CallNode(decl);
    }
    FilterOverloads(global->Body());
}

void ScopesInitPhaseETS::AddGlobalDeclaration(ir::AstNode *node)
{
    ir::Identifier *ident = nullptr;
    bool is_builtin = false;
    switch (node->Type()) {
        case ir::AstNodeType::CLASS_DECLARATION: {
            auto def = node->AsClassDeclaration()->Definition();
            if (def->IsGlobal()) {
                return;
            }
            ident = def->Ident();
            is_builtin = def->IsFromExternal();
            break;
        }
        case ir::AstNodeType::STRUCT_DECLARATION: {
            ident = node->AsETSStructDeclaration()->Definition()->Ident();
            is_builtin = node->AsETSStructDeclaration()->Definition()->IsFromExternal();
            break;
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            ident = node->AsTSInterfaceDeclaration()->Id();
            is_builtin = node->AsTSInterfaceDeclaration()->IsFromExternal();
            break;
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            ident = node->AsTSEnumDeclaration()->Key();
            break;
        }
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION: {
            ident = node->AsTSTypeAliasDeclaration()->Id();
            break;
        }
        default: {
            break;
        }
    }
    if (ident != nullptr) {
        VarBinder()->TopScope()->InsertBinding(ident->Name(), ident->Variable());
        if (is_builtin) {
            ident->Variable()->AddFlag(varbinder::VariableFlags::BUILTIN_TYPE);
        }
    }
}

void ScopesInitPhaseAS::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrow_expr)
{
    Iterate(arrow_expr);
}

void ScopesInitPhaseAS::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *export_decl)
{
    ExportDeclarationContext export_decl_ctx(VarBinder());
    Iterate(export_decl);
}

}  // namespace panda::es2panda::compiler
