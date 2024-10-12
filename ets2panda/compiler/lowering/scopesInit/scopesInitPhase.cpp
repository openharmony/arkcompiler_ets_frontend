/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "util/errorHandler.h"
#include "scopesInitPhase.h"

namespace ark::es2panda::compiler {

template <typename T>
varbinder::LexicalScope<T> LexicalScopeCreateOrEnter(varbinder::VarBinder *varBinder, ir::AstNode *ast)
{
    if (ast != nullptr && ast->Scope() != nullptr) {
        return varbinder::LexicalScope<T>::Enter(varBinder, reinterpret_cast<T *>(ast->Scope()));
    }
    return varbinder::LexicalScope<T>(varBinder);
}

template <typename T, typename... Args>
T *AddOrGetDecl(varbinder::VarBinder *varBinder, util::StringView name, ir::AstNode *ast,
                const lexer::SourcePosition &pos, Args &&...args)
{
    if (auto *var = varBinder->GetScope()->FindLocal(name, varbinder::ResolveBindingOptions::BINDINGS);
        var != nullptr && var->Declaration() != nullptr && var->Declaration()->Node() == ast) {
        return reinterpret_cast<T *>(var->Declaration());
    }
    return varBinder->AddDecl<T>(pos, args...);
}

bool ScopesInitPhase::Perform(PhaseContext *ctx, parser::Program *program)
{
    Prepare(ctx, program);
    program->VarBinder()->InitTopScope();
    HandleBlockStmt(program->Ast(), GetScope());
    Finalize();
    return true;
}

void ScopesInitPhase::VisitScriptFunction(ir::ScriptFunction *scriptFunction)
{
    if (auto *const id = scriptFunction->Id(); id != nullptr && id->Variable() == nullptr) {
        auto const *const curScope = VarBinder()->GetScope();
        auto const &functionName = id->Name();
        auto const res =
            curScope->Find(functionName, scriptFunction->IsStatic() ? varbinder::ResolveBindingOptions::ALL_STATIC
                                                                    : varbinder::ResolveBindingOptions::ALL_NON_STATIC);
        if (res.variable != nullptr && res.variable->Declaration()->IsFunctionDecl()) {
            id->SetVariable(res.variable);
        }
    }

    HandleFunction(scriptFunction);
}

void ScopesInitPhase::VisitBlockStatement(ir::BlockStatement *blockStmt)
{
    auto localCtx = LexicalScopeCreateOrEnter<varbinder::LocalScopeWithTypeAlias>(VarBinder(), blockStmt);
    HandleBlockStmt(blockStmt, GetScope());
}

void ScopesInitPhase::VisitImportDeclaration(ir::ImportDeclaration *importDeclaration)
{
    ImportDeclarationContext importCtx(VarBinder());
    Iterate(importDeclaration);
    importCtx.BindImportDecl(importDeclaration);
}

void ScopesInitPhase::VisitClassStaticBlock(ir::ClassStaticBlock *staticBlock)
{
    Iterate(staticBlock);
}

void ScopesInitPhase::VisitMethodDefinition(ir::MethodDefinition *methodDefinition)
{
    Iterate(methodDefinition);
}

varbinder::FunctionParamScope *ScopesInitPhase::HandleFunctionSig(ir::TSTypeParameterDeclaration *typeParams,
                                                                  const ir::FunctionSignature::FunctionParams &params,
                                                                  ir::TypeNode *returnType)
{
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(typeParams);

    auto lexicalScope = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());
    CallFuncParams(params);
    CallNode(returnType);

    return lexicalScope.GetScope();
}

void ScopesInitPhase::HandleFunction(ir::ScriptFunction *function)
{
    CallNode(function->Id());
    // NOTE(gogabr): this will skip type/value parameters when they are added to an existing function sig
    auto funcParamScope = (function->Scope() == nullptr) ? HandleFunctionSig(function->TypeParams(), function->Params(),
                                                                             function->ReturnTypeAnnotation())
                                                         : function->Scope()->ParamScope();
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);

    auto functionCtx = LexicalScopeCreateOrEnter<varbinder::FunctionScope>(VarBinder(), function);
    auto *functionScope = functionCtx.GetScope();
    BindFunctionScopes(functionScope, funcParamScope);

    if (function->Body() != nullptr && function->Body()->IsBlockStatement()) {
        HandleBlockStmt(function->Body()->AsBlockStatement(), functionScope);
    } else {
        Iterate(function->Body());
    }
    BindScopeNode(functionScope, function);
    funcParamScope->BindNode(function);
}

void ScopesInitPhase::HandleBlockStmt(ir::BlockStatement *block, varbinder::Scope *scope)
{
    if (block->Scope() == nullptr) {
        BindScopeNode(scope, block);
    }
    Iterate(block);
}

void ScopesInitPhase::VisitClassDefinition(ir::ClassDefinition *classDef)
{
    auto classCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), classDef);
    AddOrGetDecl<varbinder::ConstDecl>(VarBinder(), classDef->PrivateId(), classDef, classDef->Start(),
                                       classDef->PrivateId());
    BindClassName(classDef);

    auto *classScope = classCtx.GetScope();
    BindScopeNode(classScope, classDef);
    Iterate(classDef);
}

void ScopesInitPhase::VisitForUpdateStatement(ir::ForUpdateStatement *forUpdateStmt)
{
    auto declCtx = (forUpdateStmt->Scope() == nullptr)
                       ? varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder())
                       : varbinder::LexicalScope<varbinder::LoopDeclarationScope>::Enter(
                             VarBinder(), forUpdateStmt->Scope()->DeclScope());
    CallNode(forUpdateStmt->Init());

    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::LoopScope>(VarBinder(), forUpdateStmt);
    AttachLabelToScope(forUpdateStmt);
    CallNode(forUpdateStmt->Test());
    CallNode(forUpdateStmt->Update());
    CallNode(forUpdateStmt->Body());
    lexicalScope.GetScope()->BindDecls(declCtx.GetScope());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forUpdateStmt);
}

void ScopesInitPhase::VisitForInStatement(ir::ForInStatement *forInStmt)
{
    auto declCtx = (forInStmt->Scope() == nullptr)
                       ? varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder())
                       : varbinder::LexicalScope<varbinder::LoopDeclarationScope>::Enter(
                             VarBinder(), forInStmt->Scope()->DeclScope());
    CallNode(forInStmt->Left());

    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::LoopScope>(VarBinder(), forInStmt);
    CallNode(forInStmt->Right());
    CallNode(forInStmt->Body());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forInStmt);
}
void ScopesInitPhase::VisitForOfStatement(ir::ForOfStatement *forOfStmt)
{
    auto declCtx = (forOfStmt->Scope() == nullptr)
                       ? varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder())
                       : varbinder::LexicalScope<varbinder::LoopDeclarationScope>::Enter(
                             VarBinder(), forOfStmt->Scope()->DeclScope());
    CallNode(forOfStmt->Left());

    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::LoopScope>(VarBinder(), forOfStmt);
    AttachLabelToScope(forOfStmt);
    CallNode(forOfStmt->Right());
    CallNode(forOfStmt->Body());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forOfStmt);
}

void ScopesInitPhase::VisitCatchClause(ir::CatchClause *catchClause)
{
    auto catchParamCtx = (catchClause->Scope() == nullptr)
                             ? varbinder::LexicalScope<varbinder::CatchParamScope>(VarBinder())
                             : varbinder::LexicalScope<varbinder::CatchParamScope>::Enter(
                                   VarBinder(), catchClause->Scope()->ParamScope());
    auto *catchParamScope = catchParamCtx.GetScope();
    auto *param = catchClause->Param();

    CallNode(param);

    if (param != nullptr) {
        auto [param_decl, var] = VarBinder()->AddParamDecl(param);
        (void)param_decl;
        if (param->IsIdentifier()) {
            var->SetScope(catchParamScope);
            param->AsIdentifier()->SetVariable(var);
        }
    }

    // Catch Clause is scope bearer
    catchParamScope->BindNode(catchClause);

    auto catchCtx = LexicalScopeCreateOrEnter<varbinder::CatchScope>(VarBinder(), catchClause);
    auto *catchScope = catchCtx.GetScope();

    catchScope->AssignParamScope(catchParamScope);
    auto body = catchClause->Body();
    HandleBlockStmt(body, catchScope);

    BindScopeNode(catchScope, catchClause);
}

void ScopesInitPhase::VisitVariableDeclarator(ir::VariableDeclarator *varDecl)
{
    auto init = varDecl->Id();
    std::vector<ir::Identifier *> bindings = util::Helpers::CollectBindingNames(init);
    for (auto *binding : bindings) {
        auto [decl, var] = AddOrGetVarDecl(varDecl->Flag(), varDecl->Start(), binding);
        BindVarDecl(binding, init, decl, var);
    }
    Iterate(varDecl);
}

void ScopesInitPhase::VisitSwitchStatement(ir::SwitchStatement *switchStmt)
{
    CallNode(switchStmt->Discriminant());
    auto localCtx = LexicalScopeCreateOrEnter<varbinder::LocalScopeWithTypeAlias>(VarBinder(), switchStmt);
    AttachLabelToScope(switchStmt);
    BindScopeNode(localCtx.GetScope(), switchStmt);
    CallNode(switchStmt->Cases());
}

void ScopesInitPhase::VisitWhileStatement(ir::WhileStatement *whileStmt)
{
    CallNode(whileStmt->Test());
    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::LoopScope>(VarBinder(), whileStmt);
    AttachLabelToScope(whileStmt);
    BindScopeNode(lexicalScope.GetScope(), whileStmt);
    CallNode(whileStmt->Body());
}

void ScopesInitPhase::VisitETSStructDeclaration(ir::ETSStructDeclaration *structDecl)
{
    Iterate(structDecl);
    BindClassDefinition(structDecl->Definition());
}

void ScopesInitPhase::VisitClassDeclaration(ir::ClassDeclaration *classDecl)
{
    Iterate(classDecl);
    BindClassDefinition(classDecl->Definition());
}

void ScopesInitPhase::VisitDoWhileStatement(ir::DoWhileStatement *doWhileStmt)
{
    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::LoopScope>(VarBinder(), doWhileStmt);
    AttachLabelToScope(doWhileStmt);
    BindScopeNode(lexicalScope.GetScope(), doWhileStmt);
    Iterate(doWhileStmt);
}

void ScopesInitPhase::VisitFunctionDeclaration(ir::FunctionDeclaration *funcDecl)
{
    const auto func = funcDecl->Function();
    if (!funcDecl->IsAnonymous()) {
        CreateFuncDecl(func);
    }
    Iterate(funcDecl);
}

void ScopesInitPhase::VisitExportAllDeclaration(ir::ExportAllDeclaration *exportAllDecl)
{
    Iterate(exportAllDecl);
    const auto name = exportAllDecl->Exported() != nullptr ? exportAllDecl->Exported()->Name() : "*";
    auto *decl =
        AddOrGetDecl<varbinder::ExportDecl>(VarBinder(), name, exportAllDecl, exportAllDecl->Start(), name, "*");
    VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(exportAllDecl, decl);
}

void ScopesInitPhase::VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *importSpec)
{
    Iterate(importSpec);
    AddOrGetDecl<varbinder::ImportDecl>(VarBinder(), importSpec->Local()->Name(), importSpec, importSpec->Start(), "*",
                                        importSpec->Local()->Name(), importSpec);
}

void ScopesInitPhase::VisitImportSpecifier(ir::ImportSpecifier *importSpec)
{
    Iterate(importSpec);
    const auto *imported = importSpec->Imported();
    AddOrGetDecl<varbinder::ImportDecl>(VarBinder(), importSpec->Local()->Name(), importSpec, importSpec->Start(),
                                        imported->Name(), importSpec->Local()->Name(), importSpec);
}

void ScopesInitPhase::VisitImportDefaultSpecifier(ir::ImportDefaultSpecifier *importSpec)
{
    Iterate(importSpec);
    const auto *local = importSpec->Local();
    AddOrGetDecl<varbinder::ImportDecl>(VarBinder(), local->Name(), importSpec, local->Start(), "default",
                                        local->Name(), importSpec);
}

void ScopesInitPhase::VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *exportDecl)
{
    ExportDeclarationContext exportDeclCtx(VarBinder());
    Iterate(exportDecl);
    exportDeclCtx.BindExportDecl(exportDecl);
}

void ScopesInitPhase::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrowExpr)
{
    Iterate(arrowExpr);
}

void ScopesInitPhase::VisitDirectEvalExpression(ir::DirectEvalExpression *directCallExpr)
{
    VarBinder()->PropagateDirectEval();
    Iterate(directCallExpr);
}

void ScopesInitPhase::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl)
{
    if (exportDecl->Decl() != nullptr) {
        ExportDeclarationContext exportDeclCtx(VarBinder());
        Iterate(exportDecl);
        exportDeclCtx.BindExportDecl(exportDecl);
    } else {
        varbinder::ModuleScope::ExportDeclList exportDecls(program_->Allocator()->Adapter());

        for (auto *spec : exportDecl->Specifiers()) {
            auto *decl =
                AddOrGetDecl<varbinder::ExportDecl>(VarBinder(), spec->Local()->Name(), spec, exportDecl->Start(),
                                                    spec->Exported()->Name(), spec->Local()->Name(), spec);
            exportDecls.push_back(decl);
        }
        VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(exportDecl, std::move(exportDecls));
    }
}

void ScopesInitPhase::VisitTSFunctionType(ir::TSFunctionType *funcType)
{
    auto lexicalScope = LexicalScopeCreateOrEnter<varbinder::FunctionParamScope>(VarBinder(), funcType);
    auto *funcParamScope = lexicalScope.GetScope();
    BindScopeNode(funcParamScope, funcType);
    Iterate(funcType);
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

void ScopesInitPhase::IterateNoTParams(ir::ClassDefinition *classDef)
{
    CallNode(classDef->Super());
    CallNode(classDef->SuperTypeParams());
    CallNode(classDef->Implements());
    CallNode(classDef->Ctor());
    CallNode(classDef->Body());
}

void ScopesInitPhase::ThrowSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const
{
    util::ErrorHandler::ThrowSyntaxError(Program(), errorMessage, pos);
}

void ScopesInitPhase::CreateFuncDecl(ir::ScriptFunction *func)
{
    AddOrGetDecl<varbinder::FunctionDecl>(VarBinder(), func->Id()->Name(), func, func->Id()->Start(), Allocator(),
                                          func->Id()->Name(), func);
}

util::StringView ScopesInitPhase::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    return id->Name();
}

varbinder::Decl *ScopesInitPhase::BindClassName(ir::ClassDefinition *classDef)
{
    const auto identNode = classDef->Ident();
    if (identNode == nullptr) {
        return nullptr;
    }

    auto identDecl = AddOrGetDecl<varbinder::ConstDecl>(VarBinder(), identNode->Name(), classDef, identNode->Start(),
                                                        identNode->Name());
    if (identDecl != nullptr) {
        identDecl->BindNode(classDef);
    }
    return identDecl;
}

void ScopesInitPhase::BindFunctionScopes(varbinder::FunctionScope *scope, varbinder::FunctionParamScope *paramScope)
{
    scope->BindParamScope(paramScope);
    paramScope->BindFunctionScope(scope);
}

void ScopesInitPhase::BindClassDefinition(ir::ClassDefinition *classDef)
{
    if (classDef->IsGlobal()) {
        return;  // We handle it in ClassDeclaration
    }
    const auto locStart = classDef->Ident()->Start();
    const auto &className = classDef->Ident()->Name();
    if ((classDef->Modifiers() & ir::ClassDefinitionModifiers::CLASS_DECL) != 0U) {
        AddOrGetDecl<varbinder::ClassDecl>(VarBinder(), className, classDef, locStart, className, classDef);
    } else {
        AddOrGetDecl<varbinder::LetDecl>(VarBinder(), className, classDef, locStart, className, classDef);
    }
}

std::tuple<varbinder::Decl *, varbinder::Variable *> ScopesInitPhase::AddOrGetVarDecl(ir::VariableDeclaratorFlag flag,
                                                                                      lexer::SourcePosition startLoc,
                                                                                      const ir::Identifier *id)
{
    if (auto var = id->Variable(); var != nullptr) {
        return {var->Declaration(), var};
    }
    auto name = id->Name();
    switch (flag) {
        case ir::VariableDeclaratorFlag::LET:
            return VarBinder()->NewVarDecl<varbinder::LetDecl>(startLoc, name);
        case ir::VariableDeclaratorFlag::VAR:
            return VarBinder()->NewVarDecl<varbinder::VarDecl>(startLoc, name);
        case ir::VariableDeclaratorFlag::CONST:
            return VarBinder()->NewVarDecl<varbinder::ConstDecl>(startLoc, name);
        default:
            UNREACHABLE();
    }
}

void ScopesInitPhase::BindVarDecl([[maybe_unused]] ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                                  [[maybe_unused]] varbinder::Variable *var)
{
    decl->BindNode(init);
}

void ScopesInitPhase::AttachLabelToScope([[maybe_unused]] ir::AstNode *node) {}

void ScopesInitPhase::VisitFunctionExpression(ir::FunctionExpression *funcExpr)
{
    Iterate(funcExpr);
    if (!funcExpr->IsAnonymous()) {
        auto func = funcExpr->Function();
        auto id = funcExpr->Id();
        auto *funcParamScope = func->Scope()->ParamScope();
        funcParamScope->BindName(Allocator(), id->Name());
        func->SetIdent(id->Clone(Allocator(), nullptr));
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

void ScopeInitTyped::VisitTSModuleDeclaration(ir::TSModuleDeclaration *moduleDecl)
{
    if (!moduleDecl->IsExternalOrAmbient()) {
        auto name = moduleDecl->Name()->AsIdentifier()->Name();
        auto *decl = AddOrGetDecl<varbinder::VarDecl>(VarBinder(), name, moduleDecl, moduleDecl->Name()->Start(), name);
        decl->BindNode(moduleDecl);
    }
    auto localCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), moduleDecl);
    BindScopeNode(localCtx.GetScope(), moduleDecl);
    Iterate(moduleDecl);
}

void ScopeInitTyped::VisitTSModuleBlock(ir::TSModuleBlock *block)
{
    auto localCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), block);
    Iterate(block);
    BindScopeNode(localCtx.GetScope(), block);
}

void ScopeInitTyped::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAliasDecl)
{
    const auto id = typeAliasDecl->Id();
    varbinder::TSBinding tsBinding(Allocator(), id->Name());
    auto *decl = VarBinder()->AddTsDecl<varbinder::TypeAliasDecl>(id->Start(), tsBinding.View());
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), typeAliasDecl->TypeParams());
    decl->BindNode(typeAliasDecl);
    Iterate(typeAliasDecl);
}

util::StringView ScopeInitTyped::FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id)
{
    varbinder::TSBinding tsBinding(Allocator(), id->Name());
    return tsBinding.View();
}

void ScopeInitTyped::VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interfDecl)
{
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    const auto ident = interfDecl->Id();
    const auto name = FormInterfaceOrEnumDeclarationIdBinding(ident);
    auto res = bindings.find(name);

    varbinder::InterfaceDecl *decl {};

    bool alreadyExists = false;
    if (res == bindings.end()) {
        decl = VarBinder()->AddTsDecl<varbinder::InterfaceDecl>(ident->Start(), Allocator(), name);
    } else if (!AllowInterfaceRedeclaration()) {
        ThrowSyntaxError("Interface redeclaration is not allowed", interfDecl->Start());
    } else if (!res->second->Declaration()->IsInterfaceDecl()) {
        VarBinder()->ThrowRedeclaration(ident->Start(), ident->Name());
    } else {
        decl = res->second->Declaration()->AsInterfaceDecl();
        alreadyExists = true;
    }

    CallNode(ident);
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), interfDecl->TypeParams());
    CallNode(interfDecl->TypeParams());
    CallNode(interfDecl->Extends());

    auto localScope = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), interfDecl);
    auto *identDecl =
        AddOrGetDecl<varbinder::ConstDecl>(VarBinder(), ident->Name(), interfDecl, ident->Start(), ident->Name());
    identDecl->BindNode(interfDecl);
    BindScopeNode(localScope.GetScope(), interfDecl);

    CallNode(interfDecl->Body());
    if (!alreadyExists) {
        decl->BindNode(interfDecl);
    }
    decl->Add(interfDecl);
}

void ScopeInitTyped::VisitTSEnumMember(ir::TSEnumMember *enumMember)
{
    const auto key = enumMember->Key();
    util::StringView name;
    if (key->IsIdentifier()) {
        name = key->AsIdentifier()->Name();
    } else if (key->IsStringLiteral()) {
        name = key->AsStringLiteral()->Str();
    } else {
        UNREACHABLE();
    }
    auto *decl = AddOrGetDecl<varbinder::EnumDecl>(VarBinder(), name, enumMember, key->Start(), name);
    decl->BindNode(enumMember);
}

void ScopeInitTyped::VisitTSEnumDeclaration(ir::TSEnumDeclaration *enumDecl)
{
    util::StringView ident = FormInterfaceOrEnumDeclarationIdBinding(enumDecl->Key());
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    auto res = bindings.find(ident);

    varbinder::EnumLiteralDecl *decl {};
    if (res == bindings.end()) {
        decl = VarBinder()->AddTsDecl<varbinder::EnumLiteralDecl>(enumDecl->Start(), ident, enumDecl->IsConst());
        varbinder::LexicalScope enumCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), enumDecl);
        decl->BindScope(enumCtx.GetScope());
        BindScopeNode(VarBinder()->GetScope()->AsLocalScope(), enumDecl);
    } else if (!res->second->Declaration()->IsEnumLiteralDecl() ||
               (enumDecl->IsConst() ^ res->second->Declaration()->AsEnumLiteralDecl()->IsConst()) != 0) {
        auto loc = enumDecl->Key()->End();
        loc.index++;
        VarBinder()->ThrowRedeclaration(loc, enumDecl->Key()->Name());
    } else {
        decl = res->second->Declaration()->AsEnumLiteralDecl();

        auto scopeCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), decl->Scope());
    }
    decl->BindNode(enumDecl);
    Iterate(enumDecl);
}

void ScopeInitTyped::VisitTSTypeParameter(ir::TSTypeParameter *typeParam)
{
    auto name = typeParam->Name()->Name();
    auto decl = AddOrGetDecl<varbinder::TypeParameterDecl>(VarBinder(), name, typeParam, typeParam->Start(), name);
    decl->BindNode(typeParam);
    Iterate(typeParam);
}

void ScopeInitTyped::VisitTSTypeParameterDeclaration(ir::TSTypeParameterDeclaration *paramDecl)
{
    BindScopeNode(VarBinder()->GetScope()->AsLocalScope(), paramDecl);
    Iterate(paramDecl);
}

void ScopeInitTyped::VisitClassDefinition(ir::ClassDefinition *classDef)
{
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), classDef->TypeParams());
    CallNode(classDef->TypeParams());

    auto classCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), classDef);
    BindClassName(classDef);
    AddOrGetDecl<varbinder::ConstDecl>(VarBinder(), classDef->PrivateId(), classDef, classDef->Start(),
                                       classDef->PrivateId());
    BindScopeNode(classCtx.GetScope(), classDef);
    IterateNoTParams(classDef);
}

void InitScopesPhaseTs::VisitExportDefaultDeclaration(ir::ExportDefaultDeclaration *exportDecl)
{
    ExportDeclarationContext exportDeclCtx(VarBinder());
    Iterate(exportDecl);
}

void InitScopesPhaseTs::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl)
{
    ExportDeclarationContext exportDeclCtx(VarBinder());
    Iterate(exportDecl);
}

void InitScopesPhaseTs::VisitImportDeclaration(ir::ImportDeclaration *importDeclaration)
{
    ImportDeclarationContext importCtx(VarBinder());
    Iterate(importDeclaration);
}

void InitScopesPhaseTs::VisitTSFunctionType(ir::TSFunctionType *constrType)
{
    auto lexicalScope =
        (constrType->Scope() == nullptr)
            ? HandleFunctionSig(constrType->TypeParams(), constrType->Params(), constrType->ReturnType())
            : constrType->Scope();
    BindScopeNode(lexicalScope, constrType);
}

void InitScopesPhaseTs::CreateFuncDecl(ir::ScriptFunction *func)
{
    const auto identNode = func->Id();
    const auto startLoc = identNode->Start();
    const auto &bindings = VarBinder()->GetScope()->Bindings();
    auto res = bindings.find(identNode->Name());
    varbinder::FunctionDecl *decl {};

    if (res == bindings.end()) {
        decl = VarBinder()->AddDecl<varbinder::FunctionDecl>(startLoc, Allocator(), identNode->Name(), func);
    } else {
        varbinder::Decl *currentDecl = res->second->Declaration();

        auto &existing = currentDecl->AsFunctionDecl()->Decls();
        if (std::find(existing.begin(), existing.end(), func) != existing.end()) {
            return;
        }

        if (!currentDecl->IsFunctionDecl() ||
            !currentDecl->AsFunctionDecl()->Node()->AsScriptFunction()->IsOverload()) {
            VarBinder()->ThrowRedeclaration(startLoc, currentDecl->Name());
        }
        decl = currentDecl->AsFunctionDecl();
    }

    decl->Add(func);
}

void InitScopesPhaseTs::VisitTSConstructorType(ir::TSConstructorType *constrT)
{
    auto funcParamScope = (constrT->Scope() == nullptr)
                              ? HandleFunctionSig(constrT->TypeParams(), constrT->Params(), constrT->ReturnType())
                              : constrT->Scope();
    BindScopeNode(funcParamScope, constrT);
}

void InitScopesPhaseTs::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrowFExpr)
{
    auto typeParamsCtx =
        LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), arrowFExpr->Function()->TypeParams());
    Iterate(arrowFExpr);
}

void InitScopesPhaseTs::VisitTSSignatureDeclaration(ir::TSSignatureDeclaration *signDecl)
{
    auto funcParamScope = (signDecl->Scope() == nullptr) ? HandleFunctionSig(signDecl->TypeParams(), signDecl->Params(),
                                                                             signDecl->ReturnTypeAnnotation())
                                                         : signDecl->Scope();
    BindScopeNode(funcParamScope, signDecl);
}

void InitScopesPhaseTs::VisitTSMethodSignature(ir::TSMethodSignature *methodSign)
{
    auto funcParamScope =
        (methodSign->Scope() == nullptr)
            ? HandleFunctionSig(methodSign->TypeParams(), methodSign->Params(), methodSign->ReturnTypeAnnotation())
            : methodSign->Scope();
    BindScopeNode(funcParamScope, methodSign);
}

void InitScopesPhaseETS::RunExternalNode(ir::AstNode *node, varbinder::VarBinder *varbinder)
{
    auto program = parser::Program(varbinder->Allocator(), varbinder);
    RunExternalNode(node, &program);
}

void InitScopesPhaseETS::RunExternalNode(ir::AstNode *node, parser::Program *ctx)
{
    auto scopesPhase = InitScopesPhaseETS();
    scopesPhase.SetProgram(ctx);
    scopesPhase.CallNode(node);
}

bool InitScopesPhaseETS::Perform(PhaseContext *ctx, parser::Program *program)
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

void InitScopesPhaseETS::HandleProgram(parser::Program *program)
{
    for (auto &[_, prog_list] : program->ExternalSources()) {
        (void)_;
        auto savedTopScope(program->VarBinder()->TopScope());
        auto mainProg = prog_list.front();
        mainProg->VarBinder()->InitTopScope();
        AddGlobalToBinder(mainProg);
        BindScopeNode(mainProg->VarBinder()->GetScope(), mainProg->Ast());
        auto globalClass = mainProg->GlobalClass();
        auto globalScope = mainProg->GlobalScope();
        for (auto &prog : prog_list) {
            prog->SetGlobalClass(globalClass);
            BindScopeNode(prog->VarBinder()->GetScope(), prog->Ast());
            prog->VarBinder()->ResetTopScope(globalScope);
            if (mainProg->Ast() != nullptr) {
                InitScopesPhaseETS().Perform(Context(), prog);
            }
        }
        program->VarBinder()->ResetTopScope(savedTopScope);
    }
    ASSERT(program->Ast() != nullptr);

    HandleETSScript(program->Ast());
}

void InitScopesPhaseETS::BindVarDecl(ir::Identifier *binding, ir::Expression *init, varbinder::Decl *decl,
                                     varbinder::Variable *var)
{
    binding->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::LOCAL);
    decl->BindNode(init);
}

void InitScopesPhaseETS::VisitBlockExpression(ir::BlockExpression *blockExpr)
{
    auto localCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), blockExpr);
    if (blockExpr->Scope() == nullptr) {
        BindScopeNode(GetScope(), blockExpr);
    }
    Iterate(blockExpr);
}

void InitScopesPhaseETS::VisitClassStaticBlock(ir::ClassStaticBlock *staticBlock)
{
    const auto func = staticBlock->Function();

    {
        auto funcParamCtx = (func->Scope() == nullptr)
                                ? varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder())
                                : varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(
                                      VarBinder(), func->Scope()->ParamScope());
        auto *funcParamScope = funcParamCtx.GetScope();
        auto funcCtx = LexicalScopeCreateOrEnter<varbinder::FunctionScope>(VarBinder(), func);
        auto *funcScope = funcCtx.GetScope();

        func->Body()->AsBlockStatement()->SetScope(funcScope);
        BindScopeNode(funcScope, func);
        funcParamScope->BindNode(func);
        BindFunctionScopes(funcScope, funcParamScope);
        Iterate(func->Body()->AsBlockStatement());
    }

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        VarBinder(), VarBinder()->GetScope()->AsClassScope()->StaticMethodScope());

    if (func->Id()->Variable() != nullptr) {
        return;
    }

    auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(staticBlock->Start(), Allocator(),
                                                                     func->Id()->Name(), staticBlock);
    (void)_;
    var->AddFlag(varbinder::VariableFlags::METHOD);
    func->Id()->SetVariable(var);
}

void InitScopesPhaseETS::VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *importSpec)
{
    if (importSpec->Local()->Name().Empty()) {
        return;
    }
    AddOrGetDecl<varbinder::ImportDecl>(VarBinder(), importSpec->Local()->Name(), importSpec, importSpec->Start(),
                                        importSpec->Local()->Name(), importSpec->Local()->Name(), importSpec);
    auto var =
        VarBinder()->GetScope()->FindLocal(importSpec->Local()->Name(), varbinder::ResolveBindingOptions::BINDINGS);
    importSpec->Local()->SetVariable(var);
    Iterate(importSpec);
}

void InitScopesPhaseETS::VisitImportSpecifier(ir::ImportSpecifier *importSpec)
{
    if (importSpec->Parent()->AsETSImportDeclaration()->IsPureDynamic()) {
        auto [decl, var] =
            VarBinder()->NewVarDecl<varbinder::LetDecl>(importSpec->Start(), importSpec->Local()->Name(), importSpec);
        var->AddFlag(varbinder::VariableFlags::INITIALIZED);
    }
    Iterate(importSpec);
}

//  Auxiliary method to avoid extra nested levels and too large function size
void AddOverload(ir::MethodDefinition *overload, varbinder::Variable *variable) noexcept
{
    auto *currentNode = variable->Declaration()->Node();
    currentNode->AsMethodDefinition()->AddOverload(overload);
    overload->Id()->SetVariable(variable);
    overload->SetParent(currentNode);
}

void InitScopesPhaseETS::DeclareClassMethod(ir::MethodDefinition *method)
{
    ASSERT(VarBinder()->GetScope()->IsClassScope());

    if ((method->AsMethodDefinition()->Function()->Flags() & ir::ScriptFunctionFlags::OVERLOAD) != 0) {
        return;
    }

    const auto methodName = method->Id();
    auto *const clsScope = VarBinder()->GetScope()->AsClassScope();
    auto options =
        method->IsStatic()
            ? varbinder::ResolveBindingOptions::STATIC_VARIABLES | varbinder::ResolveBindingOptions::STATIC_DECLARATION
            : varbinder::ResolveBindingOptions::VARIABLES | varbinder::ResolveBindingOptions::DECLARATION;
    if (clsScope->FindLocal(methodName->Name(), options) != nullptr) {
        VarBinder()->ThrowRedeclaration(methodName->Start(), methodName->Name());
    }

    varbinder::LocalScope *targetScope {};
    if (method->IsStatic() || method->IsConstructor()) {
        targetScope = clsScope->StaticMethodScope();
    } else {
        targetScope = clsScope->InstanceMethodScope();
    }
    auto *found = targetScope->FindLocal(methodName->Name(), varbinder::ResolveBindingOptions::BINDINGS);

    MaybeAddOverload(method, methodName, found, clsScope, targetScope);
}

void InitScopesPhaseETS::MaybeAddOverload(ir::MethodDefinition *method, ir::Identifier *methodName,
                                          varbinder::Variable *found, varbinder::ClassScope *clsScope,
                                          varbinder::LocalScope *targetScope)
{
    if (found == nullptr) {
        auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(VarBinder(), targetScope);

        auto *var = methodName->Variable();
        if (var == nullptr) {
            var = std::get<1>(VarBinder()->NewVarDecl<varbinder::FunctionDecl>(methodName->Start(), Allocator(),
                                                                               methodName->Name(), method));
            var->SetScope(clsScope);
            var->AddFlag(varbinder::VariableFlags::METHOD);
            methodName->SetVariable(var);
        }
        for (auto *overload : method->Overloads()) {
            ASSERT((overload->Function()->Flags() & ir::ScriptFunctionFlags::OVERLOAD));
            overload->Id()->SetVariable(var);
            overload->SetParent(var->Declaration()->Node());
        }
    } else {
        if (methodName->Name().Is(compiler::Signatures::MAIN) && clsScope->Parent()->IsGlobalScope()) {
            ThrowSyntaxError("Main overload is not enabled", methodName->Start());
        }
        AddOverload(method, found);
        method->Function()->AddFlag(ir::ScriptFunctionFlags::OVERLOAD);

        // default params overloads
        for (auto *overload : method->Overloads()) {
            ASSERT((overload->Function()->Flags() & ir::ScriptFunctionFlags::OVERLOAD));
            AddOverload(overload, found);
        }
        method->ClearOverloads();
    }
}

void InitScopesPhaseETS::VisitETSReExportDeclaration(ir::ETSReExportDeclaration *reExport)
{
    if (reExport->GetETSImportDeclarations()->Language().IsDynamic()) {
        VarBinder()->AsETSBinder()->AddDynamicImport(reExport->GetETSImportDeclarations());
    }
    VarBinder()->AsETSBinder()->AddReExportImport(reExport);
}

void InitScopesPhaseETS::VisitETSParameterExpression(ir::ETSParameterExpression *paramExpr)
{
    auto *const var = std::get<1>(VarBinder()->AddParamDecl(paramExpr));
    paramExpr->Ident()->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    Iterate(paramExpr);
}

void InitScopesPhaseETS::VisitETSImportDeclaration(ir::ETSImportDeclaration *importDecl)
{
    ImportDeclarationContext importCtx(VarBinder());
    if (importDecl->Language().IsDynamic()) {
        VarBinder()->AsETSBinder()->AddDynamicImport(importDecl);
    }
    Iterate(importDecl);
}

void InitScopesPhaseETS::VisitTSEnumMember(ir::TSEnumMember *enumMember)
{
    auto ident = enumMember->Key()->AsIdentifier();
    if (ident->Variable() != nullptr) {
        return;
    }
    auto [decl, var] = VarBinder()->NewVarDecl<varbinder::LetDecl>(ident->Start(), ident->Name());
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::STATIC);
    ident->SetVariable(var);
    decl->BindNode(enumMember);
    Iterate(enumMember);
}

void InitScopesPhaseETS::VisitMethodDefinition(ir::MethodDefinition *method)
{
    auto *curScope = VarBinder()->GetScope();
    const auto methodName = method->Id();
    auto res =
        curScope->Find(methodName->Name(), method->IsStatic() ? varbinder::ResolveBindingOptions::ALL_STATIC
                                                              : varbinder::ResolveBindingOptions::ALL_NON_STATIC);
    if (res.variable != nullptr && !res.variable->Declaration()->IsFunctionDecl() && res.scope == curScope) {
        VarBinder()->ThrowRedeclaration(methodName->Start(), res.name);
    }
    Iterate(method);
    DeclareClassMethod(method);
}

void InitScopesPhaseETS::VisitETSFunctionType(ir::ETSFunctionType *funcType)
{
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), funcType->TypeParams());

    // Check for existing scope
    // In some cases we can visit function again with scope that already exists
    // Example: async lambda, we "move" original function to another place and visit it again
    if (funcType->Scope() == nullptr) {
        varbinder::LexicalScope<varbinder::FunctionParamScope> lexicalScope(VarBinder());
        auto *funcParamScope = lexicalScope.GetScope();
        BindScopeNode(funcParamScope, funcType);
        Iterate(funcType);
    }
}

void InitScopesPhaseETS::VisitETSNewClassInstanceExpression(ir::ETSNewClassInstanceExpression *newClassExpr)
{
    CallNode(newClassExpr->GetArguments());
    CallNode(newClassExpr->GetTypeRef());
    if (newClassExpr->ClassDefinition() != nullptr) {
        const auto classDef = newClassExpr->ClassDefinition();
        auto *parentClassScope = VarBinder()->GetScope();
        while (!parentClassScope->IsClassScope()) {
            ASSERT(parentClassScope->Parent());
            parentClassScope = parentClassScope->Parent();
        }
        auto classCtx = LexicalScopeCreateOrEnter<varbinder::ClassScope>(VarBinder(), newClassExpr->ClassDefinition());
        util::UString anonymousName(util::StringView("#"), Allocator());
        anonymousName.Append(std::to_string(parentClassScope->AsClassScope()->GetAndIncrementAnonymousClassIdx()));
        classDef->SetInternalName(anonymousName.View());
        classDef->Ident()->SetName(anonymousName.View());
        CallNode(classDef);
    }
}

void InitScopesPhaseETS::VisitTSTypeParameter(ir::TSTypeParameter *typeParam)
{
    if (typeParam->Name()->Variable() != nullptr) {
        return;
    }
    auto [decl, var] =
        VarBinder()->NewVarDecl<varbinder::TypeParameterDecl>(typeParam->Name()->Start(), typeParam->Name()->Name());
    typeParam->Name()->SetVariable(var);
    var->SetScope(VarBinder()->GetScope());
    var->AddFlag(varbinder::VariableFlags::TYPE_PARAMETER);
    decl->BindNode(typeParam);
}

void InitScopesPhaseETS::VisitTSInterfaceDeclaration(ir::TSInterfaceDeclaration *interfaceDecl)
{
    {
        auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), interfaceDecl->TypeParams());
        CallNode(interfaceDecl->TypeParams());
        CallNode(interfaceDecl->Extends());
        auto localScope = LexicalScopeCreateOrEnter<varbinder::ClassScope>(VarBinder(), interfaceDecl);
        CallNode(interfaceDecl->Body());
        BindScopeNode(localScope.GetScope(), interfaceDecl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(interfaceDecl->Id());
    auto *decl = AddOrGetDecl<varbinder::InterfaceDecl>(VarBinder(), name, interfaceDecl, interfaceDecl->Start(),
                                                        Allocator(), name, interfaceDecl);
    decl->AsInterfaceDecl()->Add(interfaceDecl);
}

void InitScopesPhaseETS::VisitTSEnumDeclaration(ir::TSEnumDeclaration *enumDecl)
{
    {
        const auto enumCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), enumDecl);
        BindScopeNode(enumCtx.GetScope(), enumDecl);
        Iterate(enumDecl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(enumDecl->Key());
    auto *decl = AddOrGetDecl<varbinder::EnumLiteralDecl>(VarBinder(), name, enumDecl, enumDecl->Start(), name,
                                                          enumDecl, enumDecl->IsConst());
    decl->BindScope(enumDecl->Scope());
}

void InitScopesPhaseETS::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAlias)
{
    AddOrGetDecl<varbinder::TypeAliasDecl>(VarBinder(), typeAlias->Id()->Name(), typeAlias, typeAlias->Id()->Start(),
                                           typeAlias->Id()->Name(), typeAlias);
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), typeAlias->TypeParams());
    Iterate(typeAlias);
}

void InitScopesPhaseETS::AddGlobalToBinder(parser::Program *program)
{
    auto globalId = program->GlobalClass()->Ident();
    if (globalId->Variable() != nullptr) {
        return;
    }

    auto [decl2, var] = program->VarBinder()->NewVarDecl<varbinder::ClassDecl>(globalId->Start(), globalId->Name());

    auto classCtx = LexicalScopeCreateOrEnter<varbinder::ClassScope>(program->VarBinder(), program->GlobalClass());
    classCtx.GetScope()->BindNode(program->GlobalClass());
    program->GlobalClass()->SetScope(classCtx.GetScope());

    auto *classDecl = program->GlobalClass()->Parent();
    decl2->BindNode(classDecl);
    globalId->SetVariable(var);
}

void InitScopesPhaseETS::HandleETSScript(ir::BlockStatement *script)
{
    for (auto decl : script->Statements()) {
        if (decl->IsETSImportDeclaration()) {
            CallNode(decl);
        } else {
            auto classCtx =
                varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), Program()->GlobalClassScope());
            CallNode(decl);
        }
    }
    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>::Enter(VarBinder(), Program()->GlobalClassScope());

    for (auto decl : script->Statements()) {
        AddGlobalDeclaration(decl);
    }
}

void InitScopesPhaseETS::VisitClassDefinition(ir::ClassDefinition *classDef)
{
    if (classDef->IsGlobal()) {
        ParseGlobalClass(classDef);
        return;
    }
    auto typeParamsCtx = LexicalScopeCreateOrEnter<varbinder::LocalScope>(VarBinder(), classDef->TypeParams());
    CallNode(classDef->TypeParams());
    auto classCtx = LexicalScopeCreateOrEnter<varbinder::ClassScope>(VarBinder(), classDef);

    IterateNoTParams(classDef);
    FilterOverloads(classDef->Body());
    auto *classScope = classCtx.GetScope();
    BindScopeNode(classScope, classDef);
}

void InitScopesPhaseETS::VisitTSInterfaceBody(ir::TSInterfaceBody *interfBody)
{
    Iterate(interfBody);
    FilterInterfaceOverloads(interfBody->Body());
}

void InitScopesPhaseETS::FilterInterfaceOverloads(ArenaVector<ir::AstNode *, false> &props)
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

void InitScopesPhaseETS::FilterOverloads(ArenaVector<ir::AstNode *, false> &props)
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

void InitScopesPhaseETS::VisitClassProperty(ir::ClassProperty *classProp)
{
    auto curScope = VarBinder()->GetScope();
    const auto name = classProp->Key()->AsIdentifier()->Name();
    if (classProp->IsClassStaticBlock()) {
        ASSERT(curScope->IsClassScope());
        auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
            VarBinder(), curScope->AsClassScope()->StaticMethodScope());
        auto *var = classProp->Id()->Variable();
        if (var == nullptr) {
            var = std::get<1>(VarBinder()->NewVarDecl<varbinder::FunctionDecl>(classProp->Start(), Allocator(),
                                                                               classProp->Id()->Name(), classProp));
        }
        var->AddFlag(varbinder::VariableFlags::METHOD);
        classProp->AsClassStaticBlock()->Function()->Id()->SetVariable(var);
    } else if (classProp->IsConst()) {
        ASSERT(curScope->Parent() != nullptr);
        const auto initializer = classProp->Value();
        if (initializer == nullptr && curScope->Parent()->IsGlobalScope() && !classProp->IsDeclare()) {
            auto pos = classProp->End();
            // NOTE: Just use property Name?
            if (!classProp->TypeAnnotation()->IsETSPrimitiveType()) {
                pos.index--;
            }
            ThrowSyntaxError("Missing initializer in const declaration", pos);
        }
        AddOrGetDecl<varbinder::ConstDecl>(VarBinder(), name, classProp, classProp->Key()->Start(), name, classProp);
    } else if (classProp->IsReadonly()) {
        ASSERT(curScope->Parent() != nullptr);
        if (curScope->Parent()->IsGlobalScope() && !classProp->IsDeclare()) {
            auto pos = classProp->End();
            ThrowSyntaxError("Readonly field cannot be in Global scope", pos);
        }
        AddOrGetDecl<varbinder::ReadonlyDecl>(VarBinder(), name, classProp, classProp->Key()->Start(), name, classProp);
    } else {
        AddOrGetDecl<varbinder::LetDecl>(VarBinder(), name, classProp, classProp->Key()->Start(), name, classProp);
    }
    Iterate(classProp);
}

void InitScopesPhaseETS::VisitBreakStatement(ir::BreakStatement *stmt)
{
    auto label = stmt->Ident();
    if (label != nullptr) {
        auto scope = VarBinder()->GetScope();
        auto var = scope->FindInFunctionScope(label->Name(), varbinder::ResolveBindingOptions::ALL).variable;
        label->SetVariable(var);
    }
}

void InitScopesPhaseETS::VisitContinueStatement(ir::ContinueStatement *stmt)
{
    auto label = stmt->Ident();
    if (label != nullptr) {
        auto scope = VarBinder()->GetScope();
        auto var = scope->FindInFunctionScope(label->Name(), varbinder::ResolveBindingOptions::ALL).variable;
        label->SetVariable(var);
    }
}

void InitScopesPhaseETS::AttachLabelToScope(ir::AstNode *node)
{
    if (node->Parent() == nullptr) {
        return;
    }

    if (!node->Parent()->IsLabelledStatement()) {
        return;
    }

    auto stmt = node->Parent()->AsLabelledStatement();
    auto label = stmt->Ident();
    if (label == nullptr) {
        return;
    }

    auto decl = AddOrGetDecl<varbinder::LabelDecl>(VarBinder(), label->Name(), stmt, label->Start(), label->Name());
    decl->BindNode(stmt);

    auto var = VarBinder()->GetScope()->FindLocal(label->Name(), varbinder::ResolveBindingOptions::BINDINGS);
    if (var != nullptr) {
        label->SetVariable(var);
        var->SetScope(VarBinder()->GetScope());
        var->AddFlag(varbinder::VariableFlags::LOCAL);
    }
}

void InitScopesPhaseETS::ParseGlobalClass(ir::ClassDefinition *global)
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

void InitScopesPhaseETS::AddGlobalDeclaration(ir::AstNode *node)
{
    ir::Identifier *ident = nullptr;
    bool isBuiltin = false;
    switch (node->Type()) {
        case ir::AstNodeType::CLASS_DECLARATION: {
            auto def = node->AsClassDeclaration()->Definition();
            if (def->IsGlobal()) {
                return;
            }
            ident = def->Ident();
            isBuiltin = def->IsFromExternal();
            break;
        }
        case ir::AstNodeType::STRUCT_DECLARATION: {
            ident = node->AsETSStructDeclaration()->Definition()->Ident();
            isBuiltin = node->AsETSStructDeclaration()->Definition()->IsFromExternal();
            break;
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            ident = node->AsTSInterfaceDeclaration()->Id();
            isBuiltin = node->AsTSInterfaceDeclaration()->IsFromExternal();
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
        if (isBuiltin) {
            ident->Variable()->AddFlag(varbinder::VariableFlags::BUILTIN_TYPE);
        }
    }
}

void InitScopesPhaseAS::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrowExpr)
{
    Iterate(arrowExpr);
}

void InitScopesPhaseAS::VisitExportNamedDeclaration(ir::ExportNamedDeclaration *exportDecl)
{
    ExportDeclarationContext exportDeclCtx(VarBinder());
    Iterate(exportDecl);
}

}  // namespace ark::es2panda::compiler
