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
    HandleFunction(scriptFunction);
}

void ScopesInitPhase::VisitBlockStatement(ir::BlockStatement *blockStmt)
{
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
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
    auto funcParamScope =
        HandleFunctionSig(function->TypeParams(), function->Params(), function->ReturnTypeAnnotation());
    auto paramCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>::Enter(VarBinder(), funcParamScope, false);

    auto functionCtx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
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
    BindScopeNode(scope, block);
    Iterate(block);
}

void ScopesInitPhase::VisitClassDefinition(ir::ClassDefinition *classDef)
{
    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    VarBinder()->AddDecl<varbinder::ConstDecl>(classDef->Start(), classDef->PrivateId());
    BindClassName(classDef);

    auto *classScope = classCtx.GetScope();
    BindScopeNode(classScope, classDef);
    Iterate(classDef);
}

void ScopesInitPhase::VisitForUpdateStatement(ir::ForUpdateStatement *forUpdateStmt)
{
    auto declCtx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(forUpdateStmt->Init());

    varbinder::LexicalScope<varbinder::LoopScope> lexicalScope(VarBinder());
    CallNode(forUpdateStmt->Test());
    CallNode(forUpdateStmt->Update());
    CallNode(forUpdateStmt->Body());
    lexicalScope.GetScope()->BindDecls(declCtx.GetScope());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forUpdateStmt);
}

void ScopesInitPhase::VisitForInStatement(ir::ForInStatement *forInStmt)
{
    auto declCtx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(forInStmt->Left());

    varbinder::LexicalScope<varbinder::LoopScope> lexicalScope(VarBinder());
    CallNode(forInStmt->Right());
    CallNode(forInStmt->Body());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forInStmt);
}
void ScopesInitPhase::VisitForOfStatement(ir::ForOfStatement *forOfStmt)
{
    auto declCtx = varbinder::LexicalScope<varbinder::LoopDeclarationScope>(VarBinder());
    CallNode(forOfStmt->Left());

    varbinder::LexicalScope<varbinder::LoopScope> lexicalScope(VarBinder());
    CallNode(forOfStmt->Right());
    CallNode(forOfStmt->Body());
    HandleFor(declCtx.GetScope(), lexicalScope.GetScope(), forOfStmt);
}

void ScopesInitPhase::VisitCatchClause(ir::CatchClause *catchClause)
{
    auto catchParamCtx = varbinder::LexicalScope<varbinder::CatchParamScope>(VarBinder());
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
    catchParamScope->BindNode(param);

    auto catchCtx = varbinder::LexicalScope<varbinder::CatchScope>(VarBinder());
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
        auto [decl, var] = AddVarDecl(varDecl->Flag(), varDecl->Start(), binding->Name());
        BindVarDecl(binding, init, decl, var);
    }
    Iterate(varDecl);
}

void ScopesInitPhase::VisitSwitchStatement(ir::SwitchStatement *switchStmt)
{
    CallNode(switchStmt->Discriminant());
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindScopeNode(localCtx.GetScope(), switchStmt);
    CallNode(switchStmt->Cases());
}

void ScopesInitPhase::VisitWhileStatement(ir::WhileStatement *whileStmt)
{
    CallNode(whileStmt->Test());
    varbinder::LexicalScope<varbinder::LoopScope> lexicalScope(VarBinder());
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
    varbinder::LexicalScope<varbinder::LoopScope> lexicalScope(VarBinder());
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
    auto *decl = VarBinder()->AddDecl<varbinder::ExportDecl>(exportAllDecl->Start(), name, "*");
    VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(exportAllDecl, decl);
}

void ScopesInitPhase::VisitImportNamespaceSpecifier(ir::ImportNamespaceSpecifier *importSpec)
{
    Iterate(importSpec);
    VarBinder()->AddDecl<varbinder::ImportDecl>(importSpec->Start(), "*", importSpec->Local()->Name(), importSpec);
}

void ScopesInitPhase::VisitImportSpecifier(ir::ImportSpecifier *importSpec)
{
    Iterate(importSpec);
    const auto *imported = importSpec->Imported();
    VarBinder()->AddDecl<varbinder::ImportDecl>(importSpec->Start(), imported->Name(), importSpec->Local()->Name(),
                                                importSpec);
}

void ScopesInitPhase::VisitImportDefaultSpecifier(ir::ImportDefaultSpecifier *importSpec)
{
    Iterate(importSpec);
    const auto *local = importSpec->Local();
    VarBinder()->AddDecl<varbinder::ImportDecl>(local->Start(), "default", local->Name(), importSpec);
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
            auto *decl = VarBinder()->AddDecl<varbinder::ExportDecl>(exportDecl->Start(), spec->Exported()->Name(),
                                                                     spec->Local()->Name(), spec);
            exportDecls.push_back(decl);
        }
        VarBinder()->GetScope()->AsModuleScope()->AddExportDecl(exportDecl, std::move(exportDecls));
    }
}

void ScopesInitPhase::VisitTSFunctionType(ir::TSFunctionType *funcType)
{
    varbinder::LexicalScope<varbinder::FunctionParamScope> lexicalScope(VarBinder());
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
    VarBinder()->AddDecl<varbinder::FunctionDecl>(func->Id()->Start(), Allocator(), func->Id()->Name(), func);
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

    auto identDecl = VarBinder()->AddDecl<varbinder::ConstDecl>(identNode->Start(), identNode->Name());
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
        VarBinder()->AddDecl<varbinder::ClassDecl>(locStart, className, classDef);
    } else {
        VarBinder()->AddDecl<varbinder::LetDecl>(locStart, className, classDef);
    }
}

std::tuple<varbinder::Decl *, varbinder::Variable *> ScopesInitPhase::AddVarDecl(ir::VariableDeclaratorFlag flag,
                                                                                 lexer::SourcePosition startLoc,
                                                                                 const util::StringView &name)
{
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
        auto *decl = VarBinder()->AddDecl<varbinder::VarDecl>(moduleDecl->Name()->Start(),
                                                              moduleDecl->Name()->AsIdentifier()->Name());
        decl->BindNode(moduleDecl);
    }
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindScopeNode(localCtx.GetScope(), moduleDecl);
    Iterate(moduleDecl);
}

void ScopeInitTyped::VisitTSModuleBlock(ir::TSModuleBlock *block)
{
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(block);
    BindScopeNode(localCtx.GetScope(), block);
}

void ScopeInitTyped::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAliasDecl)
{
    const auto id = typeAliasDecl->Id();
    varbinder::TSBinding tsBinding(Allocator(), id->Name());
    auto *decl = VarBinder()->AddTsDecl<varbinder::TypeAliasDecl>(id->Start(), tsBinding.View());
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
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
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(interfDecl->TypeParams());
    CallNode(interfDecl->Extends());

    auto localScope = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    auto *identDecl = VarBinder()->AddDecl<varbinder::ConstDecl>(ident->Start(), ident->Name());
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
    auto *decl = VarBinder()->AddDecl<varbinder::EnumDecl>(key->Start(), name);
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
        varbinder::LexicalScope enumCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
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
    auto decl = VarBinder()->AddDecl<varbinder::TypeParameterDecl>(typeParam->Start(), typeParam->Name()->Name());
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
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(classDef->TypeParams());

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindClassName(classDef);
    VarBinder()->AddDecl<varbinder::ConstDecl>(classDef->Start(), classDef->PrivateId());
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
    auto lexicalScope = HandleFunctionSig(constrType->TypeParams(), constrType->Params(), constrType->ReturnType());
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
    auto funcParamScope = HandleFunctionSig(constrT->TypeParams(), constrT->Params(), constrT->ReturnType());
    BindScopeNode(funcParamScope, constrT);
}

void InitScopesPhaseTs::VisitArrowFunctionExpression(ir::ArrowFunctionExpression *arrowFExpr)
{
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(arrowFExpr);
}

void InitScopesPhaseTs::VisitTSSignatureDeclaration(ir::TSSignatureDeclaration *signDecl)
{
    auto funcParamScope =
        HandleFunctionSig(signDecl->TypeParams(), signDecl->Params(), signDecl->ReturnTypeAnnotation());
    BindScopeNode(funcParamScope, signDecl);
}

void InitScopesPhaseTs::VisitTSMethodSignature(ir::TSMethodSignature *methodSign)
{
    auto funcParamScope =
        HandleFunctionSig(methodSign->TypeParams(), methodSign->Params(), methodSign->ReturnTypeAnnotation());
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
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    BindScopeNode(GetScope(), blockExpr);
    Iterate(blockExpr);
}

void InitScopesPhaseETS::VisitClassStaticBlock(ir::ClassStaticBlock *staticBlock)
{
    const auto func = staticBlock->Function();

    {
        auto funcParamCtx = varbinder::LexicalScope<varbinder::FunctionParamScope>(VarBinder());
        auto *funcParamScope = funcParamCtx.GetScope();
        auto funcCtx = varbinder::LexicalScope<varbinder::FunctionScope>(VarBinder());
        auto *funcScope = funcCtx.GetScope();

        func->Body()->AsBlockStatement()->SetScope(funcScope);
        BindScopeNode(funcScope, func);
        funcParamScope->BindNode(func);
        BindFunctionScopes(funcScope, funcParamScope);
        Iterate(func->Body()->AsBlockStatement());
    }

    auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
        VarBinder(), VarBinder()->GetScope()->AsClassScope()->StaticMethodScope());

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
    VarBinder()->AddDecl<varbinder::ImportDecl>(importSpec->Start(), importSpec->Local()->Name(),
                                                importSpec->Local()->Name(), importSpec);
    Iterate(importSpec);
}

//  Auxiliary method to avoid extra nested levels and too large function size
void AddOverload(ir::MethodDefinition *overload, varbinder::Variable *variable) noexcept
{
    auto *currentNode = variable->Declaration()->Node();
    currentNode->AsMethodDefinition()->AddOverload(overload);
    overload->Id()->SetVariable(variable);
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
        [[maybe_unused]] auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(
            methodName->Start(), Allocator(), methodName->Name(), method);
        var->SetScope(clsScope);
        var->AddFlag(varbinder::VariableFlags::METHOD);
        methodName->SetVariable(var);
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
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    varbinder::LexicalScope<varbinder::FunctionParamScope> lexicalScope(VarBinder());
    auto *funcParamScope = lexicalScope.GetScope();
    BindScopeNode(funcParamScope, funcType);
    Iterate(funcType);
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
        auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
        util::UString anonymousName(util::StringView("#"), Allocator());
        anonymousName.Append(std::to_string(parentClassScope->AsClassScope()->GetAndIncrementAnonymousClassIdx()));
        classDef->SetInternalName(anonymousName.View());
        classDef->Ident()->SetName(anonymousName.View());
        classDef->Ident()->SetReference();
        CallNode(classDef);
    }
}

void InitScopesPhaseETS::VisitTSTypeParameter(ir::TSTypeParameter *typeParam)
{
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
        auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
        CallNode(interfaceDecl->TypeParams());
        CallNode(interfaceDecl->Extends());
        auto localScope = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());
        CallNode(interfaceDecl->Body());
        BindScopeNode(localScope.GetScope(), interfaceDecl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(interfaceDecl->Id());
    auto *decl =
        VarBinder()->AddDecl<varbinder::InterfaceDecl>(interfaceDecl->Start(), Allocator(), name, interfaceDecl);
    decl->AsInterfaceDecl()->Add(interfaceDecl);
}

void InitScopesPhaseETS::VisitTSEnumDeclaration(ir::TSEnumDeclaration *enumDecl)
{
    {
        const auto enumCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
        BindScopeNode(enumCtx.GetScope(), enumDecl);
        Iterate(enumDecl);
    }
    auto name = FormInterfaceOrEnumDeclarationIdBinding(enumDecl->Key());
    auto *decl =
        VarBinder()->AddDecl<varbinder::EnumLiteralDecl>(enumDecl->Start(), name, enumDecl, enumDecl->IsConst());
    decl->BindScope(enumDecl->Scope());
}

void InitScopesPhaseETS::VisitTSTypeAliasDeclaration(ir::TSTypeAliasDeclaration *typeAlias)
{
    VarBinder()->AddDecl<varbinder::TypeAliasDecl>(typeAlias->Id()->Start(), typeAlias->Id()->Name(), typeAlias);
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    Iterate(typeAlias);
}

void InitScopesPhaseETS::AddGlobalToBinder(parser::Program *program)
{
    auto globalId = program->GlobalClass()->Ident();

    auto [decl2, var] = program->VarBinder()->NewVarDecl<varbinder::ClassDecl>(globalId->Start(), globalId->Name());

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(program->VarBinder());
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
    auto typeParamsCtx = varbinder::LexicalScope<varbinder::LocalScope>(VarBinder());
    CallNode(classDef->TypeParams());
    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(VarBinder());

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
    if (classProp->IsClassStaticBlock()) {
        ASSERT(curScope->IsClassScope());
        auto classCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(
            VarBinder(), curScope->AsClassScope()->StaticMethodScope());
        auto [_, var] = VarBinder()->NewVarDecl<varbinder::FunctionDecl>(classProp->Start(), Allocator(),
                                                                         classProp->Id()->Name(), classProp);
        (void)_;
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
        VarBinder()->AddDecl<varbinder::ConstDecl>(classProp->Key()->Start(), classProp->Key()->AsIdentifier()->Name(),
                                                   classProp);
    } else {
        VarBinder()->AddDecl<varbinder::LetDecl>(classProp->Key()->Start(), classProp->Key()->AsIdentifier()->Name(),
                                                 classProp);
    }
    Iterate(classProp);
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
