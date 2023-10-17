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

#include "binder.h"

#include "binder/privateBinding.h"
#include "parser/program/program.h"
#include "util/helpers.h"
#include "binder/scope.h"
#include "binder/tsBinding.h"
#include "compiler/core/compilerContext.h"
#include "es2panda.h"
#include "ir/astNode.h"
#include "ir/base/catchClause.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/forInStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/whileStatement.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/importDeclaration.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsConstructorType.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/base/tsMethodSignature.h"

namespace panda::es2panda::binder {
void Binder::InitTopScope()
{
    if (program_->Kind() == parser::ScriptKind::MODULE) {
        top_scope_ = Allocator()->New<ModuleScope>(Allocator());
    } else {
        top_scope_ = Allocator()->New<GlobalScope>(Allocator());
    }

    scope_ = top_scope_;
    var_scope_ = top_scope_;
}

std::tuple<ParameterDecl *, Variable *> Binder::AddParamDecl(ir::AstNode *param)
{
    ASSERT(scope_->IsFunctionParamScope() || scope_->IsCatchParamScope());
    auto [decl, node, var] = static_cast<ParamScope *>(scope_)->AddParamDecl(Allocator(), param);

    if (node == nullptr) {
        return {decl, var};
    }

    ThrowRedeclaration(node->Start(), decl->Name());
}

void Binder::ThrowRedeclaration(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Variable '" << name << "' has already been declared.";
    ThrowError(pos, ss.str());
}

void Binder::ThrowUnresolvableVariable(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Cannot find variable '" << name << "'.";
    ThrowError(pos, ss.str());
}

void Binder::ThrowUnresolvableType(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Cannot find type '" << name << "'.";
    ThrowError(pos, ss.str());
}

void Binder::ThrowTDZ(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Variable '" << name << "' is accessed before it's initialization.";
    ThrowError(pos, ss.str());
}

void Binder::ThrowInvalidCapture(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Cannot capture variable'" << name << "'.";
    ThrowError(pos, ss.str());
}

void Binder::ThrowPrivateFieldMismatch(const lexer::SourcePosition &pos, const util::StringView &name) const
{
    std::stringstream ss;
    ss << "Private field '" << name << "' must be declared in an enclosing class";

    ThrowError(pos, ss.str());
}

void Binder::ThrowError(const lexer::SourcePosition &pos, const std::string_view &msg) const
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error(ErrorType::SYNTAX, program_->SourceFile().Utf8(), msg, loc.line, loc.col);
}

void Binder::IdentifierAnalysis()
{
    ASSERT(program_->Ast());
    ASSERT(scope_ == top_scope_);
    ASSERT(var_scope_ == top_scope_);

    function_scopes_.push_back(top_scope_);
    top_scope_->BindName(MAIN);
    top_scope_->BindInternalName(BuildFunctionName(MAIN, 0));

    top_scope_->CheckDirectEval(compiler_ctx_);

    ResolveReferences(program_->Ast());
    AddMandatoryParams();
}

void Binder::LookupReference(const util::StringView &name)
{
    auto res = scope_->Find(name);
    if (res.level == 0) {
        return;
    }

    ASSERT(res.variable);
    res.variable->SetLexical(res.scope);
}

void Binder::InstantiateArguments()
{
    auto *iter = scope_;
    while (true) {
        Scope *scope = iter->IsFunctionParamScope() ? iter : iter->EnclosingVariableScope();

        const auto *node = scope->Node();

        if (scope->IsLoopScope()) {
            iter = scope->Parent();
            continue;
        }

        if (!node->IsScriptFunction()) {
            break;
        }

        if (!node->AsScriptFunction()->IsArrow()) {
            auto *arguments_variable =
                scope->AddDecl<ConstDecl, LocalVariable>(Allocator(), FUNCTION_ARGUMENTS, VariableFlags::INITIALIZED);

            if (iter->IsFunctionParamScope()) {
                if (arguments_variable == nullptr) {
                    break;
                }

                scope = iter->AsFunctionParamScope()->GetFunctionScope();
                scope->InsertBinding(arguments_variable->Name(), arguments_variable);
            }

            scope->AddFlag(ScopeFlags::USE_ARGS);

            break;
        }

        iter = scope->Parent();
    }
}

void Binder::PropagateDirectEval() const
{
    auto *iter = scope_;

    do {
        VariableScope *scope = iter->IsFunctionParamScope() ? iter->AsFunctionParamScope()->GetFunctionScope()
                                                            : iter->EnclosingVariableScope();

        scope->AddFlag(ScopeFlags::NO_REG_STORE);
        iter = iter->Parent();
    } while (iter != nullptr);
}

void Binder::InstantiatePrivateContext(const ir::Identifier *ident) const
{
    auto *class_def = util::Helpers::GetContainingClassDefinition(ident);

    while (class_def != nullptr) {
        auto *scope = class_def->Scope();
        Variable *variable = scope->FindLocal(class_def->PrivateId());

        if (!variable->HasFlag(VariableFlags::INITIALIZED)) {
            break;
        }

        if (class_def->HasMatchingPrivateKey(ident->Name())) {
            variable->SetLexical(scope);
            return;
        }

        class_def = util::Helpers::GetContainingClassDefinition(class_def->Parent());
    }

    ThrowPrivateFieldMismatch(ident->Start(), ident->Name());
}

void Binder::LookupIdentReference(ir::Identifier *ident)
{
    if (!ident->IsReference()) {
        return;
    }

    if (ident->Name().Is(FUNCTION_ARGUMENTS)) {
        InstantiateArguments();
    }

    if (ident->IsPrivateIdent()) {
        InstantiatePrivateContext(ident);
        return;
    }

    auto res = scope_->Find(ident->Name(), BindingOptions());
    if (res.level != 0) {
        ASSERT(res.variable);
        res.variable->SetLexical(res.scope);
    }

    if (res.variable == nullptr) {
        return;
    }

    if (res.variable->Declaration()->IsLetOrConstDecl() && !res.variable->HasFlag(VariableFlags::INITIALIZED)) {
        ident->SetTdz();
    }

    ident->SetVariable(res.variable);
}

util::StringView Binder::BuildFunctionName(util::StringView name, uint32_t idx)
{
    std::stringstream ss;
    ss << "func_" << name << "_" << std::to_string(idx);
    util::UString internal_name(ss.str(), Allocator());

    return internal_name.View();
}

bool Binder::BuildInternalName(ir::ScriptFunction *script_func)
{
    auto *func_scope = script_func->Scope();
    auto name = util::Helpers::FunctionName(Allocator(), script_func);

    uint32_t idx = function_scopes_.size();
    func_scope->BindName(name);
    func_scope->BindInternalName(BuildFunctionName(name, idx));

    return !script_func->IsOverload();
}

void Binder::BuildVarDeclaratorId(ir::AstNode *child_node)
{
    switch (child_node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto *ident = child_node->AsIdentifier();
            const auto &name = ident->Name();

            if (util::Helpers::IsGlobalIdentifier(name)) {
                break;
            }

            auto *variable = scope_->FindLocal(name);
            ident->SetVariable(variable);
            BuildSignatureDeclarationBaseParams(ident->TypeAnnotation());
            variable->AddFlag(VariableFlags::INITIALIZED);
            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            auto *obj_pattern = child_node->AsObjectPattern();

            for (auto *prop : obj_pattern->Properties()) {
                BuildVarDeclaratorId(prop);
            }

            BuildSignatureDeclarationBaseParams(obj_pattern->TypeAnnotation());
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            auto *array_pattern = child_node->AsArrayPattern();

            for (auto *element : child_node->AsArrayPattern()->Elements()) {
                BuildVarDeclaratorId(element);
            }

            BuildSignatureDeclarationBaseParams(array_pattern->TypeAnnotation());
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            ResolveReference(child_node->AsAssignmentPattern()->Right());
            BuildVarDeclaratorId(child_node->AsAssignmentPattern()->Left());
            break;
        }
        case ir::AstNodeType::PROPERTY: {
            ResolveReference(child_node->AsProperty()->Key());
            BuildVarDeclaratorId(child_node->AsProperty()->Value());
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            BuildVarDeclaratorId(child_node->AsRestElement()->Argument());
            break;
        }
        default:
            break;
    }
}

void Binder::BuildVarDeclarator(ir::VariableDeclarator *var_decl)
{
    if (var_decl->Parent()->AsVariableDeclaration()->Kind() == ir::VariableDeclaration::VariableDeclarationKind::VAR) {
        ResolveReferences(var_decl);
        return;
    }

    if (var_decl->Init() != nullptr) {
        ResolveReference(var_decl->Init());
    }

    BuildVarDeclaratorId(var_decl->Id());
}

void Binder::BuildClassProperty(const ir::ClassProperty *prop)
{
    const ir::ScriptFunction *ctor = util::Helpers::GetContainingConstructor(prop);
    auto scope_ctx = LexicalScope<FunctionScope>::Enter(this, ctor->Scope());

    ResolveReferences(prop);
}

void Binder::InitializeClassBinding(ir::ClassDefinition *class_def)
{
    auto res = scope_->Find(class_def->Ident()->Name());

    ASSERT(res.variable && res.variable->Declaration()->IsLetDecl());
    res.variable->AddFlag(VariableFlags::INITIALIZED);
}

void Binder::InitializeClassIdent(ir::ClassDefinition *class_def)
{
    auto res = scope_->Find(class_def->Ident()->Name());

    ASSERT(res.variable && res.variable->Declaration()->IsConstDecl());
    res.variable->AddFlag(VariableFlags::INITIALIZED);
}

void Binder::BuildClassDefinition(ir::ClassDefinition *class_def)
{
    if (class_def->Parent()->IsClassDeclaration() || class_def->Parent()->IsETSStructDeclaration()) {
        InitializeClassBinding(class_def);
    }

    auto scope_ctx = LexicalScope<LocalScope>::Enter(this, class_def->Scope());

    if (class_def->Super() != nullptr) {
        ResolveReference(class_def->Super());
    }

    Variable *variable = scope_->FindLocal(class_def->PrivateId());
    variable->AddFlag(VariableFlags::INITIALIZED);

    if (class_def->Ident() != nullptr) {
        InitializeClassIdent(class_def);
    }

    ResolveReference(class_def->Ctor());

    for (auto *stmt : class_def->Body()) {
        ResolveReference(stmt);
    }
}

void Binder::BuildForUpdateLoop(ir::ForUpdateStatement *for_update_stmt)
{
    auto *loop_scope = for_update_stmt->Scope();

    auto decl_scope_ctx = LexicalScope<LoopDeclarationScope>::Enter(this, loop_scope->DeclScope());

    if (for_update_stmt->Init() != nullptr) {
        ResolveReference(for_update_stmt->Init());
    }

    if (for_update_stmt->Update() != nullptr) {
        ResolveReference(for_update_stmt->Update());
    }

    auto loop_ctx = LexicalScope<LoopScope>::Enter(this, loop_scope);

    if (for_update_stmt->Test() != nullptr) {
        ResolveReference(for_update_stmt->Test());
    }

    ResolveReference(for_update_stmt->Body());

    loop_ctx.GetScope()->ConvertToVariableScope(Allocator());
}

void Binder::BuildForInOfLoop(binder::LoopScope *loop_scope, ir::AstNode *left, ir::Expression *right,
                              ir::Statement *body)
{
    auto decl_scope_ctx = LexicalScope<LoopDeclarationScope>::Enter(this, loop_scope->DeclScope());

    ResolveReference(right);
    ResolveReference(left);

    auto loop_ctx = LexicalScope<LoopScope>::Enter(this, loop_scope);

    ResolveReference(body);
    loop_ctx.GetScope()->ConvertToVariableScope(Allocator());
}

void Binder::BuildCatchClause(ir::CatchClause *catch_clause_stmt)
{
    if (catch_clause_stmt->Param() != nullptr) {
        auto param_scope_ctx = LexicalScope<CatchParamScope>::Enter(this, catch_clause_stmt->Scope()->ParamScope());
        ResolveReference(catch_clause_stmt->Param());
    }

    auto scope_ctx = LexicalScope<CatchScope>::Enter(this, catch_clause_stmt->Scope());
    ResolveReference(catch_clause_stmt->Body());
}

void Binder::AddCompilableFunction(ir::ScriptFunction *func)
{
    if (func->IsArrow()) {
        VariableScope *outer_var_scope = scope_->EnclosingVariableScope();
        outer_var_scope->AddFlag(ScopeFlags::INNER_ARROW);
    }

    AddCompilableFunctionScope(func->Scope());
}

void Binder::AddCompilableFunctionScope(binder::FunctionScope *func_scope)
{
    function_scopes_.push_back(func_scope);
}

void Binder::VisitScriptFunction(ir::ScriptFunction *func)
{
    auto *func_scope = func->Scope();

    {
        auto param_scope_ctx = LexicalScope<FunctionParamScope>::Enter(this, func_scope->ParamScope());

        for (auto *param : func->Params()) {
            ResolveReference(param);
        }
    }

    if (func->ReturnTypeAnnotation() != nullptr) {
        ResolveReference(func->ReturnTypeAnnotation());
    }

    if (!BuildInternalName(func)) {
        return;
    }

    AddCompilableFunction(func);

    auto scope_ctx = LexicalScope<FunctionScope>::Enter(this, func_scope);

    if (func->Body() != nullptr) {
        ResolveReference(func->Body());
    }
}

void Binder::VisitScriptFunctionWithPotentialTypeParams(ir::ScriptFunction *func)
{
    if (func->TypeParams() != nullptr) {
        auto type_param_scope_ctx = LexicalScope<Scope>::Enter(this, func->TypeParams()->Scope());
        VisitScriptFunction(func);
        return;
    }

    VisitScriptFunction(func);
}

void Binder::ResolveReference(ir::AstNode *child_node)
{
    switch (child_node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto *ident = child_node->AsIdentifier();

            LookupIdentReference(ident);
            ResolveReferences(child_node);
            break;
        }
        case ir::AstNodeType::SUPER_EXPRESSION: {
            VariableScope *var_scope = scope_->EnclosingVariableScope();
            var_scope->AddFlag(ScopeFlags::USE_SUPER);
            ResolveReferences(child_node);
            break;
        }
        case ir::AstNodeType::SCRIPT_FUNCTION: {
            VisitScriptFunctionWithPotentialTypeParams(child_node->AsScriptFunction());
            break;
        }
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            BuildVarDeclarator(child_node->AsVariableDeclarator());
            break;
        }
        case ir::AstNodeType::CLASS_DEFINITION: {
            BuildClassDefinition(child_node->AsClassDefinition());
            break;
        }
        case ir::AstNodeType::CLASS_PROPERTY: {
            BuildClassProperty(child_node->AsClassProperty());
            break;
        }
        case ir::AstNodeType::BLOCK_STATEMENT: {
            auto scope_ctx = LexicalScope<Scope>::Enter(this, child_node->AsBlockStatement()->Scope());

            ResolveReferences(child_node);
            break;
        }
        case ir::AstNodeType::SWITCH_STATEMENT: {
            auto scope_ctx = LexicalScope<LocalScope>::Enter(this, child_node->AsSwitchStatement()->Scope());

            ResolveReferences(child_node);
            break;
        }
        case ir::AstNodeType::DO_WHILE_STATEMENT: {
            auto *do_while_statement = child_node->AsDoWhileStatement();

            {
                auto loop_scope_ctx = LexicalScope<LoopScope>::Enter(this, do_while_statement->Scope());
                ResolveReference(do_while_statement->Body());
            }

            ResolveReference(do_while_statement->Test());
            break;
        }
        case ir::AstNodeType::WHILE_STATEMENT: {
            auto *while_statement = child_node->AsWhileStatement();
            ResolveReference(while_statement->Test());

            auto loop_scope_ctx = LexicalScope<LoopScope>::Enter(this, while_statement->Scope());
            ResolveReference(while_statement->Body());

            break;
        }
        case ir::AstNodeType::FOR_UPDATE_STATEMENT: {
            BuildForUpdateLoop(child_node->AsForUpdateStatement());
            break;
        }
        case ir::AstNodeType::FOR_IN_STATEMENT: {
            auto *for_in_stmt = child_node->AsForInStatement();
            BuildForInOfLoop(for_in_stmt->Scope(), for_in_stmt->Left(), for_in_stmt->Right(), for_in_stmt->Body());

            break;
        }
        case ir::AstNodeType::FOR_OF_STATEMENT: {
            auto *for_of_stmt = child_node->AsForOfStatement();
            BuildForInOfLoop(for_of_stmt->Scope(), for_of_stmt->Left(), for_of_stmt->Right(), for_of_stmt->Body());
            break;
        }
        case ir::AstNodeType::CATCH_CLAUSE: {
            BuildCatchClause(child_node->AsCatchClause());
            break;
        }
        default: {
            HandleCustomNodes(child_node);
            break;
        }
    }
}

void Binder::ResolveReferences(const ir::AstNode *parent)
{
    parent->Iterate([this](auto *child_node) { ResolveReference(child_node); });
}

LocalVariable *Binder::AddMandatoryParam(const std::string_view &name)
{
    ASSERT(scope_->IsFunctionParamScope());

    auto *decl = Allocator()->New<ParameterDecl>(name);
    auto *param = Allocator()->New<LocalVariable>(decl, VariableFlags::VAR);

    auto &func_params = scope_->AsFunctionParamScope()->Params();

    func_params.insert(func_params.begin(), param);
    scope_->AsFunctionParamScope()->GetFunctionScope()->InsertBinding(decl->Name(), param);
    scope_->InsertBinding(decl->Name(), param);

    return param;
}

void Binder::LookUpMandatoryReferences(const FunctionScope *func_scope, bool need_lexical_func_obj)
{
    LookupReference(MANDATORY_PARAM_NEW_TARGET);
    LookupReference(MANDATORY_PARAM_THIS);

    if (func_scope->HasFlag(ScopeFlags::USE_ARGS)) {
        LookupReference(FUNCTION_ARGUMENTS);
    }

    if (need_lexical_func_obj) {
        LookupReference(MANDATORY_PARAM_FUNC);
    }
}

void Binder::AddMandatoryParams()
{
    ASSERT(scope_ == top_scope_);
    ASSERT(!function_scopes_.empty());
    auto iter = function_scopes_.begin();
    [[maybe_unused]] auto *func_scope = *iter++;

    ASSERT(func_scope->IsGlobalScope() || func_scope->IsModuleScope());

    if (compiler_ctx_->IsDirectEval()) {
        AddMandatoryParams(EVAL_SCRIPT_MANDATORY_PARAMS);
        top_scope_->ParamScope()->Params().back()->SetLexical(top_scope_);
    } else {
        AddMandatoryParams(FUNCTION_MANDATORY_PARAMS);
    }

    if (compiler_ctx_->IsFunctionEval()) {
        ASSERT(iter != function_scopes_.end());
        func_scope = *iter++;
        auto scope_ctx = LexicalScope<FunctionScope>::Enter(this, func_scope);
        AddMandatoryParams(ARROW_MANDATORY_PARAMS);
        LookUpMandatoryReferences(func_scope, false);
    }

    for (; iter != function_scopes_.end(); iter++) {
        func_scope = *iter;
        const auto *script_func = func_scope->Node()->AsScriptFunction();

        auto scope_ctx = LexicalScope<FunctionScope>::Enter(this, func_scope);

        if (!script_func->IsArrow()) {
            AddMandatoryParams(FUNCTION_MANDATORY_PARAMS);
            continue;
        }

        const ir::ScriptFunction *ctor = util::Helpers::GetContainingConstructor(script_func);
        bool lexical_function_object {};

        if (ctor != nullptr && util::Helpers::GetClassDefiniton(ctor)->Super() != nullptr &&
            func_scope->HasFlag(ScopeFlags::USE_SUPER)) {
            ASSERT(ctor->Scope()->HasFlag(ScopeFlags::INNER_ARROW));
            ctor->Scope()->AddFlag(ScopeFlags::SET_LEXICAL_FUNCTION);
            lexical_function_object = true;
            AddMandatoryParams(CTOR_ARROW_MANDATORY_PARAMS);
        } else {
            AddMandatoryParams(ARROW_MANDATORY_PARAMS);
        }

        LookUpMandatoryReferences(func_scope, lexical_function_object);
    }
}
}  // namespace panda::es2panda::binder
