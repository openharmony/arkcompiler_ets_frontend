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

#include "ASTVerifier.h"

#include "checker/types/typeFlag.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/module/importSpecifier.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/forInStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "lexer/token/tokenType.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "varbinder/scope.h"

#include <algorithm>
#include <iterator>

namespace panda::es2panda::compiler {

template <typename Func>
ASTVerifier::CheckFunction RecursiveCheck(const Func &func)
{
    return [func](const ir::AstNode *ast) -> bool {
        bool has_parent = func(ast);
        ast->IterateRecursively([func, &has_parent](ir::AstNode *child) { has_parent &= func(child); });
        return has_parent;
    };
}

static bool IsNumericType(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (!ast->IsTyped()) {
        return false;
    }

    auto typed_ast = static_cast<const ir::TypedAstNode *>(ast);

    if (typed_ast->TsType() == nullptr) {
        return false;
    }

    return typed_ast->TsType()->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) ||
           typed_ast->TsType()->HasTypeFlag(checker::TypeFlag::NUMBER_LITERAL) ||
           typed_ast->TsType()->HasTypeFlag(checker::TypeFlag::BIGINT_LITERAL);
}

static bool IsStringType(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (!ast->IsTyped()) {
        return false;
    }

    auto typed_ast = static_cast<const ir::TypedAstNode *>(ast);

    if (typed_ast->TsType() == nullptr) {
        return false;
    }

    return typed_ast->TsType()->HasTypeFlag(checker::TypeFlag::STRING_LIKE);
}

template <typename T>
bool IsContainedIn(const T *child, const T *parent)
{
    if (child == nullptr || parent == nullptr) {
        return false;
    }

    std::unordered_set<const T *> saved_nodes;
    while (child != nullptr && child != parent) {
        if (saved_nodes.find(child) != saved_nodes.end()) {
            return false;
        }
        child = child->Parent();
        saved_nodes.emplace(child);
    }
    return child == parent;
}

bool ValidateVariableAccess(const varbinder::LocalVariable *prop_var, const ir::MemberExpression *ast)
{
    const auto *decl = prop_var->Declaration();
    if (decl == nullptr) {
        return false;
    }
    const auto *node = decl->Node();
    if (node == nullptr) {
        return false;
    }
    auto *obj_type = ast->ObjType();
    if (obj_type == nullptr) {
        return false;
    }
    const auto *obj_type_decl_node = obj_type->GetDeclNode();
    if (obj_type_decl_node == nullptr) {
        return false;
    }
    const auto *parent_node = node->Parent();
    if (parent_node != nullptr && parent_node->IsClassDefinition() && obj_type_decl_node->IsClassDefinition()) {
        if (IsContainedIn<const ir::AstNode>(ast, obj_type_decl_node->AsClassDefinition())) {
            return true;
        }
        if (node->IsPrivate() && parent_node == obj_type_decl_node) {
            return true;
        }
        if (node->IsProtected()) {
            auto ret = obj_type->IsPropertyInherited(prop_var);
            return ret;
        }
    }
    return false;
}

bool ValidateMethodAccess(const ir::MemberExpression *member_expression, const ir::CallExpression *ast)
{
    auto *obj_type = member_expression->ObjType();
    if (obj_type == nullptr) {
        return false;
    }

    if (obj_type->HasObjectFlag(checker::ETSObjectFlags::RESOLVED_SUPER) && obj_type->SuperType() != nullptr &&
        obj_type->SuperType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_TYPE |
                                             checker::ETSObjectFlags::GLOBAL_CLASS)) {
        return true;
    }
    const auto *decl_node = obj_type->GetDeclNode();
    if (decl_node == nullptr) {
        return false;
    }
    auto *signature = ast->Signature();
    if (signature == nullptr) {
        return false;
    }
    auto *owner_sign = signature->Owner();
    if (owner_sign == nullptr) {
        return false;
    }
    auto *decl_node_sign = owner_sign->GetDeclNode();
    if (decl_node_sign != nullptr && decl_node_sign->IsClassDefinition() && decl_node->IsClassDefinition()) {
        if (IsContainedIn<const ir::AstNode>(ast, decl_node->AsClassDefinition())) {
            return true;
        }
        if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE) && decl_node_sign == decl_node) {
            return true;
        }
        if (signature->HasSignatureFlag(checker::SignatureFlags::PROTECTED)) {
            auto ret = obj_type->IsSignatureInherited(signature);
            return ret;
        }
    }
    return false;
}

bool ValidateExport(const varbinder::Variable *var)
{
    const auto *decl = var->Declaration();
    if (decl == nullptr) {
        return false;
    }
    const auto *node = decl->Node();
    if (node == nullptr) {
        return false;
    }
    return node->IsExported();
}

std::string ToStringHelper(const varbinder::ScopeType type)
{
    switch (type) {
        case varbinder::ScopeType::CATCH: {
            return "CATCH";
        }
        case varbinder::ScopeType::CATCH_PARAM: {
            return "CATCH_PARAM";
        }
        case varbinder::ScopeType::CLASS: {
            return "CLASS";
        }
        case varbinder::ScopeType::FUNCTION: {
            return "FUNCTION";
        }
        case varbinder::ScopeType::FUNCTION_PARAM: {
            return "FUNCTION_PARAM";
        }
        case varbinder::ScopeType::GLOBAL: {
            return "GLOBAL";
        }
        case varbinder::ScopeType::LOCAL: {
            return "LOCAL";
        }
        case varbinder::ScopeType::LOOP: {
            return "LOOP";
        }
        case varbinder::ScopeType::LOOP_DECL: {
            return "LOOP_DECL";
        }
        case varbinder::ScopeType::MODULE: {
            return "MODULE";
        }
        case varbinder::ScopeType::PARAM: {
            return "PARAM";
        }
        default: {
            return "MUST BE UNREACHABLE";
        }
    }
}

std::string ToStringHelper(const util::StringView &name)
{
    return name == nullptr ? "<null>" : name.Mutf8();
}

std::string ToStringHelper(const varbinder::Scope *scope)
{
    if (scope == nullptr) {
        return "<null>";
    }

    switch (scope->Type()) {
        case varbinder::ScopeType::FUNCTION: {
            return "FUNC_SCOPE " + ToStringHelper(scope->AsFunctionScope()->Name());
        }
        case varbinder::ScopeType::LOCAL: {
            return "LOCAL_SCOPE ";
        }
        case varbinder::ScopeType::CATCH: {
            return "CATCH_SCOPE ";
        }
        default: {
            return "MUST BE UNREACHABLE";
        }
    }
}

std::string ToStringHelper(const varbinder::Variable *var)
{
    if (var == nullptr) {
        return "<null>";
    }

    switch (var->Type()) {
        case varbinder::VariableType::LOCAL: {
            return "LOCAL_VAR " + ToStringHelper(var->Name());
        }
        case varbinder::VariableType::MODULE: {
            return "MODULE_VAR " + ToStringHelper(var->Name());
        }
        case varbinder::VariableType::GLOBAL: {
            return "GLOBAL_VAR " + ToStringHelper(var->Name());
        }
        case varbinder::VariableType::ENUM: {
            return "ENUM_VAR " + ToStringHelper(var->Name());
        }
        default: {
            return "MUST BE UNREACHABLE";
        }
    }
}

template <typename T>
std::string ToStringParamsHelper(const ir::AstNode *parent, const ArenaVector<T *> &params)
{
    std::string name;
    if (parent != nullptr) {
        name = ToStringHelper(parent) + " ";
    }

    name += "(";
    for (auto const *param : params) {
        name += ToStringHelper(param);
    }

    return name + ")";
}

std::string ToStringHelper(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return "<null>";
    }

    switch (ast->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            return "ID " + ToStringHelper(ast->AsIdentifier()->Name());
        }
        case ir::AstNodeType::CLASS_DEFINITION: {
            return "CLS_DEF " + ToStringHelper(ast->AsClassDefinition()->Ident());
        }
        case ir::AstNodeType::CLASS_DECLARATION: {
            return "CLS_DECL " + ToStringHelper(ast->AsClassDeclaration()->Definition());
        }
        case ir::AstNodeType::BLOCK_STATEMENT: {
            return "BLOCK " + ToStringHelper(ast->AsBlockStatement()->Scope());
        }
        case ir::AstNodeType::SCRIPT_FUNCTION: {
            auto const *sf = ast->AsScriptFunction();
            return "SCRIPT_FUN " + ToStringHelper(sf->Scope()) + "::" + ToStringHelper(sf->Id());
        }
        case ir::AstNodeType::FUNCTION_EXPRESSION: {
            return "FUN_EXPR " + ToStringHelper(ast->AsFunctionExpression()->Function());
        }
        case ir::AstNodeType::METHOD_DEFINITION: {
            return "METHOD_DEF " + ToStringHelper(ast->AsMethodDefinition()->Value());
        }
        case ir::AstNodeType::ETS_TYPE_REFERENCE_PART: {
            return "TYPE_REF_PART " + ToStringHelper(ast->AsETSTypeReferencePart()->Name());
        }
        case ir::AstNodeType::ETS_TYPE_REFERENCE: {
            return "TYPE_REF " + ToStringHelper(ast->AsETSTypeReference()->Part());
        }
        case ir::AstNodeType::VARIABLE_DECLARATOR: {
            return "VAR_DECLARATOR " + ToStringHelper(ast->AsVariableDeclarator()->Id());
        }
        case ir::AstNodeType::VARIABLE_DECLARATION: {
            if (ast->AsVariableDeclaration()->Declarators().empty()) {
                return "VAR_DECLARATION <null>";
            }
            return "VAR_DECLARATION " + ToStringHelper(ast->AsVariableDeclaration()->Declarators().at(0));
        }
        case ir::AstNodeType::CALL_EXPRESSION: {
            return "CALL_EXPR " + ToStringHelper(ast->AsCallExpression()->Callee()) + "(...)";
        }
        case ir::AstNodeType::EXPRESSION_STATEMENT: {
            return "EXPR_STMT " + ToStringHelper(ast->AsExpressionStatement()->GetExpression());
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            auto const *me = ast->AsMemberExpression();
            return "MEMBER_EXPR " + ToStringHelper(me->Object()) + "." + ToStringHelper(me->Property());
        }
        case ir::AstNodeType::CLASS_STATIC_BLOCK: {
            return "CLS_STATIC_BLOCK " + ToStringHelper(ast->AsClassStaticBlock()->Function());
        }
        case ir::AstNodeType::ETS_PACKAGE_DECLARATION: {
            return "PKG_DECL ";
        }
        case ir::AstNodeType::TS_TYPE_PARAMETER_DECLARATION: {
            auto params = ast->AsTSTypeParameterDeclaration()->Params();
            return "PARAM_DECL " + ToStringParamsHelper<ir::TSTypeParameter>(ast->Parent(), params);
        }
        case ir::AstNodeType::TS_TYPE_PARAMETER: {
            return "TYPE_PARAM " + ToStringHelper(ast->AsTSTypeParameter()->Name());
        }
        case ir::AstNodeType::TS_TYPE_PARAMETER_INSTANTIATION: {
            return "PARAM_INSTANTIATION " +
                   ToStringParamsHelper<ir::TypeNode>(ast->Parent(), ast->AsTSTypeParameterInstantiation()->Params());
        }
        case ir::AstNodeType::THROW_STATEMENT: {
            return "THROW_STMT " + ToStringHelper(ast->AsThrowStatement()->Argument());
        }
        case ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION: {
            return "NEW_CLS_INSTANCE " + ToStringHelper(ast->AsETSNewClassInstanceExpression()->GetTypeRef());
        }
        case ir::AstNodeType::STRING_LITERAL: {
            return "STR_LITERAL " + ToStringHelper(ast->AsStringLiteral()->Str());
        }
        case ir::AstNodeType::TRY_STATEMENT: {
            return "TRY_STMT " + ToStringHelper(ast->AsTryStatement()->Block());
        }
        case ir::AstNodeType::CATCH_CLAUSE: {
            return "CATCH_CLAUSE ";
        }
        case ir::AstNodeType::NUMBER_LITERAL: {
            return "NUMBER_LITERAL " + ToStringHelper(ast->AsNumberLiteral()->Str());
        }
        case ir::AstNodeType::ETS_PARAMETER_EXPRESSION: {
            return "ETS_PARAM_EXPR " + ToStringHelper(ast->AsETSParameterExpression()->Ident());
        }
        case ir::AstNodeType::TS_INTERFACE_DECLARATION: {
            return "TS_INTERFACE_DECL " + ToStringHelper(ast->AsTSInterfaceDeclaration()->Id());
        }
        case ir::AstNodeType::TS_INTERFACE_BODY: {
            return "TS_INTERFACE_BODY ";
        }
        case ir::AstNodeType::ETS_FUNCTION_TYPE: {
            return "ETS_FUNC_TYPE " +
                   ToStringParamsHelper<ir::Expression>(ast->Parent(), ast->AsETSFunctionType()->Params());
        }
        case ir::AstNodeType::TS_CLASS_IMPLEMENTS: {
            return "TS_CLASS_IMPL " + ToStringHelper(ast->AsTSClassImplements()->Expr());
        }
        default: {
            return "MUST BE UNREACHABLE";
        }
    }
}

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define ADD_CHECK(Name)                                                                        \
    {                                                                                          \
        const auto check = [this](const ir::AstNode *ast) -> bool { return this->Name(ast); }; \
        checks_.emplace_back(NamedCheck {#Name, check});                                       \
        all_checks_.insert(#Name);                                                             \
        checks_.emplace_back(NamedCheck {#Name "Recursive", RecursiveCheck(check)});           \
        all_checks_.insert(#Name "Recursive");                                                 \
    }
// NOLINTEND(cppcoreguidelines-macro-usage)

bool ASTVerifier::HasParent(const ir::AstNode *ast)
{
    if (ast != nullptr && !ast->IsETSScript() && ast->Parent() == nullptr) {
        AddError("NULL_PARENT: " + ToStringHelper(ast), ast->Start());
        return false;
    }

    return true;
}

bool ASTVerifier::HasType(const ir::AstNode *ast)
{
    if (ast->IsTyped() && static_cast<const ir::TypedAstNode *>(ast)->TsType() == nullptr) {
        AddError("NULL_TS_TYPE: " + ToStringHelper(ast), ast->Start());
        return false;
    }
    return true;
}

bool ASTVerifier::HasVariable(const ir::AstNode *ast)
{
    if (!ast->IsIdentifier() || ast->AsIdentifier()->Variable() != nullptr) {
        return true;
    }

    const auto *id = ast->AsIdentifier();
    AddError("NULL_VARIABLE: " + ToStringHelper(id), id->Start());
    return false;
}

bool ASTVerifier::HasScope(const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        return true;  // we will check only Identifier
    }

    // we will check only local variables of identifiers
    if (const auto maybe_var = GetLocalScopeVariable(ast)) {
        const auto var = *maybe_var;
        const auto scope = var->GetScope();
        if (scope == nullptr) {
            AddError("NULL_SCOPE_LOCAL_VAR: " + ToStringHelper(ast), ast->Start());
            return false;
        }
        return ScopeEncloseVariable(var);
    }
    return true;
}

std::optional<varbinder::LocalVariable *> ASTVerifier::GetLocalScopeVariable(const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        return std::nullopt;
    }

    const auto variable = ast->AsIdentifier()->Variable();
    if (HasVariable(ast) && variable->IsLocalVariable()) {
        const auto local_var = variable->AsLocalVariable();
        if (local_var->HasFlag(varbinder::VariableFlags::LOCAL)) {
            return local_var;
        }
    }
    return std::nullopt;
}

bool ASTVerifier::VerifyChildNode(const ir::AstNode *ast)
{
    ASSERT(ast);
    bool is_ok;
    ast->Iterate([&](const auto node) {
        if (ast != node->Parent()) {
            AddError("INCORRECT_PARENT_REF: " + ToStringHelper(node), node->Start());
            is_ok = false;
        }
    });
    return is_ok;
}

bool ASTVerifier::VerifyScopeNode(const ir::AstNode *ast)
{
    ASSERT(ast);
    const auto maybe_var = GetLocalScopeVariable(ast);
    if (!maybe_var) {
        return true;
    }
    const auto var = *maybe_var;
    const auto scope = var->GetScope();
    if (scope == nullptr) {
        // already checked
        return false;
    }
    const auto enclose_scope = scope->EnclosingVariableScope();
    if (enclose_scope == nullptr) {
        AddError("NO_ENCLOSING_VAR_SCOPE: " + ToStringHelper(ast), ast->Start());
        return false;
    }
    const auto node = scope->Node();
    bool is_ok = true;
    if (!IsContainedIn(ast, node)) {
        is_ok = false;
        AddError("VARIABLE_NOT_ENCLOSE_SCOPE: " + ToStringHelper(ast), ast->Start());
    }
    if (!IsContainedIn<varbinder::Scope>(scope, enclose_scope)) {
        is_ok = false;
        AddError("VARIABLE_NOT_ENCLOSE_SCOPE: " + ToStringHelper(ast), ast->Start());
    }
    return is_ok;
}

bool ASTVerifier::ScopeEncloseVariable(const varbinder::LocalVariable *var)
{
    ASSERT(var);

    const auto scope = var->GetScope();
    if (scope == nullptr || var->Declaration() == nullptr) {
        return true;
    }
    const auto node = var->Declaration()->Node();
    if (node == nullptr) {
        return true;
    }
    const auto var_start = node->Start();
    bool is_ok = true;
    if (scope->Bindings().count(var->Name()) == 0) {
        AddError("SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR: " + ToStringHelper(node), var_start);
        is_ok = false;
    }
    const auto scope_node = scope->Node();
    auto var_node = node;
    if (!IsContainedIn(var_node, scope_node) || scope_node == nullptr) {
        AddError("SCOPE_NODE_DONT_DOMINATE_VAR_NODE: " + ToStringHelper(node), var_start);
        is_ok = false;
    }
    const auto &decls = scope->Decls();
    const auto decl_dominate = std::count(decls.begin(), decls.end(), var->Declaration());
    if (decl_dominate == 0) {
        AddError("SCOPE_DECL_DONT_DOMINATE_VAR_DECL: " + ToStringHelper(node), var_start);
        is_ok = false;
    }
    return is_ok;
}

bool ASTVerifier::CheckArithmeticExpression(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->IsArithmetic()) {
        if (ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS &&
            IsStringType(ast->AsBinaryExpression()->Left()) && IsStringType(ast->AsBinaryExpression()->Right())) {
            return true;
        }
        bool is_correct = true;
        ast->Iterate([&is_correct](ir::AstNode *child) { is_correct &= (IsNumericType(child)); });
        return is_correct;
    }

    return true;
}

bool ASTVerifier::IsForLoopCorrectInitialized(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (ast->IsForInStatement()) {
        auto const *left = ast->AsForInStatement()->Left();
        if (left == nullptr) {
            AddError("NULL FOR-IN-LEFT: " + ToStringHelper(ast), ast->Start());
            return false;
        }

        if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
            AddError("INCORRECT FOR-IN-LEFT: " + ToStringHelper(ast), ast->Start());
            return false;
        }
    }

    if (ast->IsForOfStatement()) {
        auto const *left = ast->AsForOfStatement()->Left();
        if (left == nullptr) {
            AddError("NULL FOR-OF-LEFT: " + ToStringHelper(ast), ast->Start());
            return false;
        }

        if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
            AddError("INCORRECT FOR-OF-LEFT: " + ToStringHelper(ast), ast->Start());
            return false;
        }
    }

    if (ast->IsForUpdateStatement()) {
        // The most important part of for-loop is the test.
        // But it also can be null. Then there must be break;(return) in the body.
        auto const *test = ast->AsForUpdateStatement()->Test();
        if (test == nullptr) {
            auto const *body = ast->AsForUpdateStatement()->Body();
            if (body == nullptr) {
                AddError("NULL FOR-TEST AND FOR-BODY: " + ToStringHelper(ast), ast->Start());
                return false;
            }
            bool has_exit = body->IsBreakStatement() || body->IsReturnStatement();
            body->IterateRecursively([&has_exit](ir::AstNode *child) {
                has_exit |= child->IsBreakStatement() || child->IsReturnStatement();
            });
            if (!has_exit) {
                // an infinite loop
                AddError("WARNING: NULL FOR-TEST AND FOR-BODY doesn't exit: " + ToStringHelper(ast), ast->Start());
            }
            return true;
        }

        if (test->IsExpression()) {
            AddError("NULL FOR VAR: " + ToStringHelper(ast), ast->Start());
            return false;
        }
    }
    return true;
}

bool ASTVerifier::AreForLoopsCorrectInitialized(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    bool is_for_initialized = IsForLoopCorrectInitialized(ast);
    ast->IterateRecursively(
        [this, &is_for_initialized](ir::AstNode *child) { is_for_initialized &= IsForLoopCorrectInitialized(child); });
    return is_for_initialized;
}

bool ASTVerifier::VerifyModifierAccess(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }
    if (ast->IsMemberExpression()) {
        const auto *prop_var = ast->AsMemberExpression()->PropVar();
        if (prop_var != nullptr && prop_var->HasFlag(varbinder::VariableFlags::PROPERTY) &&
            !ValidateVariableAccess(prop_var, ast->AsMemberExpression())) {
            AddError("PROPERTY_NOT_VISIBLE_HERE: " + ToStringHelper(ast), ast->Start());
            return false;
        }
    }
    if (ast->IsCallExpression()) {
        const auto *call_expr = ast->AsCallExpression();
        const auto *callee = call_expr->Callee();
        if (callee != nullptr && callee->IsMemberExpression()) {
            const auto *callee_member = callee->AsMemberExpression();
            const auto *prop_var_callee = callee_member->PropVar();
            if (prop_var_callee != nullptr && prop_var_callee->HasFlag(varbinder::VariableFlags::METHOD) &&
                !ValidateMethodAccess(callee_member, ast->AsCallExpression())) {
                AddError("PROPERTY_NOT_VISIBLE_HERE: " + ToStringHelper(callee), callee->Start());
                return false;
            }
        }
    }
    return true;
}

bool ASTVerifier::VerifyExportAccess(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }
    if (ast->IsETSImportDeclaration()) {
        const auto import_decl = ast->AsETSImportDeclaration()->Specifiers();
        const auto name = [](ir::AstNode *const specifier) {
            if (specifier->IsImportNamespaceSpecifier()) {
                return specifier->AsImportNamespaceSpecifier()->Local()->Name();
            }
            if (specifier->IsImportSpecifier()) {
                return specifier->AsImportSpecifier()->Local()->Name();
            }
            return specifier->AsImportDefaultSpecifier()->Local()->Name();
        };
        for (const auto import : import_decl) {
            imported_variables_.emplace(name(import));
        }
    }
    if (ast->IsCallExpression()) {
        const auto *call_expr = ast->AsCallExpression();
        const auto *callee = call_expr->Callee();
        if (callee != nullptr && callee->IsIdentifier() &&
            !HandleImportExportIdentifier(callee->AsIdentifier(), call_expr)) {
            AddError("PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED): " + ToStringHelper(callee), callee->Start());
            return false;
        }
    }
    if (ast->IsIdentifier() && !HandleImportExportIdentifier(ast->AsIdentifier())) {
        AddError("PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED): " + ToStringHelper(ast), ast->Start());
        return false;
    }
    return true;
}

bool ASTVerifier::CheckImportExportMethod(const varbinder::Variable *var_callee, const ir::AstNode *call_expr,
                                          util::StringView name)
{
    auto *signature = call_expr->AsCallExpression()->Signature();
    if (signature != nullptr && var_callee->Declaration() != nullptr && var_callee->Declaration()->Node() != nullptr &&
        !IsContainedIn(var_callee->Declaration()->Node(), signature->Owner()->GetDeclNode()) &&
        var_callee->Declaration()->Node() != signature->Owner()->GetDeclNode()) {
        if (imported_variables_.find(name) != imported_variables_.end() ||
            imported_variables_.find(util::StringView("")) != imported_variables_.end()) {
            return ValidateExport(var_callee);
        }
        return false;
    }
    return true;
}

bool ASTVerifier::CheckImportExportVariable(const varbinder::Variable *var, const ir::Identifier *ident,
                                            util::StringView name)
{
    if (!var->HasFlag(varbinder::VariableFlags::LOCAL) && !var->HasFlag(varbinder::VariableFlags::VAR) &&
        var->HasFlag(varbinder::VariableFlags::INITIALIZED) && var->Declaration() != nullptr &&
        var->Declaration()->Node() != nullptr && !var->Declaration()->Node()->IsMethodDefinition() &&
        !var->Declaration()->Node()->IsClassProperty()) {
        auto var_parent = var->Declaration()->Node()->Parent();
        if (var_parent != nullptr && !IsContainedIn(ident->Parent(), var_parent) && ident->Parent() != var_parent) {
            if (var->GetScope() != nullptr && var->GetScope()->Parent() != nullptr &&
                var->GetScope()->Parent()->IsGlobalScope() &&
                ident->GetTopStatement() == var_parent->GetTopStatement()) {
                return true;
            }
            if (imported_variables_.find(name) != imported_variables_.end() ||
                imported_variables_.find(util::StringView("")) != imported_variables_.end()) {
                return ValidateExport(var);
            }
            return false;
        }
    }
    return true;
}

bool ASTVerifier::HandleImportExportIdentifier(const ir::Identifier *ident, const ir::AstNode *call_expr)
{
    if (ident->IsReference()) {
        const auto *var = ident->Variable();
        if (var != nullptr) {
            if (var->HasFlag(varbinder::VariableFlags::METHOD) && call_expr != nullptr) {
                return CheckImportExportMethod(var, call_expr, ident->Name());
            }
            return CheckImportExportVariable(var, ident, ident->Name());
        }
    }
    return true;
}

ASTVerifier::ASTVerifier(ArenaAllocator *allocator, util::StringView source_code)
    : allocator_ {allocator},
      named_errors_ {allocator_->Adapter()},
      encountered_errors_ {allocator_->Adapter()},
      checks_ {allocator_->Adapter()},
      all_checks_(allocator_->Adapter())
{
    if (!source_code.Empty()) {
        index_.emplace(source_code);
    }

    ADD_CHECK(HasParent);
    ADD_CHECK(HasType);
    ADD_CHECK(HasVariable);
    ADD_CHECK(HasScope);
    ADD_CHECK(VerifyChildNode);
    ADD_CHECK(VerifyScopeNode);
    ADD_CHECK(IsForLoopCorrectInitialized);
    ADD_CHECK(AreForLoopsCorrectInitialized);
    ADD_CHECK(VerifyModifierAccess);
    ADD_CHECK(VerifyExportAccess);
    ADD_CHECK(CheckArithmeticExpression);
}

bool ASTVerifier::VerifyFull(const ir::AstNode *ast)
{
    return Verify(ast, all_checks_);
}

bool ASTVerifier::Verify(const ir::AstNode *ast, const CheckSet &check_set)
{
    bool is_correct = true;
    auto check_and_report = [&is_correct, this](util::StringView name, const CheckFunction &check,
                                                const ir::AstNode *node) {
        if (node == nullptr) {
            return;
        }

        is_correct &= check(node);
        if (!is_correct) {
            for (const auto &error : encountered_errors_) {
                named_errors_.emplace_back(NamedError {name, error});
            }
            encountered_errors_.clear();
        }
    };

    const auto contains_checks =
        std::includes(all_checks_.begin(), all_checks_.end(), check_set.begin(), check_set.end());
    if (!contains_checks) {
        auto invalid_checks = CheckSet {allocator_->Adapter()};
        for (const auto &check : check_set) {
            if (all_checks_.find(check) == all_checks_.end()) {
                invalid_checks.insert(check);
            }
        }
        for (const auto &check : invalid_checks) {
            const auto &message = check.Mutf8() + " check is not found";
            named_errors_.emplace_back(NamedError {"Check", Error {message, lexer::SourceLocation {}}});
        }
    }

    for (const auto &[name, check] : checks_) {
        if (check_set.find(name) != check_set.end()) {
            check_and_report(name, check, ast);
        }
    }
    return is_correct;
}

}  // namespace panda::es2panda::compiler
