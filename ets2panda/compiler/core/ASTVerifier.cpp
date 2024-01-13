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
#include "ir/base/classElement.h"
#include "ir/statement.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsScript.h"
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
        bool hasParent = func(ast);
        ast->IterateRecursively([func, &hasParent](ir::AstNode *child) { hasParent &= func(child); });
        return hasParent;
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

    auto typedAst = static_cast<const ir::TypedAstNode *>(ast);

    if (typedAst->TsType() == nullptr) {
        return false;
    }

    return typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) ||
           typedAst->TsType()->HasTypeFlag(checker::TypeFlag::NUMBER_LITERAL) ||
           typedAst->TsType()->HasTypeFlag(checker::TypeFlag::BIGINT_LITERAL);
}

static bool IsStringType(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (!ast->IsTyped()) {
        return false;
    }

    auto typedAst = static_cast<const ir::TypedAstNode *>(ast);

    if (typedAst->TsType() == nullptr) {
        return false;
    }

    return typedAst->TsType()->HasTypeFlag(checker::TypeFlag::STRING_LIKE);
}

template <typename T>
bool IsContainedIn(const T *child, const T *parent)
{
    if (child == nullptr || parent == nullptr) {
        return false;
    }

    std::unordered_set<const T *> savedNodes;
    while (child != nullptr && child != parent) {
        savedNodes.emplace(child);
        child = child->Parent();
        if (savedNodes.find(child) != savedNodes.end()) {
            return false;
        }
    }
    return child == parent;
}
bool IsVisibleInternalNode(const ir::AstNode *ast, const ir::AstNode *objTypeDeclNode)
{
    auto *currentTopStatement = (static_cast<const ir::ETSScript *>(ast->GetTopStatement()));
    auto *currentProgram = currentTopStatement->Program();
    if (currentProgram == nullptr) {
        return false;
    }
    util::StringView packageNameCurrent = currentProgram->GetPackageName();
    auto *objectTopStatement = (static_cast<const ir::ETSScript *>(objTypeDeclNode->GetTopStatement()));
    auto *objectProgram = objectTopStatement->Program();
    if (objectProgram == nullptr) {
        return false;
    }
    util::StringView packageNameObject = objectProgram->GetPackageName();
    return currentTopStatement == objectTopStatement ||
           (packageNameCurrent == packageNameObject && !packageNameCurrent.Empty());
}
bool ValidateVariableAccess(const varbinder::LocalVariable *propVar, const ir::MemberExpression *ast)
{
    const auto *propVarDecl = propVar->Declaration();
    if (propVarDecl == nullptr) {
        return false;
    }
    const auto *propVarDeclNode = propVarDecl->Node();
    if (propVarDeclNode == nullptr) {
        return false;
    }
    auto *objType = ast->ObjType();
    if (objType == nullptr) {
        return false;
    }
    const auto *objTypeDeclNode = objType->GetDeclNode();
    if (objTypeDeclNode == nullptr) {
        return false;
    }
    const auto *propVarDeclNodeParent = propVarDeclNode->Parent();
    if (propVarDeclNodeParent != nullptr && propVarDeclNodeParent->IsClassDefinition() &&
        objTypeDeclNode->IsClassDefinition()) {
        // Check if the variable is used where it is declared
        if (IsContainedIn<const ir::AstNode>(ast, propVarDeclNodeParent->AsClassDefinition())) {
            return true;
        }
        if (propVarDeclNode->IsPrivate()) {
            return false;
        }
        if (propVarDeclNode->IsProtected()) {
            // Check if the variable is inherited and is used in class in which it is inherited
            auto ret = objType->IsPropertyInherited(propVar);
            return ret && IsContainedIn<const ir::AstNode>(ast, objTypeDeclNode->AsClassDefinition());
        }
        if (propVarDeclNode->IsInternal()) {
            return IsVisibleInternalNode(ast, objTypeDeclNode);
        }
        return true;
    }
    return false;
}

bool ValidateMethodAccess(const ir::MemberExpression *memberExpression, const ir::CallExpression *ast)
{
    auto *memberObjType = memberExpression->ObjType();
    if (memberObjType == nullptr) {
        return false;
    }
    if (memberObjType->HasObjectFlag(checker::ETSObjectFlags::RESOLVED_SUPER) &&
        memberObjType->SuperType() != nullptr &&
        memberObjType->SuperType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_TYPE |
                                                  checker::ETSObjectFlags::GLOBAL)) {
        return true;
    }
    const auto *memberObjTypeDeclNode = memberObjType->GetDeclNode();
    if (memberObjTypeDeclNode == nullptr) {
        return false;
    }
    auto *signature = ast->Signature();
    if (signature == nullptr) {
        return false;
    }
    auto *ownerSign = signature->Owner();
    if (ownerSign == nullptr) {
        return false;
    }
    auto *ownerSignDeclNode = ownerSign->GetDeclNode();
    if (ownerSignDeclNode != nullptr && ownerSignDeclNode->IsClassDefinition() &&
        memberObjTypeDeclNode->IsClassDefinition()) {
        // Check if the method is used where it is declared
        if (IsContainedIn<const ir::AstNode>(ast, ownerSignDeclNode->AsClassDefinition())) {
            return true;
        }
        if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE)) {
            return false;
        }
        if (signature->HasSignatureFlag(checker::SignatureFlags::PROTECTED)) {
            // Check if the method is inherited and is used in class in which it is inherited
            auto ret = memberObjType->IsSignatureInherited(signature);
            return ret && IsContainedIn<const ir::AstNode>(ast, memberObjTypeDeclNode->AsClassDefinition());
        }
        if (signature->HasSignatureFlag(checker::SignatureFlags::INTERNAL)) {
            return IsVisibleInternalNode(ast, memberObjTypeDeclNode);
        }
        return true;
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

template <typename T>
std::string ToStringParamsHelper(const ArenaVector<T *> &params)
{
    std::string name = "(";

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
            return "ETS_FUNC_TYPE " + ToStringParamsHelper<ir::Expression>(ast->AsETSFunctionType()->Params());
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
        allChecks_.insert(#Name);                                                              \
        checks_.emplace_back(NamedCheck {#Name "Recursive", RecursiveCheck(check)});           \
        allChecks_.insert(#Name "Recursive");                                                  \
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
    if (const auto maybeVar = GetLocalScopeVariable(ast)) {
        const auto var = *maybeVar;
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
        const auto localVar = variable->AsLocalVariable();
        if (localVar->HasFlag(varbinder::VariableFlags::LOCAL)) {
            return localVar;
        }
    }
    return std::nullopt;
}

bool ASTVerifier::VerifyChildNode(const ir::AstNode *ast)
{
    ASSERT(ast);
    bool isOk = true;
    ast->Iterate([&](const auto node) {
        if (ast != node->Parent()) {
            AddError("INCORRECT_PARENT_REF: " + ToStringHelper(node), node->Start());
            isOk = false;
        }
    });
    return isOk;
}

bool ASTVerifier::VerifyScopeNode(const ir::AstNode *ast)
{
    ASSERT(ast);
    const auto maybeVar = GetLocalScopeVariable(ast);
    if (!maybeVar) {
        return true;
    }
    const auto var = *maybeVar;
    const auto scope = var->GetScope();
    if (scope == nullptr) {
        // already checked
        return false;
    }
    const auto encloseScope = scope->EnclosingVariableScope();
    if (encloseScope == nullptr) {
        AddError("NO_ENCLOSING_VAR_SCOPE: " + ToStringHelper(ast), ast->Start());
        return false;
    }
    const auto node = scope->Node();
    bool isOk = true;
    if (!IsContainedIn(ast, node)) {
        isOk = false;
        AddError("VARIABLE_NOT_ENCLOSE_SCOPE: " + ToStringHelper(ast), ast->Start());
    }
    if (!IsContainedIn<varbinder::Scope>(scope, encloseScope)) {
        isOk = false;
        AddError("VARIABLE_NOT_ENCLOSE_SCOPE: " + ToStringHelper(ast), ast->Start());
    }
    return isOk;
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
    const auto varStart = node->Start();
    bool isOk = true;
    if (scope->Bindings().count(var->Name()) == 0) {
        AddError("SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR: " + ToStringHelper(node), varStart);
        isOk = false;
    }
    const auto scopeNode = scope->Node();
    auto varNode = node;
    if (!IsContainedIn(varNode, scopeNode) || scopeNode == nullptr) {
        AddError("SCOPE_NODE_DONT_DOMINATE_VAR_NODE: " + ToStringHelper(node), varStart);
        isOk = false;
    }
    const auto &decls = scope->Decls();
    const auto declDominate = std::count(decls.begin(), decls.end(), var->Declaration());
    if (declDominate == 0) {
        AddError("SCOPE_DECL_DONT_DOMINATE_VAR_DECL: " + ToStringHelper(node), varStart);
        isOk = false;
    }
    return isOk;
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
        bool isCorrect = true;
        ast->Iterate([&isCorrect](ir::AstNode *child) { isCorrect &= (IsNumericType(child)); });
        return isCorrect;
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
            bool hasExit = body->IsBreakStatement() || body->IsReturnStatement();
            body->IterateRecursively(
                [&hasExit](ir::AstNode *child) { hasExit |= child->IsBreakStatement() || child->IsReturnStatement(); });
            if (!hasExit) {
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

    bool isForInitialized = IsForLoopCorrectInitialized(ast);
    ast->IterateRecursively(
        [this, &isForInitialized](ir::AstNode *child) { isForInitialized &= IsForLoopCorrectInitialized(child); });
    return isForInitialized;
}

bool ASTVerifier::VerifyModifierAccess(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }
    if (ast->IsMemberExpression()) {
        const auto *propVar = ast->AsMemberExpression()->PropVar();
        if (propVar == nullptr || (propVar->HasFlag(varbinder::VariableFlags::PROPERTY) &&
                                   !ValidateVariableAccess(propVar, ast->AsMemberExpression()))) {
            AddError("PROPERTY_NOT_VISIBLE_HERE: " + ToStringHelper(ast), ast->Start());
            return false;
        }
    }
    if (ast->IsCallExpression()) {
        const auto *callExpr = ast->AsCallExpression();
        const auto *callee = callExpr->Callee();
        if (callee == nullptr) {
            return false;
        }
        if (callee->IsMemberExpression()) {
            const auto *calleeMember = callee->AsMemberExpression();
            const auto *propVarCallee = calleeMember->PropVar();
            if (propVarCallee == nullptr || (propVarCallee->HasFlag(varbinder::VariableFlags::METHOD) &&
                                             !ValidateMethodAccess(calleeMember, ast->AsCallExpression()))) {
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
        const auto importDecl = ast->AsETSImportDeclaration()->Specifiers();
        const auto name = [](ir::AstNode *const specifier) {
            if (specifier->IsImportNamespaceSpecifier()) {
                return specifier->AsImportNamespaceSpecifier()->Local()->Name();
            }
            if (specifier->IsImportSpecifier()) {
                return specifier->AsImportSpecifier()->Local()->Name();
            }
            return specifier->AsImportDefaultSpecifier()->Local()->Name();
        };
        for (const auto import : importDecl) {
            importedVariables_.emplace(name(import));
        }
    }
    if (ast->IsCallExpression()) {
        const auto *callExpr = ast->AsCallExpression();
        const auto *callee = callExpr->Callee();
        if (callee != nullptr && callee->IsIdentifier() &&
            !HandleImportExportIdentifier(callee->AsIdentifier(), callExpr)) {
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

bool ASTVerifier::CheckImportExportMethod(const varbinder::Variable *varCallee, const ir::AstNode *callExpr,
                                          util::StringView name)
{
    auto *signature = callExpr->AsCallExpression()->Signature();
    if (signature->Owner() == nullptr) {
        // NOTE(vpukhov): Add a synthetic owner for dynamic signatures
        ASSERT(callExpr->AsCallExpression()->Callee()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG));
        return true;
    }

    if (signature != nullptr && varCallee->Declaration() != nullptr && varCallee->Declaration()->Node() != nullptr &&
        !IsContainedIn(varCallee->Declaration()->Node(), signature->Owner()->GetDeclNode()) &&
        varCallee->Declaration()->Node() != signature->Owner()->GetDeclNode()) {
        if (importedVariables_.find(name) != importedVariables_.end() ||
            importedVariables_.find(util::StringView("")) != importedVariables_.end()) {
            return ValidateExport(varCallee);
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
        auto varParent = var->Declaration()->Node()->Parent();
        if (varParent != nullptr && !IsContainedIn(ident->Parent(), varParent) && ident->Parent() != varParent) {
            if (var->GetScope() != nullptr && var->GetScope()->Parent() != nullptr &&
                var->GetScope()->Parent()->IsGlobalScope() &&
                ident->GetTopStatement() == varParent->GetTopStatement()) {
                return true;
            }
            if (importedVariables_.find(name) != importedVariables_.end() ||
                importedVariables_.find(util::StringView("")) != importedVariables_.end()) {
                return ValidateExport(var);
            }
            return false;
        }
    }
    return true;
}

bool ASTVerifier::HandleImportExportIdentifier(const ir::Identifier *ident, const ir::AstNode *callExpr)
{
    if (ident->IsReference()) {
        const auto *var = ident->Variable();
        if (var != nullptr) {
            if (var->HasFlag(varbinder::VariableFlags::METHOD) && callExpr != nullptr) {
                return CheckImportExportMethod(var, callExpr, ident->Name());
            }
            return CheckImportExportVariable(var, ident, ident->Name());
        }
    }
    return true;
}

ASTVerifier::ASTVerifier(ArenaAllocator *allocator, bool saveErrors, util::StringView sourceCode)
    : saveErrors_(saveErrors),
      allocator_ {allocator},
      namedErrors_ {allocator_->Adapter()},
      encounteredErrors_ {allocator_->Adapter()},
      checks_ {allocator_->Adapter()},
      allChecks_(allocator_->Adapter())
{
    if (!sourceCode.Empty()) {
        index_.emplace(sourceCode);
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
    return Verify(ast, allChecks_);
}

bool ASTVerifier::Verify(const ir::AstNode *ast, const CheckSet &checkSet)
{
    bool isCorrect = true;
    auto checkAndReport = [&isCorrect, this](util::StringView name, const CheckFunction &check,
                                             const ir::AstNode *node) {
        if (node == nullptr) {
            return;
        }

        isCorrect &= check(node);
        if (!isCorrect) {
            for (const auto &error : encounteredErrors_) {
                namedErrors_.emplace_back(NamedError {name, error});
            }
            encounteredErrors_.clear();
        }
    };

    const auto containsChecks = std::includes(allChecks_.begin(), allChecks_.end(), checkSet.begin(), checkSet.end());
    if (!containsChecks) {
        auto invalidChecks = CheckSet {allocator_->Adapter()};
        for (const auto &check : checkSet) {
            if (allChecks_.find(check) == allChecks_.end()) {
                invalidChecks.insert(check);
            }
        }
        for (const auto &check : invalidChecks) {
            const auto &message = check.Mutf8() + " check is not found";
            namedErrors_.emplace_back(NamedError {"Check", Error {message, lexer::SourceLocation {}}});
        }
    }

    for (const auto &[name, check] : checks_) {
        if (checkSet.find(name) != checkSet.end()) {
            checkAndReport(name, check, ast);
        }
    }
    return isCorrect;
}

}  // namespace panda::es2panda::compiler
