/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "es2panda.h"
#include "binder/variableFlags.h"
#include "binder/scope.h"
#include "ir/astNode.h"
#include "ir/base/catchClause.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsPackageDeclaration.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"

namespace panda::es2panda::compiler {

bool ASTVerifier::IsCorrectProgram(const parser::Program *program)
{
    bool is_correct = true;
    error_messages_.clear();

    for (auto *statement : program->Ast()->Statements()) {
        is_correct &= HaveParents(statement);
    }
    is_correct &= HaveParents(program->GlobalClass());

    for (auto *statement : program->Ast()->Statements()) {
        is_correct &= HaveTypes(statement);
    }
    is_correct &= HaveTypes(program->GlobalClass());

    for (auto *statement : program->Ast()->Statements()) {
        is_correct &= HaveVariables(statement);
    }
    is_correct &= HaveVariables(program->GlobalClass());

    for (auto *statement : program->Ast()->Statements()) {
        is_correct &= HaveScopes(statement);
    }
    is_correct &= HaveScopes(program->GlobalClass());

#ifndef NDEBUG
    std::for_each(error_messages_.begin(), error_messages_.end(), [](auto const msg) { LOG(INFO, COMMON) << msg; });
#endif  // NDEBUG
    return is_correct;
}

std::string ToStringHelper(const binder::ScopeType type)
{
    switch (type) {
        case binder::ScopeType::CATCH: {
            return "CATCH";
        }
        case binder::ScopeType::CATCH_PARAM: {
            return "CATCH_PARAM";
        }
        case binder::ScopeType::CLASS: {
            return "CLASS";
        }
        case binder::ScopeType::FUNCTION: {
            return "FUNCTION";
        }
        case binder::ScopeType::FUNCTION_PARAM: {
            return "FUNCTION_PARAM";
        }
        case binder::ScopeType::GLOBAL: {
            return "GLOBAL";
        }
        case binder::ScopeType::LOCAL: {
            return "LOCAL";
        }
        case binder::ScopeType::LOOP: {
            return "LOOP";
        }
        case binder::ScopeType::LOOP_DECL: {
            return "LOOP_DECL";
        }
        case binder::ScopeType::MODULE: {
            return "MODULE";
        }
        case binder::ScopeType::PARAM: {
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

std::string ToStringHelper(const binder::Scope *scope)
{
    if (scope == nullptr) {
        return "<null>";
    }

    switch (scope->Type()) {
        case binder::ScopeType::FUNCTION: {
            return "FUNC_SCOPE " + ToStringHelper(scope->AsFunctionScope()->Name());
        }
        case binder::ScopeType::LOCAL: {
            return "LOCAL_SCOPE ";
        }
        case binder::ScopeType::CATCH: {
            return "CATCH_SCOPE ";
        }
        default: {
            return "MUST BE UNREACHABLE";
        }
    }
}

std::string ToStringHelper(const binder::Variable *var)
{
    if (var == nullptr) {
        return "<null>";
    }

    switch (var->Type()) {
        case binder::VariableType::LOCAL: {
            return "LOCAL_VAR " + ToStringHelper(var->Name());
        }
        case binder::VariableType::MODULE: {
            return "MODULE_VAR " + ToStringHelper(var->Name());
        }
        case binder::VariableType::GLOBAL: {
            return "GLOBAL_VAR " + ToStringHelper(var->Name());
        }
        case binder::VariableType::ENUM: {
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
            return "PARAM_DECL " + ToStringParamsHelper<ir::TSTypeParameter>(
                                       ast->Parent(), ast->AsTSTypeParameterDeclaration()->Params());
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

bool ASTVerifier::HasParent(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (ast->Parent() == nullptr) {
        error_messages_.push_back("NULL_PARENT: " + ToStringHelper(ast));
        return false;
    }

    return true;
}

bool ASTVerifier::HaveParents(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    bool has_parent = HasParent(ast);
    ast->IterateRecursively([this, &has_parent](ir::AstNode *child) { has_parent &= HasParent(child); });
    return has_parent;
}

bool ASTVerifier::HasType(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (ast->IsTyped() && static_cast<const ir::TypedAstNode *>(ast)->TsType() == nullptr) {
        error_messages_.push_back("NULL_TS_TYPE: " + ToStringHelper(ast));
        return false;
    }
    return true;
}

bool ASTVerifier::HaveTypes(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    bool has_type = HasType(ast);
    ast->IterateRecursively([this, &has_type](ir::AstNode *child) { has_type &= HasType(child); });
    return has_type;
}

bool ASTVerifier::HasVariable(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (!ast->IsIdentifier() || ast->AsIdentifier()->Variable() != nullptr) {
        return true;
    }

    error_messages_.push_back("NULL_VARIABLE: " + ToStringHelper(ast->AsIdentifier()));
    return false;
}

bool ASTVerifier::HaveVariables(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    bool has_variable = HasVariable(ast);
    ast->IterateRecursively([this, &has_variable](ir::AstNode *child) { has_variable &= HasVariable(child); });
    return has_variable;
}

bool ASTVerifier::HasScope(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    if (!ast->IsIdentifier()) {
        return true;  // we will check only Identifier
    }
    // we will check only local variables of identifiers
    if (HasVariable(ast) && ast->AsIdentifier()->Variable()->IsLocalVariable() &&
        ast->AsIdentifier()->Variable()->AsLocalVariable()->GetScope() == nullptr) {
        error_messages_.push_back("NULL_SCOPE_LOCAL_VAR: " + ToStringHelper(ast));
        return false;
    }
    // TODO(tatiana): Add check that the scope enclose this identifier
    return true;
}

bool ASTVerifier::HaveScopes(const ir::AstNode *ast)
{
    if (ast == nullptr) {
        return false;
    }

    bool has_scope = HasScope(ast);
    ast->IterateRecursively([this, &has_scope](ir::AstNode *child) { has_scope &= HasScope(child); });
    return has_scope;
}

}  // namespace panda::es2panda::compiler
