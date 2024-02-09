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

#include "ASTVerifier.h"

#include "checker/types/typeFlag.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classElement.h"
#include "ir/statement.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsScript.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/module/importSpecifier.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/statements/forInStatement.h"
#include "ir/statements/forOfStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/ts/tsTypeParameter.h"
#include "lexer/token/tokenType.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "varbinder/scope.h"

constexpr auto RECURSIVE_SUFFIX = "ForAll";

namespace ark::es2panda::compiler {

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
static bool IsContainedIn(const T *child, const T *parent)
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

static bool ValidateVariableAccess(const varbinder::LocalVariable *propVar, const ir::MemberExpression *ast)
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

static bool ValidateMethodAccess(const ir::MemberExpression *memberExpression, const ir::CallExpression *ast)
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

class NodeHasParent {
public:
    explicit NodeHasParent([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        const auto isEtsScript = ast->IsETSScript();
        const auto hasParent = ast->Parent() != nullptr;
        if (!isEtsScript && !hasParent) {
            ctx.AddInvariantError("NodeHasParent", "NULL_PARENT", *ast);
            return ASTVerifier::CheckResult::FAILED;
        }
        if (ast->IsProgram()) {
            return ASTVerifier::CheckResult::SUCCESS;
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }
};

class IdentifierHasVariable {
public:
    explicit IdentifierHasVariable([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return ASTVerifier::CheckResult::SUCCESS;
        }
        if (ast->AsIdentifier()->Variable() != nullptr) {
            return ASTVerifier::CheckResult::SUCCESS;
        }

        const auto *id = ast->AsIdentifier();
        ctx.AddInvariantError("IdentifierHasVariable", "NULL_VARIABLE", *id);
        return ASTVerifier::CheckResult::FAILED;
    }

private:
};

class NodeHasType {
public:
    explicit NodeHasType([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        if (ast->IsTyped()) {
            if (ast->IsClassDefinition() && ast->AsClassDefinition()->Ident()->Name() == "ETSGLOBAL") {
                return ASTVerifier::CheckResult::SKIP_SUBTREE;
            }
            const auto *typed = static_cast<const ir::TypedAstNode *>(ast);
            if (typed->TsType() == nullptr) {
                ctx.AddInvariantError("NodeHasType", "NULL_TS_TYPE", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
};

class VariableHasScope {
public:
    explicit VariableHasScope(ArenaAllocator &allocator) : allocator_ {allocator} {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return ASTVerifier::CheckResult::SUCCESS;  // we will check invariant of Identifier only
        }

        // we will check invariant for only local variables of identifiers
        if (const auto maybeVar = GetLocalScopeVariable(allocator_, ctx, ast); maybeVar.has_value()) {
            const auto var = *maybeVar;
            const auto scope = var->GetScope();
            if (scope == nullptr) {
                ctx.AddInvariantError("VariableHasScope", "NULL_SCOPE_LOCAL_VAR", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
            return ScopeEncloseVariable(ctx, var) ? ASTVerifier::CheckResult::SUCCESS
                                                  : ASTVerifier::CheckResult::FAILED;
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

    static std::optional<varbinder::LocalVariable *> GetLocalScopeVariable(ArenaAllocator &allocator,
                                                                           ASTVerifier::ErrorContext &ctx,
                                                                           const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return std::nullopt;
        }

        auto invariantHasVariable = IdentifierHasVariable {allocator};
        const auto variable = ast->AsIdentifier()->Variable();
        if ((invariantHasVariable(ctx, ast) == ASTVerifier::CheckResult::SUCCESS) && variable->IsLocalVariable()) {
            const auto localVar = variable->AsLocalVariable();
            if (localVar->HasFlag(varbinder::VariableFlags::LOCAL)) {
                return localVar;
            }
        }
        return std::nullopt;
    }

    bool ScopeEncloseVariable(ASTVerifier::ErrorContext &ctx, const varbinder::LocalVariable *var)
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
        const auto name = "VariableHasScope";
        bool isOk = true;
        if (scope->Bindings().count(var->Name()) == 0) {
            ctx.AddInvariantError(name, "SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR", *node);
            isOk = false;
        }
        const auto scopeNode = scope->Node();
        auto varNode = node;
        if (!IsContainedIn(varNode, scopeNode) || scopeNode == nullptr) {
            ctx.AddInvariantError(name, "SCOPE_NODE_DONT_DOMINATE_VAR_NODE", *node);
            isOk = false;
        }
        const auto &decls = scope->Decls();
        const auto declDominate = std::count(decls.begin(), decls.end(), var->Declaration());
        if (declDominate == 0) {
            ctx.AddInvariantError(name, "SCOPE_DECL_DONT_DOMINATE_VAR_DECL", *node);
            isOk = false;
        }
        return isOk;
    }

private:
    ArenaAllocator &allocator_;
};

class EveryChildHasValidParent {
public:
    explicit EveryChildHasValidParent([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        auto result = ASTVerifier::CheckResult::SUCCESS;
        if (ast->IsETSScript()) {
            return result;
        }
        ast->Iterate([&](const ir::AstNode *node) {
            if (ast != node->Parent()) {
                ctx.AddInvariantError("EveryChildHasValidParent", "INCORRECT_PARENT_REF", *node);
                result = ASTVerifier::CheckResult::FAILED;
            }
        });
        return result;
    }

private:
};

class VariableHasEnclosingScope {
public:
    explicit VariableHasEnclosingScope(ArenaAllocator &allocator) : allocator_ {allocator} {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        const auto maybeVar = VariableHasScope::GetLocalScopeVariable(allocator_, ctx, ast);
        if (!maybeVar) {
            return ASTVerifier::CheckResult::SUCCESS;
        }
        const auto var = *maybeVar;
        const auto scope = var->GetScope();
        const auto name = "VariableHasEnclosingScope";
        if (scope == nullptr) {
            // already checked
            return ASTVerifier::CheckResult::SUCCESS;
        }
        const auto encloseScope = scope->EnclosingVariableScope();
        if (encloseScope == nullptr) {
            ctx.AddInvariantError(name, "NO_ENCLOSING_VAR_SCOPE", *ast);
            return ASTVerifier::CheckResult::FAILED;
        }
        const auto node = scope->Node();
        auto result = ASTVerifier::CheckResult::SUCCESS;
        if (!IsContainedIn(ast, node)) {
            result = ASTVerifier::CheckResult::FAILED;
            ctx.AddInvariantError(name, "VARIABLE_NOT_ENCLOSE_SCOPE", *ast);
        }
        if (!IsContainedIn<varbinder::Scope>(scope, encloseScope)) {
            result = ASTVerifier::CheckResult::FAILED;
            ctx.AddInvariantError(name, "VARIABLE_NOT_ENCLOSE_SCOPE", *ast);
        }
        return result;
    }

private:
    ArenaAllocator &allocator_;
};

class SequenceExpressionHasLastType {
public:
    explicit SequenceExpressionHasLastType([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsSequenceExpression()) {
            return ASTVerifier::CheckResult::SUCCESS;
        }
        const auto *expr = ast->AsSequenceExpression();
        const auto *last = expr->Sequence().back();
        const auto name = "SequenceExpressionHasLastType";
        if (expr->TsType() == nullptr) {
            ctx.AddInvariantError(name, "Sequence expression type is null", *expr);
            return ASTVerifier::CheckResult::FAILED;
        }
        if (last->TsType() == nullptr) {
            ctx.AddInvariantError(name, "Sequence expression last type is null", *last);
            return ASTVerifier::CheckResult::FAILED;
        }
        if (expr->TsType() != last->TsType()) {
            ctx.AddInvariantError(name, "Sequence expression type and last expression type are not the same", *expr);
            return ASTVerifier::CheckResult::FAILED;
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
};

class ForLoopCorrectlyInitialized {
public:
    explicit ForLoopCorrectlyInitialized([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        const auto name = "ForLoopCorrectlyInitialized";
        if (ast->IsForInStatement()) {
            auto const *left = ast->AsForInStatement()->Left();
            if (left == nullptr) {
                ctx.AddInvariantError(name, "NULL FOR-IN-LEFT", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }

            if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
                ctx.AddInvariantError(name, "INCORRECT FOR-IN-LEFT", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
        }

        if (ast->IsForOfStatement()) {
            auto const *left = ast->AsForOfStatement()->Left();
            if (left == nullptr) {
                ctx.AddInvariantError(name, "NULL FOR-OF-LEFT", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }

            if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
                ctx.AddInvariantError(name, "INCORRECT FOR-OF-LEFT", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
        }

        if (ast->IsForUpdateStatement()) {
            // The most important part of for-loop is the test.
            // But it also can be null. Then there must be break;(return) in the body.
            auto const *test = ast->AsForUpdateStatement()->Test();
            if (test == nullptr) {
                auto const *body = ast->AsForUpdateStatement()->Body();
                if (body == nullptr) {
                    ctx.AddInvariantError(name, "NULL FOR-TEST AND FOR-BODY", *ast);
                    return ASTVerifier::CheckResult::FAILED;
                }
                bool hasExit = body->IsBreakStatement() || body->IsReturnStatement();
                body->IterateRecursively([&hasExit](ir::AstNode *child) {
                    hasExit |= child->IsBreakStatement() || child->IsReturnStatement();
                });
                if (!hasExit) {
                    // an infinite loop
                    ctx.AddInvariantError(name, "WARNING: NULL FOR-TEST AND FOR-BODY doesn't exit", *ast);
                }
                return ASTVerifier::CheckResult::SUCCESS;
            }

            if (!test->IsExpression()) {
                ctx.AddInvariantError(name, "NULL FOR VAR", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
};

class ModifierAccessValid {
public:
    explicit ModifierAccessValid([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        const auto name = "ModifierAccessValid";
        if (ast->IsMemberExpression()) {
            const auto *propVar = ast->AsMemberExpression()->PropVar();
            if (propVar != nullptr && propVar->HasFlag(varbinder::VariableFlags::PROPERTY) &&
                !ValidateVariableAccess(propVar, ast->AsMemberExpression())) {
                ctx.AddInvariantError(name, "PROPERTY_NOT_VISIBLE_HERE", *ast);
                return ASTVerifier::CheckResult::FAILED;
            }
        }
        if (ast->IsCallExpression()) {
            const auto *callExpr = ast->AsCallExpression();
            const auto *callee = callExpr->Callee();
            if (callee != nullptr && callee->IsMemberExpression()) {
                const auto *calleeMember = callee->AsMemberExpression();
                const auto *propVarCallee = calleeMember->PropVar();
                if (propVarCallee != nullptr && propVarCallee->HasFlag(varbinder::VariableFlags::METHOD) &&
                    !ValidateMethodAccess(calleeMember, ast->AsCallExpression())) {
                    ctx.AddInvariantError(name, "PROPERTY_NOT_VISIBLE_HERE", *callee);
                    return ASTVerifier::CheckResult::FAILED;
                }
            }
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
};

class ImportExportAccessValid {
public:
    explicit ImportExportAccessValid([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()(ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        ASTVerifier::InvariantSet importedVariables {};
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
                importedVariables.emplace(name(import));
            }
        }
        const auto name = "ImportExportAccessValid";
        if (ast->IsCallExpression()) {
            const auto *callExpr = ast->AsCallExpression();
            const auto *callee = callExpr->Callee();
            if (callee != nullptr && callee->IsIdentifier() &&
                !HandleImportExportIdentifier(importedVariables, callee->AsIdentifier(), callExpr)) {
                ctx.AddInvariantError(name, "PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED)", *callee);
                return ASTVerifier::CheckResult::FAILED;
            }
        }
        if (ast->IsIdentifier() && !HandleImportExportIdentifier(importedVariables, ast->AsIdentifier(), nullptr)) {
            ctx.AddInvariantError(name, "PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED)", *ast);
            return ASTVerifier::CheckResult::FAILED;
        }
        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
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

    bool InvariantImportExportMethod(const ASTVerifier::InvariantSet &importedVariables,
                                     const varbinder::Variable *varCallee, const ir::AstNode *callExpr,
                                     util::StringView name)
    {
        auto *signature = callExpr->AsCallExpression()->Signature();
        if (signature->Owner() == nullptr) {
            // NOTE(vpukhov): Add a synthetic owner for dynamic signatures
            ASSERT(callExpr->AsCallExpression()->Callee()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_DYNAMIC_FLAG));
            return true;
        }

        if (signature != nullptr && varCallee->Declaration() != nullptr &&
            varCallee->Declaration()->Node() != nullptr &&
            !IsContainedIn(varCallee->Declaration()->Node(), signature->Owner()->GetDeclNode()) &&
            varCallee->Declaration()->Node() != signature->Owner()->GetDeclNode()) {
            if (importedVariables.find(name.Mutf8()) != importedVariables.end() ||
                importedVariables.find("") != importedVariables.end()) {
                return ValidateExport(varCallee);
            }
            return false;
        }
        return true;
    }

    bool InvariantImportExportVariable(const ASTVerifier::InvariantSet &importedVariables,
                                       const varbinder::Variable *var, const ir::Identifier *ident,
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
                if (importedVariables.find(name.Mutf8()) != importedVariables.end() ||
                    importedVariables.find("") != importedVariables.end()) {
                    return ValidateExport(var);
                }
                return false;
            }
        }
        return true;
    }

    bool HandleImportExportIdentifier(ASTVerifier::InvariantSet &importedVariables, const ir::Identifier *ident,
                                      const ir::AstNode *callExpr)
    {
        if (ident->IsReference()) {
            const auto *var = ident->Variable();
            if (var != nullptr) {
                if (var->HasFlag(varbinder::VariableFlags::METHOD) && callExpr != nullptr) {
                    return InvariantImportExportMethod(importedVariables, var, callExpr, ident->Name());
                }
                return InvariantImportExportVariable(importedVariables, var, ident, ident->Name());
            }
        }
        return true;
    }
};

class ArithmeticOperationValid {
public:
    explicit ArithmeticOperationValid([[maybe_unused]] ArenaAllocator &allocator) {}

    ASTVerifier::CheckResult operator()([[maybe_unused]] ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast)
    {
        if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->IsArithmetic()) {
            if (ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS &&
                IsStringType(ast->AsBinaryExpression()->Left()) && IsStringType(ast->AsBinaryExpression()->Right())) {
                return ASTVerifier::CheckResult::SUCCESS;
            }
            auto result = ASTVerifier::CheckResult::SUCCESS;
            ast->Iterate([&result](ir::AstNode *child) {
                if (!IsNumericType(child)) {
                    result = ASTVerifier::CheckResult::FAILED;
                }
            });
            return result;
        }

        return ASTVerifier::CheckResult::SUCCESS;
    }

private:
};

template <typename Func>
static ASTVerifier::InvariantCheck RecursiveInvariant(const Func &func)
{
    return [func](ASTVerifier::ErrorContext &ctx, const ir::AstNode *ast) -> ASTVerifier::CheckResult {
        std::function<void(const ir::AstNode *)> aux;
        auto result = ASTVerifier::CheckResult::SUCCESS;
        aux = [&ctx, &func, &aux, &result](const ir::AstNode *child) -> void {
            if (result == ASTVerifier::CheckResult::FAILED) {
                return;
            }
            const auto newResult = func(ctx, child);
            if (newResult == ASTVerifier::CheckResult::SKIP_SUBTREE) {
                return;
            }
            result = newResult;
            child->Iterate(aux);
        };
        aux(ast);
        return result;
    };
}

void ASTVerifier::AddInvariant(const std::string &name, const InvariantCheck &invariant)
{
    invariantsChecks_[name] = invariant;
    invariantsNames_.insert(name);
    invariantsChecks_[name + RECURSIVE_SUFFIX] = RecursiveInvariant(invariant);
    invariantsNames_.insert(name + RECURSIVE_SUFFIX);
}

ASTVerifier::ASTVerifier(ArenaAllocator *allocator)
{
    AddInvariant("NodeHasParent", *allocator->New<NodeHasParent>(*allocator));
    AddInvariant("NodeHasType", *allocator->New<NodeHasType>(*allocator));
    AddInvariant("IdentifierHasVariable", *allocator->New<IdentifierHasVariable>(*allocator));
    AddInvariant("VariableHasScope", *allocator->New<VariableHasScope>(*allocator));
    AddInvariant("EveryChildHasValidParent", *allocator->New<EveryChildHasValidParent>(*allocator));
    AddInvariant("VariableHasEnclosingScope", *allocator->New<VariableHasEnclosingScope>(*allocator));
    AddInvariant("ForLoopCorrectlyInitialized", *allocator->New<ForLoopCorrectlyInitialized>(*allocator));
    AddInvariant("ModifierAccessValid", *allocator->New<ModifierAccessValid>(*allocator));
    AddInvariant("ImportExportAccessValid", *allocator->New<ImportExportAccessValid>(*allocator));
    AddInvariant("ArithmeticOperationValid", *allocator->New<ArithmeticOperationValid>(*allocator));
    AddInvariant("SequenceExpressionHasLastType", *allocator->New<SequenceExpressionHasLastType>(*allocator));
}

std::tuple<ASTVerifier::Errors, ASTVerifier::Errors> ASTVerifier::VerifyFull(
    const std::unordered_set<std::string> &warnings, const std::unordered_set<std::string> &asserts,
    const ir::AstNode *ast)
{
    auto recursiveChecks = InvariantSet {};
    std::copy_if(invariantsNames_.begin(), invariantsNames_.end(),
                 std::inserter(recursiveChecks, recursiveChecks.end()),
                 [](const std::string &s) { return s.find(RECURSIVE_SUFFIX) != s.npos; });
    return Verify(warnings, asserts, ast, recursiveChecks);
}

std::tuple<ASTVerifier::Errors, ASTVerifier::Errors> ASTVerifier::Verify(
    const std::unordered_set<std::string> &warnings, const std::unordered_set<std::string> &asserts,
    const ir::AstNode *ast, const InvariantSet &invariantSet)
{
    ErrorContext warningCtx {};
    AssertsContext assertCtx {};

    const auto containsInvariants =
        std::includes(invariantsNames_.begin(), invariantsNames_.end(), invariantSet.begin(), invariantSet.end());
    if (!containsInvariants) {
        auto invalidInvariants = InvariantSet {};
        for (const auto &invariant : invariantSet) {
            if (invariantsNames_.find(invariant) == invariantsNames_.end()) {
                invalidInvariants.insert(invariant.data());
            }
        }
        for (const auto &invariant : invalidInvariants) {
            assertCtx.AddError(std::string {"invariant was not found: "} + invariant);
        }
    }

    for (const auto &invariantName : invariantSet) {
        if (warnings.count(invariantName) > 0) {
            invariantsChecks_[invariantName](warningCtx, ast);
        } else if (asserts.count(invariantName) > 0) {
            invariantsChecks_[invariantName](assertCtx, ast);
        }
    }

    return std::make_tuple(warningCtx.GetErrors(), assertCtx.GetErrors());
}

}  // namespace ark::es2panda::compiler
