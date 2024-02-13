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
#include "ir/ets/etsClassLiteral.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsScript.h"
#include "ir/expressions/sequenceExpression.h"
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
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "lexer/token/tokenType.h"
#include "util/ustring.h"
#include "utils/arena_containers.h"
#include "varbinder/scope.h"

#include <algorithm>
#include <iterator>

namespace ark::es2panda::compiler::ast_verifier {
class CheckContext {
public:
    explicit CheckContext() : checkName_ {"Invalid"} {}

    void AddCheckMessage(const std::string &cause, const ir::AstNode &node, const lexer::SourcePosition &from)
    {
        const auto loc = from.line;
        const auto &&dump = node.DumpJSON();
        messages_.emplace_back(checkName_, cause.data(), dump.data(), loc);
    }

    void SetCheckName(util::StringView checkName)
    {
        checkName_ = checkName;
    }

    Messages GetMessages()
    {
        return messages_;
    }

private:
    Messages messages_;
    util::StringView checkName_;
};

static bool IsBooleanType(const ir::AstNode *ast)
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

    if (typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_OBJECT) &&
        ast->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOXING_FLAG)) {
        return typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_BOOLEAN);
    }

    return typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_BOOLEAN) ||
           typedAst->TsType()->HasTypeFlag(checker::TypeFlag::BOOLEAN_LIKE);
}

static bool IsValidTypeForBinaryOp(const ir::AstNode *ast, bool isBitwise)
{
    if (ast == nullptr) {
        std::cout << __LINE__ << std::endl;
        return false;
    }

    if (!ast->IsTyped()) {
        std::cout << __LINE__ << std::endl;
        return false;
    }

    auto typedAst = static_cast<const ir::TypedAstNode *>(ast);

    if (typedAst->TsType() == nullptr) {
        // std::cout << typedAst
        std::cout << __LINE__ << std::endl;
        return false;
    }

    if (IsBooleanType(ast)) {
        return isBitwise;
    }

    if (typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_OBJECT) &&
        typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_BIGINT)) {
        return true;
    }

    if (typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_OBJECT) &&
        ast->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOXING_FLAG)) {
        return typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_TYPE) &&
               !typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_BOOLEAN);
    }

    return typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_NUMERIC) ||
           typedAst->TsType()->HasTypeFlag(checker::TypeFlag::NUMBER_LITERAL) ||
           typedAst->TsType()->HasTypeFlag(checker::TypeFlag::BIGINT) ||
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

    if (typedAst->TsType()->HasTypeFlag(checker::TypeFlag::ETS_OBJECT)) {
        return typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::STRING) ||
               typedAst->TsType()->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::BUILTIN_STRING);
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
    // NOTE(orlovskymaxim) This relies on the fact, that GetTopStatement has no bugs, that is not the case for now
    if (!ast->GetTopStatement()->IsETSScript()) {
        return false;
    }
    auto *currentTopStatement = (static_cast<const ir::ETSScript *>(ast->GetTopStatement()));
    auto *currentProgram = currentTopStatement->Program();
    if (currentProgram == nullptr) {
        return false;
    }
    util::StringView packageNameCurrent = currentProgram->GetPackageName();
    // NOTE(orlovskymaxim) This relies on the fact, that GetTopStatement has no bugs, that is not the case for now
    if (!objTypeDeclNode->GetTopStatement()->IsETSScript()) {
        return false;
    }
    auto *objectTopStatement = (static_cast<const ir::ETSScript *>(objTypeDeclNode->GetTopStatement()));
    auto *objectProgram = objectTopStatement->Program();
    if (objectProgram == nullptr) {
        return false;
    }
    util::StringView packageNameObject = objectProgram->GetPackageName();
    return currentTopStatement == objectTopStatement ||
           (packageNameCurrent == packageNameObject && !packageNameCurrent.Empty());
}

static const checker::Type *GetClassDefinitionType(const ir::AstNode *ast)
{
    const ir::AstNode *tmpNode = ast;
    while (tmpNode->Parent() != nullptr && !tmpNode->IsClassDefinition()) {
        tmpNode = tmpNode->Parent();
    }
    if (!tmpNode->IsClassDefinition()) {
        return nullptr;
    }
    auto *classDefinition = tmpNode->AsClassDefinition();
    return classDefinition->TsType();
}

static const checker::Type *GetTSInterfaceDeclarationType(const ir::AstNode *ast)
{
    const ir::AstNode *tmpNode = ast;
    while (tmpNode->Parent() != nullptr && !tmpNode->IsTSInterfaceDeclaration()) {
        tmpNode = tmpNode->Parent();
    }
    if (!tmpNode->IsTSInterfaceDeclaration()) {
        return nullptr;
    }
    auto *tsInterfaceDeclaration = tmpNode->AsTSInterfaceDeclaration();
    return tsInterfaceDeclaration->TsType();
}

static bool ValidateMethodAccessForClass(const ir::AstNode *ast, const ir::AstNode *ownerSignDeclNode,
                                         checker::Signature *signature, const ir::AstNode *memberObjTypeDeclNode)
{
    // Check if the method is used where it is declared
    if (IsContainedIn<const ir::AstNode>(ast, ownerSignDeclNode)) {
        return true;
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE)) {
        return false;
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::PROTECTED)) {
        // Check if the method is inherited and is used in class in which it is inherited
        auto *classDefinitionType = GetClassDefinitionType(ast);
        if (classDefinitionType == nullptr || !classDefinitionType->IsETSObjectType()) {
            return false;
        }
        auto *classObjectType = classDefinitionType->AsETSObjectType();
        return classObjectType->IsDescendantOf(signature->Owner());
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::INTERNAL)) {
        return IsVisibleInternalNode(ast, memberObjTypeDeclNode);
    }
    return true;
}

static bool ValidateMethodAccessForTSInterface(const ir::AstNode *ast, const ir::AstNode *ownerSignDeclNode,
                                               checker::Signature *signature, const ir::AstNode *memberObjTypeDeclNode)
{
    // Check if the method is used where it is declared
    if (IsContainedIn<const ir::AstNode>(ast, ownerSignDeclNode)) {
        return true;
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::PRIVATE)) {
        return false;
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::PROTECTED)) {
        // Check if the method is inherited and is used in class in which it is inherited
        auto *tsInterfaceDeclarationType = GetTSInterfaceDeclarationType(ast);
        if (tsInterfaceDeclarationType == nullptr || !tsInterfaceDeclarationType->IsETSObjectType()) {
            return false;
        }
        auto *tsInterfaceObjectType = tsInterfaceDeclarationType->AsETSObjectType();
        return tsInterfaceObjectType->IsDescendantOf(signature->Owner());
    }
    if (signature->HasSignatureFlag(checker::SignatureFlags::INTERNAL)) {
        return IsVisibleInternalNode(ast, memberObjTypeDeclNode);
    }
    return true;
}

static bool ValidatePropertyAccessForClass(const ir::AstNode *ast, const ir::AstNode *propVarDeclNode,
                                           const ir::AstNode *propVarDeclNodeParent,
                                           const varbinder::LocalVariable *propVar, const ir::AstNode *objTypeDeclNode)
{
    // Check if the variable is used where it is declared
    if (IsContainedIn<const ir::AstNode>(ast, propVarDeclNodeParent)) {
        return true;
    }
    if (propVarDeclNode->IsPrivate()) {
        return false;
    }
    if (propVarDeclNode->IsProtected()) {
        auto *classDefinitionType = GetClassDefinitionType(ast);
        if (classDefinitionType == nullptr || !classDefinitionType->IsETSObjectType()) {
            return false;
        }
        auto *classObjectType = classDefinitionType->AsETSObjectType();
        return classObjectType->IsPropertyOfAscendant(propVar);
    }
    if (propVarDeclNode->IsInternal()) {
        return IsVisibleInternalNode(ast, objTypeDeclNode);
    }
    return true;
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
    if (objTypeDeclNode->Parent() != nullptr && objTypeDeclNode->Parent()->IsImportNamespaceSpecifier()) {
        return true;
    }
    const auto *propVarDeclNodeParent = propVarDeclNode->Parent();
    if (propVarDeclNodeParent == nullptr) {
        return false;
    }
    if (propVarDeclNodeParent->IsClassDefinition() && objTypeDeclNode->IsClassDefinition()) {
        return ValidatePropertyAccessForClass(ast, propVarDeclNode, propVarDeclNodeParent, propVar, objTypeDeclNode);
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
    if (memberObjTypeDeclNode->Parent() != nullptr && memberObjTypeDeclNode->Parent()->IsImportNamespaceSpecifier()) {
        return true;
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
    if (ownerSignDeclNode == nullptr) {
        return false;
    }
    if (!ownerSignDeclNode->IsClassDefinition() && !ownerSignDeclNode->IsTSInterfaceDeclaration()) {
        return false;
    }
    bool ret = false;
    if (memberObjTypeDeclNode->IsClassDefinition()) {
        ret = ValidateMethodAccessForClass(ast, ownerSignDeclNode, signature, memberObjTypeDeclNode);
    } else if (memberObjTypeDeclNode->IsTSInterfaceDeclaration()) {
        ret = ValidateMethodAccessForTSInterface(ast, ownerSignDeclNode, signature, memberObjTypeDeclNode);
    }
    return ret;
}

class NodeHasParent {
public:
    explicit NodeHasParent([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        const auto isEtsScript =
            ast->IsETSScript() || (ast->IsBlockStatement() && ast->AsBlockStatement()->IsProgram());
        const auto hasParent = ast->Parent() != nullptr;
        if (!isEtsScript && !hasParent) {
            ctx.AddCheckMessage("NULL_PARENT", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        if (ast->IsProgram()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

class NodeHasSourceRange {
public:
    explicit NodeHasSourceRange([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        const auto hasRange =
            ast->Start().line != 0 || ast->Start().index != 0 || ast->End().line != 0 || ast->End().index != 0;
        if (!hasRange) {
            ctx.AddCheckMessage("NULL_RANGE", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

class IdentifierHasVariable {
public:
    explicit IdentifierHasVariable([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        if (ast->AsIdentifier()->Variable() != nullptr) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        /*
         * NOTICE: That is temporary fix for identifies without variable
         *         That should be removed in future after fix issues in
         *         varbinder and checker
         */
        if (ast->AsIdentifier()->Variable() != nullptr || ast->AsIdentifier()->IsReference() ||
            ast->AsIdentifier()->Name().Empty() || ast->AsIdentifier()->Name() == "Void" ||
            ast->AsIdentifier()->Name().Utf8().find("lambda$invoke$") == 0 ||
            (ast->AsIdentifier()->Parent() != nullptr && ast->AsIdentifier()->Parent()->IsProperty())) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        const auto *id = ast->AsIdentifier();
        ctx.AddCheckMessage("NULL_VARIABLE", *id, id->Start());
        return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
    }

private:
};

class NodeHasType {
public:
    explicit NodeHasType([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        // NOTE(orlovskymaxim) In TS some ETS constructs are expressions (i.e. class/interface definition)
        // Because ETS uses some AST classes from TS this introduces semantical problem
        // Solution for now - manually filter expressions that are statements in ETS
        if (ast->IsETSPackageDeclaration()) {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (IsImportLike(ast)) {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (IsExportLike(ast)) {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }

        if (ast->IsTSTypeAliasDeclaration()) {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (auto [decision, action] = CheckCompound(ctx, ast); action == CheckAction::SKIP_SUBTREE) {
            return {decision, action};
        }

        if (ast->IsTyped() && ast->IsExpression()) {
            if (ast->IsClassDefinition() && ast->AsClassDefinition()->Ident()->Name() == "ETSGLOBAL") {
                return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
            }
            if (ast->IsIdentifier() && ast->AsIdentifier()->Name() == "") {
                return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
            }
            const auto *typed = static_cast<const ir::TypedAstNode *>(ast);
            if (typed->TsType() == nullptr) {
                ctx.AddCheckMessage("NULL_TS_TYPE", *ast, ast->Start());
                return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

private:
    bool IsImportLike(const ir::AstNode *ast) const
    {
        if (ast->IsETSImportDeclaration()) {
            return true;
        }
        if (ast->IsETSReExportDeclaration()) {
            return true;
        }
        if (ast->IsImportExpression()) {
            return true;
        }
        if (ast->IsImportSpecifier()) {
            return true;
        }
        if (ast->IsImportDefaultSpecifier()) {
            return true;
        }
        if (ast->IsImportNamespaceSpecifier()) {
            return true;
        }
        return false;
    }

    bool IsExportLike(const ir::AstNode *ast) const
    {
        if (ast->IsExportDefaultDeclaration()) {
            return true;
        }
        if (ast->IsExportSpecifier()) {
            return true;
        }
        if (ast->IsExportAllDeclaration()) {
            return true;
        }
        if (ast->IsExportNamedDeclaration()) {
            return true;
        }
        if (ast->IsETSReExportDeclaration()) {
            return true;
        }
        return false;
    }

    CheckResult CheckCompound(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (ast->IsTSInterfaceDeclaration()) {
            for (const auto &member : ast->AsTSInterfaceDeclaration()->Body()->Body()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsTSEnumDeclaration()) {
            for (const auto &member : ast->AsTSEnumDeclaration()->Members()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsClassDefinition()) {
            for (const auto &member : ast->AsClassDefinition()->Body()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

class VariableHasScope {
public:
    explicit VariableHasScope(ArenaAllocator &allocator) : allocator_ {allocator} {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};  // we will check invariant of Identifier only
        }

        /*
         * NOTICE: That is temporary exclusion for identifies without variable
         *         Should removed in future
         */
        if (ast->AsIdentifier()->IsReference() || ast->AsIdentifier()->TypeAnnotation() != nullptr ||
            ast->AsIdentifier()->Name().Empty() || ast->AsIdentifier()->Name().Utf8().find("Void") == 0 ||
            ast->AsIdentifier()->Name().Utf8().find("lambda$invoke$") == 0 ||
            (ast->AsIdentifier()->Parent() != nullptr && ast->AsIdentifier()->Parent()->IsProperty())) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        // we will check invariant for only local variables of identifiers
        if (const auto maybeVar = GetLocalScopeVariable(allocator_, ctx, ast); maybeVar.has_value()) {
            const auto var = *maybeVar;
            const auto scope = var->GetScope();
            if (scope == nullptr) {
                ctx.AddCheckMessage("NULL_SCOPE_LOCAL_VAR", *ast, ast->Start());
                return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
            if (!ScopeEncloseVariable(ctx, var)) {
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            return result;
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    static std::optional<varbinder::LocalVariable *> GetLocalScopeVariable(ArenaAllocator &allocator, CheckContext &ctx,
                                                                           const ir::AstNode *ast)
    {
        if (!ast->IsIdentifier()) {
            return std::nullopt;
        }

        /*
         * NOTICE: That is temporary exclusion for identifies without variable and scope
         *         Should removed in future
         */
        if (ast->AsIdentifier()->IsReference() || ast->AsIdentifier()->TypeAnnotation() != nullptr ||
            ast->AsIdentifier()->Name().Empty() || ast->AsIdentifier()->Name().Utf8().find("Void") == 0 ||
            ast->AsIdentifier()->Name().Utf8().find("field") == 0 ||
            ast->AsIdentifier()->Name().Utf8().find("lambda$invoke$") == 0 ||
            (ast->AsIdentifier()->Parent() != nullptr && ast->AsIdentifier()->Parent()->IsProperty())) {
            return std::nullopt;
        }

        auto invariantHasVariable = IdentifierHasVariable {allocator};
        const auto variable = ast->AsIdentifier()->Variable();
        const auto [decision, action] = invariantHasVariable(ctx, ast);
        if (decision == CheckDecision::CORRECT && variable->IsLocalVariable()) {
            const auto localVar = variable->AsLocalVariable();
            if (localVar->HasFlag(varbinder::VariableFlags::LOCAL)) {
                return localVar;
            }
        }
        return std::nullopt;
    }

    bool ScopeEncloseVariable(CheckContext &ctx, const varbinder::LocalVariable *var)
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
            ctx.AddCheckMessage("SCOPE_DO_NOT_ENCLOSE_LOCAL_VAR", *node, varStart);
            isOk = false;
        }
        const auto scopeNode = scope->Node();
        auto varNode = node;
        if (!IsContainedIn(varNode, scopeNode) || scopeNode == nullptr) {
            ctx.AddCheckMessage("SCOPE_NODE_DONT_DOMINATE_VAR_NODE", *node, varStart);
            isOk = false;
        }
        const auto &decls = scope->Decls();
        const auto declDominate = std::count(decls.begin(), decls.end(), var->Declaration());
        if (declDominate == 0) {
            ctx.AddCheckMessage("SCOPE_DECL_DONT_DOMINATE_VAR_DECL", *node, varStart);
            isOk = false;
        }
        return isOk;
    }

private:
    ArenaAllocator &allocator_;
};

class EveryChildInParentRange {
public:
    explicit EveryChildInParentRange([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        if (ast->Parent() == nullptr) {
            return result;
        }
        ast->Iterate([&](const ir::AstNode *node) {
            if (ast != node->Parent()) {
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            if (ast->Start().line > node->Start().line || ast->End().line < node->End().line) {
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            if (ast->Start().line == node->Start().line && ast->Start().index > node->Start().index) {
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            if (ast->End().line == node->End().line && ast->End().index < node->End().index) {
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            ctx.AddCheckMessage("INCORRECT_CHILD_RANGE", *node, node->Start());
        });
        return result;
    }

private:
};

class EveryChildHasValidParent {
public:
    explicit EveryChildHasValidParent([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        if (ast->IsETSScript()) {
            return result;
        }

        ast->Iterate([&](const ir::AstNode *node) {
            if (ir::AstNode const *parent = node->Parent(); ast != parent) {
                //  NOTE: Temporary suppress.
                //  Should be removed after special lowering for lambda-functions will be implemented: #14376
                if ((ast->IsScriptFunction() || ast->IsETSFunctionType()) && parent != nullptr &&
                    parent->IsScriptFunction()) {
                    return;
                }

                //  NOTE: Temporary suppress.
                //  Should be removed after new ENUMs support will be implemented: #14443
                if (ast->IsClassDeclaration() && parent != nullptr && parent->IsETSNewClassInstanceExpression()) {
                    return;
                }

                ctx.AddCheckMessage("INCORRECT_PARENT_REF", *node, node->Start());
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
        });

        return result;
    }

private:
};

class VariableHasEnclosingScope {
public:
    explicit VariableHasEnclosingScope(ArenaAllocator &allocator) : allocator_ {allocator} {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        const auto maybeVar = VariableHasScope::GetLocalScopeVariable(allocator_, ctx, ast);
        if (!maybeVar) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        const auto var = *maybeVar;
        const auto scope = var->GetScope();
        if (scope == nullptr) {
            // already checked
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        const auto encloseScope = scope->EnclosingVariableScope();
        if (encloseScope == nullptr) {
            ctx.AddCheckMessage("NO_ENCLOSING_VAR_SCOPE", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        const auto node = scope->Node();
        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        if (!IsContainedIn(ast, node)) {
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            ctx.AddCheckMessage("VARIABLE_NOT_ENCLOSE_SCOPE", *ast, ast->Start());
        }
        if (!IsContainedIn<varbinder::Scope>(scope, encloseScope)) {
            result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            ctx.AddCheckMessage("VARIABLE_NOT_ENCLOSE_SCOPE", *ast, ast->Start());
        }
        return result;
    }

private:
    ArenaAllocator &allocator_;
};

class SequenceExpressionHasLastType {
public:
    explicit SequenceExpressionHasLastType([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsSequenceExpression()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        const auto *expr = ast->AsSequenceExpression();
        const auto *last = expr->Sequence().back();
        if (expr->TsType() == nullptr) {
            ctx.AddCheckMessage("Sequence expression type is null", *expr, expr->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        if (last->TsType() == nullptr) {
            ctx.AddCheckMessage("Sequence expression last type is null", *last, last->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        if (expr->TsType() != last->TsType()) {
            ctx.AddCheckMessage("Sequence expression type and last expression type are not the same", *expr,
                                expr->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

private:
};

class ForLoopCorrectlyInitialized {
public:
    explicit ForLoopCorrectlyInitialized([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (ast->IsForInStatement()) {
            return HandleForInStatement(ctx, ast);
        }

        if (ast->IsForOfStatement()) {
            return HandleForOfStatement(ctx, ast);
        }

        if (ast->IsForUpdateStatement()) {
            return HandleForUpdateStatement(ctx, ast);
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

private:
    [[nodiscard]] CheckResult HandleForInStatement(CheckContext &ctx, const ir::AstNode *ast)
    {
        auto const *left = ast->AsForInStatement()->Left();
        if (left == nullptr) {
            ctx.AddCheckMessage("NULL FOR-IN-LEFT", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
            ctx.AddCheckMessage("INCORRECT FOR-IN-LEFT", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    [[nodiscard]] CheckResult HandleForOfStatement(CheckContext &ctx, const ir::AstNode *ast)
    {
        auto const *left = ast->AsForOfStatement()->Left();
        if (left == nullptr) {
            ctx.AddCheckMessage("NULL FOR-OF-LEFT", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        if (!left->IsIdentifier() && !left->IsVariableDeclaration()) {
            ctx.AddCheckMessage("INCORRECT FOR-OF-LEFT", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    [[nodiscard]] CheckResult HandleForUpdateStatement(CheckContext &ctx, const ir::AstNode *ast)
    {
        // The most important part of for-loop is the test.
        // But it also can be null. Then there must be break;(return) in the body.
        auto const *test = ast->AsForUpdateStatement()->Test();
        if (test == nullptr) {
            auto const *body = ast->AsForUpdateStatement()->Body();
            if (body == nullptr) {
                ctx.AddCheckMessage("NULL FOR-TEST AND FOR-BODY", *ast, ast->Start());
                return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
            bool hasExit = body->IsBreakStatement() || body->IsReturnStatement();
            body->IterateRecursively(
                [&hasExit](ir::AstNode *child) { hasExit |= child->IsBreakStatement() || child->IsReturnStatement(); });
            if (!hasExit) {
                // an infinite loop
                ctx.AddCheckMessage("NULL FOR-TEST AND FOR-BODY doesn't exit", *ast, ast->Start());
            }
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }

        if (!test->IsExpression()) {
            ctx.AddCheckMessage("NULL FOR VAR", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }

        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

class ModifierAccessValid {
public:
    explicit ModifierAccessValid([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (auto [decision, action] = HandleMethodExpression(ctx, ast); decision == CheckDecision::INCORRECT) {
            return {decision, action};
        }
        if (auto [decision, action] = HandleCallExpression(ctx, ast); decision == CheckDecision::INCORRECT) {
            return {decision, action};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

private:
    CheckResult HandleMethodExpression(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsMemberExpression()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        const auto *propVar = ast->AsMemberExpression()->PropVar();
        if (propVar != nullptr && propVar->HasFlag(varbinder::VariableFlags::PROPERTY) &&
            !ValidateVariableAccess(propVar, ast->AsMemberExpression())) {
            ctx.AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    CheckResult HandleCallExpression(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (!ast->IsCallExpression()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        const auto *callExpr = ast->AsCallExpression();
        const auto *callee = callExpr->Callee();
        if (callee != nullptr && callee->IsMemberExpression()) {
            const auto *calleeMember = callee->AsMemberExpression();
            const auto *propVarCallee = calleeMember->PropVar();
            if (propVarCallee != nullptr && propVarCallee->HasFlag(varbinder::VariableFlags::METHOD) &&
                !ValidateMethodAccess(calleeMember, ast->AsCallExpression())) {
                ctx.AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE", *callee, callee->Start());
                return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

class ImportExportAccessValid {
public:
    explicit ImportExportAccessValid([[maybe_unused]] ArenaAllocator &allocator) {}

    [[nodiscard]] CheckResult operator()(CheckContext &ctx, const ir::AstNode *ast)
    {
        std::unordered_set<std::string> importedVariables {};
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
        if (ast->IsCallExpression()) {
            const auto *callExpr = ast->AsCallExpression();
            const auto *callee = callExpr->Callee();
            if (callee != nullptr && callee->IsIdentifier() &&
                !HandleImportExportIdentifier(importedVariables, callee->AsIdentifier(), callExpr)) {
                ctx.AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED)", *callee, callee->Start());
                return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
        }
        if (ast->IsIdentifier() && !HandleImportExportIdentifier(importedVariables, ast->AsIdentifier(), nullptr)) {
            ctx.AddCheckMessage("PROPERTY_NOT_VISIBLE_HERE(NOT_EXPORTED)", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
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

    bool InvariantImportExportMethod(const std::unordered_set<std::string> &importedVariables,
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

    bool InvariantImportExportVariable(const std::unordered_set<std::string> &importedVariables,
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

    bool HandleImportExportIdentifier(std::unordered_set<std::string> &importedVariables, const ir::Identifier *ident,
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

    [[nodiscard]] CheckResult operator()([[maybe_unused]] CheckContext &ctx, const ir::AstNode *ast)
    {
        if (auto [decision, action] = CheckCompound(ctx, ast); action == CheckAction::SKIP_SUBTREE) {
            return {decision, action};
        }
        if (!ast->IsBinaryExpression() || !ast->AsBinaryExpression()->IsArithmetic()) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        if ((ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS ||
             ast->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS_EQUAL) &&
            (IsStringType(ast->AsBinaryExpression()->Left()) || IsStringType(ast->AsBinaryExpression()->Right()))) {
            return {CheckDecision::CORRECT, CheckAction::CONTINUE};
        }
        auto result = std::make_tuple(CheckDecision::CORRECT, CheckAction::CONTINUE);
        bool isBitwise = ast->AsBinaryExpression()->IsBitwise();
        ast->Iterate([&result, &ctx, &isBitwise](ir::AstNode *child) {
            if (!IsValidTypeForBinaryOp(child, isBitwise)) {
                ctx.AddCheckMessage("Not a numeric type", *child, child->Start());
                result = {CheckDecision::INCORRECT, CheckAction::CONTINUE};
            }
        });
        return result;
    }

private:
    CheckResult CheckCompound(CheckContext &ctx, const ir::AstNode *ast)
    {
        if (ast->IsTSInterfaceDeclaration()) {
            for (const auto &member : ast->AsTSInterfaceDeclaration()->Body()->Body()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsTSEnumDeclaration()) {
            for (const auto &member : ast->AsTSEnumDeclaration()->Members()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsClassDefinition()) {
            for (const auto &member : ast->AsClassDefinition()->Body()) {
                [[maybe_unused]] auto _ = (*this)(ctx, member);
            }
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }
};

ASTVerifier::ASTVerifier(ArenaAllocator *allocator)
{
    AddInvariant<NodeHasParent>(allocator, "NodeHasParent");
    AddInvariant<NodeHasSourceRange>(allocator, "NodeHasSourceRange");
    AddInvariant<NodeHasType>(allocator, "NodeHasType");
    AddInvariant<IdentifierHasVariable>(allocator, "IdentifierHasVariable");
    AddInvariant<VariableHasScope>(allocator, "VariableHasScope");
    AddInvariant<EveryChildHasValidParent>(allocator, "EveryChildHasValidParent");
    AddInvariant<EveryChildInParentRange>(allocator, "EveryChildInParentRange");
    AddInvariant<VariableHasEnclosingScope>(allocator, "VariableHasEnclosingScope");
    AddInvariant<ForLoopCorrectlyInitialized>(allocator, "ForLoopCorrectlyInitialized");
    AddInvariant<ModifierAccessValid>(allocator, "ModifierAccessValid");
    AddInvariant<ImportExportAccessValid>(allocator, "ImportExportAccessValid");
    AddInvariant<ArithmeticOperationValid>(allocator, "ArithmeticOperationValid");
    AddInvariant<SequenceExpressionHasLastType>(allocator, "SequenceExpressionHasLastType");
}

Messages ASTVerifier::VerifyFull(const ir::AstNode *ast)
{
    auto recursiveChecks = InvariantNameSet {};
    std::copy_if(invariantsNames_.begin(), invariantsNames_.end(),
                 std::inserter(recursiveChecks, recursiveChecks.end()),
                 [](const std::string &s) { return s.find(RECURSIVE_SUFFIX) != s.npos; });
    return Verify(ast, recursiveChecks);
}

Messages ASTVerifier::Verify(const ir::AstNode *ast, const InvariantNameSet &invariantSet)
{
    CheckContext ctx {};
    const auto containsInvariants =
        std::includes(invariantsNames_.begin(), invariantsNames_.end(), invariantSet.begin(), invariantSet.end());
    if (!containsInvariants) {
        auto invalidInvariants = InvariantNameSet {};
        for (const auto &invariant : invariantSet) {
            if (invariantsNames_.find(invariant) == invariantsNames_.end()) {
                invalidInvariants.insert(invariant);
            }
        }
        for (const auto &invariant : invalidInvariants) {
            ctx.AddCheckMessage(std::string {"Invariant was not found: "} + invariant, *ast, lexer::SourcePosition {});
        }
    }

    for (const auto &name : invariantSet) {
        if (const auto &found = invariantsChecks_.find(name); found != invariantsChecks_.end()) {
            if (ast == nullptr) {
                continue;
            }

            auto invariant = found->second;
            ctx.SetCheckName(name.data());
            invariant(ctx, ast);
        }
    }

    return ctx.GetMessages();
}

}  // namespace ark::es2panda::compiler::ast_verifier
