/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "unionLowering.h"
#include "compiler/core/ASTVerifier.h"
#include "varbinder/variableFlags.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/conversion.h"
#include "checker/ets/boxingConverter.h"
#include "checker/ets/unboxingConverter.h"
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/astNode.h"
#include "ir/expression.h"
#include "ir/opaqueTypeNode.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/undefinedLiteral.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/ts/tsAsExpression.h"
#include "type_helper.h"

namespace ark::es2panda::compiler {
ir::ClassDefinition *GetUnionFieldClass(checker::ETSChecker *checker, varbinder::VarBinder *varbinder)
{
    // Create the name for the synthetic class node
    util::UString unionFieldClassName(util::StringView(panda_file::GetDummyClassName()), checker->Allocator());
    varbinder::Variable *foundVar = nullptr;
    if ((foundVar = checker->Scope()->FindLocal(unionFieldClassName.View(),
                                                varbinder::ResolveBindingOptions::BINDINGS)) != nullptr) {
        return foundVar->Declaration()->Node()->AsClassDeclaration()->Definition();
    }
    auto *ident = checker->AllocNode<ir::Identifier>(unionFieldClassName.View(), checker->Allocator());
    auto [decl, var] = varbinder->NewVarDecl<varbinder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto classCtx = varbinder::LexicalScope<varbinder::ClassScope>(varbinder);
    auto *classDef =
        checker->AllocNode<ir::ClassDefinition>(checker->Allocator(), ident, ir::ClassDefinitionModifiers::GLOBAL,
                                                ir::ModifierFlags::NONE, Language(Language::Id::ETS));
    classDef->SetScope(classCtx.GetScope());
    auto *classDecl = checker->AllocNode<ir::ClassDeclaration>(classDef, checker->Allocator());
    classDef->Scope()->BindNode(classDecl);
    classDef->SetTsType(checker->GlobalETSObjectType());
    decl->BindNode(classDecl);
    var->SetScope(classDef->Scope());

    varbinder->AsETSBinder()->BuildClassDefinition(classDef);
    return classDef;
}

varbinder::LocalVariable *CreateUnionFieldClassProperty(checker::ETSChecker *checker, varbinder::VarBinder *varbinder,
                                                        checker::Type *fieldType, const util::StringView &propName)
{
    auto *const allocator = checker->Allocator();
    auto *const dummyClass = GetUnionFieldClass(checker, varbinder);
    auto *classScope = dummyClass->Scope()->AsClassScope();

    // Enter the union filed class instance field scope
    auto fieldCtx = varbinder::LexicalScope<varbinder::LocalScope>::Enter(varbinder, classScope->InstanceFieldScope());

    if (auto *var = classScope->FindLocal(propName, varbinder::ResolveBindingOptions::VARIABLES); var != nullptr) {
        return var->AsLocalVariable();
    }

    // Create field name for synthetic class
    auto *fieldIdent = checker->AllocNode<ir::Identifier>(propName, allocator);

    // Create the synthetic class property node
    auto *field =
        checker->AllocNode<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);

    // Add the declaration to the scope
    auto [decl, var] = varbinder->NewVarDecl<varbinder::LetDecl>(fieldIdent->Start(), fieldIdent->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(fieldType);
    fieldIdent->SetVariable(var);
    field->SetTsType(fieldType);
    decl->BindNode(field);

    ArenaVector<ir::AstNode *> fieldDecl {allocator->Adapter()};
    fieldDecl.push_back(field);
    dummyClass->AddProperties(std::move(fieldDecl));
    return var->AsLocalVariable();
}

void HandleUnionPropertyAccess(checker::ETSChecker *checker, varbinder::VarBinder *vbind, ir::MemberExpression *expr)
{
    ASSERT(expr->PropVar() == nullptr);
    auto parent = expr->Parent();
    if (parent->IsCallExpression() &&
        !parent->AsCallExpression()->Signature()->HasSignatureFlag(checker::SignatureFlags::TYPE)) {
        return;
    }
    expr->SetPropVar(
        CreateUnionFieldClassProperty(checker, vbind, expr->TsType(), expr->Property()->AsIdentifier()->Name()));
    ASSERT(expr->PropVar() != nullptr);
}

ir::TSAsExpression *GenAsExpression(checker::ETSChecker *checker, checker::Type *const opaqueType,
                                    ir::Expression *const node, ir::AstNode *const parent)
{
    auto *const typeNode = checker->AllocNode<ir::OpaqueTypeNode>(opaqueType);
    auto *const asExpression = checker->AllocNode<ir::TSAsExpression>(node, typeNode, false);
    asExpression->SetParent(parent);
    asExpression->Check(checker);
    return asExpression;
}

/*
 *  Function that generates conversion from (union) to (primitive) type as to `as` expressions:
 *      (union) as (prim) => ((union) as (ref)) as (prim),
 *      where (ref) is some unboxable type from union constituent types.
 *  Finally, `(union) as (prim)` expression replaces union_node that came above.
 */
ir::TSAsExpression *UnionCastToPrimitive(checker::ETSChecker *checker, checker::ETSObjectType *unboxableRef,
                                         checker::Type *unboxedPrim, ir::Expression *unionNode)
{
    auto *const unionAsRefExpression = GenAsExpression(checker, unboxableRef, unionNode, nullptr);
    return GenAsExpression(checker, unboxedPrim, unionAsRefExpression, unionNode->Parent());
}

ir::TSAsExpression *HandleUnionCastToPrimitive(checker::ETSChecker *checker, ir::TSAsExpression *expr)
{
    auto *const unionType = expr->Expr()->TsType()->AsETSUnionType();
    auto *sourceType = unionType->FindExactOrBoxedType(checker, expr->TsType());
    if (sourceType == nullptr) {
        sourceType = unionType->AsETSUnionType()->FindTypeIsCastableToSomeType(expr->Expr(), checker->Relation(),
                                                                               expr->TsType());
    }
    if (sourceType != nullptr && expr->Expr()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
        if (expr->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            auto *const asExpr = GenAsExpression(checker, sourceType, expr->Expr(), expr);
            asExpr->SetBoxingUnboxingFlags(
                checker->GetUnboxingFlag(checker->ETSBuiltinTypeAsPrimitiveType(sourceType)));
            expr->Expr()->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
            expr->SetExpr(asExpr);
        }
        return expr;
    }
    auto *const unboxableUnionType = sourceType != nullptr ? sourceType : unionType->FindUnboxableType();
    auto *const unboxedUnionType = checker->ETSBuiltinTypeAsPrimitiveType(unboxableUnionType);
    expr->SetExpr(UnionCastToPrimitive(checker, unboxableUnionType->AsETSObjectType(), unboxedUnionType, expr->Expr()));
    return expr;
}

ir::BinaryExpression *GenInstanceofExpr(checker::ETSChecker *checker, ir::Identifier *unionNode,
                                        checker::Type *constituentType)
{
    auto *const lhsExpr = unionNode->Clone(checker->Allocator(), nullptr)->AsExpression();
    lhsExpr->Check(checker);
    lhsExpr->SetBoxingUnboxingFlags(unionNode->GetBoxingUnboxingFlags());
    auto *const rhsExpr = checker->AllocNode<ir::OpaqueTypeNode>(constituentType);
    auto *const instanceofExpr =
        checker->AllocNode<ir::BinaryExpression>(lhsExpr, rhsExpr, lexer::TokenType::KEYW_INSTANCEOF);
    instanceofExpr->SetOperationType(checker->GlobalETSObjectType());
    instanceofExpr->SetTsType(checker->GlobalETSBooleanType());
    return instanceofExpr;
}

ir::VariableDeclaration *GenVariableDeclForBinaryExpr(checker::ETSChecker *checker, varbinder::Scope *scope,
                                                      ir::BinaryExpression *expr)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EQUAL ||
           expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    auto *varId = Gensym(checker->Allocator());
    auto *var = scope->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(checker->Allocator(), varId->Name(),
                                                                             varbinder::VariableFlags::LOCAL);
    var->SetTsType(checker->GlobalETSBooleanType());
    varId->SetVariable(var);
    varId->SetTsType(var->TsType());

    auto declarator = checker->AllocNode<ir::VariableDeclarator>(ir::VariableDeclaratorFlag::LET, varId);
    declarator->SetInit(
        checker->AllocNode<ir::BooleanLiteral>(expr->OperatorType() != lexer::TokenType::PUNCTUATOR_EQUAL));
    declarator->Init()->Check(checker);
    ArenaVector<ir::VariableDeclarator *> declarators(checker->Allocator()->Adapter());
    declarators.push_back(declarator);

    auto varKind = ir::VariableDeclaration::VariableDeclarationKind::LET;
    auto *binaryVarDecl =
        checker->AllocNode<ir::VariableDeclaration>(varKind, checker->Allocator(), std::move(declarators), false);
    binaryVarDecl->SetRange({expr->Start(), expr->End()});
    return binaryVarDecl;
}

ir::ExpressionStatement *GenExpressionStmtWithAssignment(checker::ETSChecker *checker, ir::Identifier *varDeclId,
                                                         ir::Expression *expr)
{
    auto *assignmentForBinary =
        checker->AllocNode<ir::AssignmentExpression>(varDeclId, expr, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignmentForBinary->SetTsType(expr->TsType());
    return checker->AllocNode<ir::ExpressionStatement>(assignmentForBinary);
}

ir::BlockStatement *GenBlockStmtForAssignmentBinary(checker::ETSChecker *checker, ir::Identifier *varDeclId,
                                                    ir::Expression *expr)
{
    auto localCtx = varbinder::LexicalScope<varbinder::LocalScope>(checker->VarBinder());
    ArenaVector<ir::Statement *> stmts(checker->Allocator()->Adapter());
    auto *stmt = GenExpressionStmtWithAssignment(checker, varDeclId, expr);
    stmts.push_back(stmt);
    auto *const localBlockStmt = checker->AllocNode<ir::BlockStatement>(checker->Allocator(), std::move(stmts));
    localBlockStmt->SetScope(localCtx.GetScope());
    localBlockStmt->SetRange(stmt->Range());
    localCtx.GetScope()->BindNode(localBlockStmt);
    return localBlockStmt;
}

ir::Expression *SetBoxFlagOrGenAsExpression(checker::ETSChecker *checker, checker::Type *constituentType,
                                            ir::Expression *otherNode)
{
    if (constituentType->IsETSObjectType() &&
        constituentType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE) &&
        otherNode->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        auto *unboxedConstituentType = checker->ETSBuiltinTypeAsPrimitiveType(constituentType);
        if (unboxedConstituentType != otherNode->TsType()) {
            auto *const primAsExpression =
                GenAsExpression(checker, unboxedConstituentType, otherNode, otherNode->Parent());
            primAsExpression->SetBoxingUnboxingFlags(checker->GetBoxingFlag(constituentType));
            return primAsExpression;
        }
        return otherNode;
    }
    if (otherNode->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        otherNode->SetBoxingUnboxingFlags(
            checker->GetBoxingFlag(checker::BoxingConverter::ETSTypeFromSource(checker, otherNode->TsType())));
    }
    return otherNode;
}

ir::Expression *ProcessOperandsInBinaryExpr(checker::ETSChecker *checker, ir::BinaryExpression *expr, bool isLhsUnion,
                                            checker::ETSObjectType *constituentType)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EQUAL ||
           expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    if (isLhsUnion) {
        expr->SetLeft(UnionCastToPrimitive(checker, constituentType, expr->Right()->TsType(), expr->Left()));
    } else {
        expr->SetRight(UnionCastToPrimitive(checker, constituentType, expr->Left()->TsType(), expr->Right()));
    }
    ASSERT(expr->Right()->TsType() == expr->Left()->TsType());
    expr->SetOperationType(expr->Right()->TsType());
    expr->SetTsType(checker->GlobalETSBooleanType());
    return expr;
}

ir::Statement *FindStatementFromNode(ir::Expression *expr)
{
    ir::AstNode *node = expr;
    while (!node->IsStatement()) {
        node = node->Parent();
    }
    ASSERT(node->IsStatement());
    return node->AsStatement();
}

static void InsertAfterStmt(ir::Statement *stmt, ir::Statement *ins)
{
    if (stmt->IsVariableDeclarator()) {
        ASSERT(stmt->Parent()->IsVariableDeclaration());
        stmt = stmt->Parent()->AsVariableDeclaration();
    }
    ASSERT(stmt->Parent()->IsBlockStatement());
    auto *block = stmt->Parent()->AsBlockStatement();
    ins->SetParent(block);
    auto itStmt = std::find(block->Statements().begin(), block->Statements().end(), stmt);
    block->Statements().insert(itStmt, ins);
}

static ir::Identifier *CreatePrecomputedTemporary(public_lib::Context *ctx, ir::Statement *pos, ir::Expression *expr)
{
    auto *const allocator = ctx->allocator;
    auto *const checker = ctx->checker->AsETSChecker();
    auto *const parser = ctx->parser->AsETSParser();
    auto *const varbinder = ctx->compilerContext->VarBinder();

    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder, NearestScope(expr));

    auto *const temp = Gensym(allocator);

    auto *const vardecl = parser->CreateFormattedStatements("let @@I1: @@T2;", parser::DEFAULT_SOURCE_FILE, temp,
                                                            checker->AllocNode<ir::OpaqueTypeNode>(expr->TsType()))[0];

    InsertAfterStmt(pos, vardecl);
    InitScopesPhaseETS::RunExternalNode(vardecl, varbinder);
    vardecl->AsVariableDeclaration()->Declarators()[0]->SetInit(expr);
    vardecl->Check(checker);

    auto *cloned = temp->Clone(allocator, nullptr);
    cloned->Check(checker);
    return cloned;
}

static ir::BlockStatement *ReplaceBinaryExprInStmt(public_lib::Context *ctx, ir::BlockStatement *block,
                                                   ir::BinaryExpression *expr)
{
    auto *const checker = ctx->checker->AsETSChecker();

    auto *stmt = FindStatementFromNode(expr);
    ASSERT(stmt->IsVariableDeclarator() || block == stmt->Parent());  // statement with union
    auto *const binaryVarDecl = GenVariableDeclForBinaryExpr(checker, NearestScope(stmt), expr);
    auto *const varDeclId = binaryVarDecl->Declarators().front()->Id();  // only one declarator was generated
    ir::IfStatement *instanceofTree = nullptr;

    expr->SetLeft(CreatePrecomputedTemporary(ctx, stmt, expr->Left()));
    expr->SetRight(CreatePrecomputedTemporary(ctx, stmt, expr->Right()));

    bool isLhsUnion = expr->Left()->TsType()->IsETSUnionType();
    auto *const unionNode = isLhsUnion ? expr->Left() : expr->Right();

    for (auto *uType : unionNode->TsType()->AsETSUnionType()->ConstituentTypes()) {
        if (!uType->IsETSObjectType() ||
            !uType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE)) {
            continue;
        }
        auto *const test = GenInstanceofExpr(checker, unionNode->AsIdentifier(), uType);
        auto *clonedBinary = expr->Clone(checker->Allocator(), expr->Parent())->AsBinaryExpression();
        clonedBinary->Check(checker);
        auto *const consequent = GenBlockStmtForAssignmentBinary(
            checker, varDeclId->AsIdentifier()->Clone(checker->Allocator(), nullptr),
            ProcessOperandsInBinaryExpr(checker, clonedBinary, isLhsUnion, uType->AsETSObjectType()));
        instanceofTree = checker->AllocNode<ir::IfStatement>(test, consequent, instanceofTree);
    }
    ASSERT(instanceofTree != nullptr);
    // Replacing a binary expression with an identifier
    // that was set in one of the branches of the `instanceof_tree` tree
    stmt->TransformChildrenRecursively([varDeclId, checker](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->OperationType() != nullptr &&
            ast->AsBinaryExpression()->OperationType()->IsETSUnionType()) {
            auto cloned = varDeclId->Clone(checker->Allocator(), ast->Parent());
            cloned->Check(checker);
            return cloned;
        }

        return ast;
    });
    InsertAfterStmt(stmt, binaryVarDecl);
    InsertAfterStmt(stmt, instanceofTree);
    return block;
}

ir::BlockStatement *HandleBlockWithBinaryAndUnion(public_lib::Context *ctx, ir::BlockStatement *block,
                                                  ir::BinaryExpression *binExpr)
{
    if (binExpr->OperatorType() != lexer::TokenType::PUNCTUATOR_EQUAL &&
        binExpr->OperatorType() != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        ctx->checker->ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.",
                                     binExpr->Start());
    }
    return ReplaceBinaryExprInStmt(ctx, block, binExpr);
}

ir::BlockStatement *HandleBlockWithBinaryAndUnions(public_lib::Context *ctx, ir::BlockStatement *block,
                                                   const ir::NodePredicate &handleBinary)
{
    ir::BlockStatement *modifiedAstBlock = block;
    while (modifiedAstBlock->IsAnyChild(handleBinary)) {
        modifiedAstBlock = HandleBlockWithBinaryAndUnion(
            ctx, modifiedAstBlock, modifiedAstBlock->FindChild(handleBinary)->AsBinaryExpression());
    }
    return modifiedAstBlock;
}

static bool BinaryLoweringAppliable(const ir::AstNode *astNode)
{
    if (!astNode->IsBinaryExpression()) {
        return false;
    }
    auto *binary = astNode->AsBinaryExpression();
    if (binary->OperatorType() == lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING) {
        return false;
    }
    auto *const lhsType = binary->Left()->TsType();
    auto *const rhsType = binary->Right()->TsType();
    if (lhsType == nullptr || rhsType == nullptr) {
        return false;
    }
    if (lhsType->IsETSReferenceType() && rhsType->IsETSReferenceType()) {
        return false;
    }
    if (!lhsType->IsETSUnionType() && !rhsType->IsETSUnionType()) {
        return false;
    }
    return binary->OperationType() != nullptr && binary->OperationType()->IsETSUnionType();
}

bool UnionLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([checker, ctx](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr) {
            auto *objType =
                checker->GetApparentType(checker->GetNonNullishType(ast->AsMemberExpression()->Object()->TsType()));
            if (objType->IsETSUnionType()) {
                HandleUnionPropertyAccess(checker, checker->VarBinder(), ast->AsMemberExpression());
                return ast;
            }
        }

        if (ast->IsTSAsExpression() && ast->AsTSAsExpression()->Expr()->TsType() != nullptr &&
            ast->AsTSAsExpression()->Expr()->TsType()->IsETSUnionType() &&
            ast->AsTSAsExpression()->TsType() != nullptr &&
            ast->AsTSAsExpression()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            return HandleUnionCastToPrimitive(checker, ast->AsTSAsExpression());
        }

        if (ast->IsBlockStatement() && ast->IsAnyChild(BinaryLoweringAppliable)) {
            return HandleBlockWithBinaryAndUnions(ctx, ast->AsBlockStatement(), BinaryLoweringAppliable);
        }

        return ast;
    });

    return true;
}

bool UnionLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    bool current = !program->Ast()->IsAnyChild([checker = ctx->checker->AsETSChecker()](ir::AstNode *ast) {
        if (!ast->IsMemberExpression() || ast->AsMemberExpression()->Object()->TsType() == nullptr) {
            return false;
        }
        auto *objType =
            checker->GetApparentType(checker->GetNonNullishType(ast->AsMemberExpression()->Object()->TsType()));
        auto *parent = ast->Parent();
        if (!(parent->IsCallExpression() &&
              parent->AsCallExpression()->Signature()->HasSignatureFlag(checker::SignatureFlags::TYPE))) {
            return false;
        }
        return objType->IsETSUnionType() && ast->AsMemberExpression()->PropVar() == nullptr;
    });
    if (!current || ctx->compilerContext->Options()->compilationMode != CompilationMode::GEN_STD_LIB) {
        return current;
    }

    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace ark::es2panda::compiler
