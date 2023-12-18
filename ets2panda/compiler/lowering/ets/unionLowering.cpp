/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
#include "compiler/core/compilerContext.h"
#include "compiler/lowering/util.h"
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

namespace panda::es2panda::compiler {
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
    auto *fieldIdent = allocator->New<ir::Identifier>(propName, allocator);

    // Create the synthetic class property node
    auto *field =
        allocator->New<ir::ClassProperty>(fieldIdent, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);

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
    node->SetParent(asExpression);
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
    unionAsRefExpression->SetBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxedPrim));
    unionNode->SetParent(unionAsRefExpression);

    auto *const refAsPrimExpression = GenAsExpression(checker, unboxedPrim, unionAsRefExpression, unionNode->Parent());
    unionAsRefExpression->SetParent(refAsPrimExpression);

    return refAsPrimExpression;
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

ir::BinaryExpression *GenInstanceofExpr(checker::ETSChecker *checker, ir::Expression *unionNode,
                                        checker::Type *constituentType)
{
    auto *const lhsExpr = unionNode->Clone(checker->Allocator())->AsExpression();
    lhsExpr->Check(checker);
    lhsExpr->SetBoxingUnboxingFlags(unionNode->GetBoxingUnboxingFlags());
    auto *rhsType = constituentType;
    if (!constituentType->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        checker->Relation()->SetNode(unionNode);
        rhsType = checker::conversion::Boxing(checker->Relation(), constituentType);
        checker->Relation()->SetNode(nullptr);
    }
    if (constituentType->IsETSStringType()) {
        rhsType = checker->GlobalBuiltinETSStringType();
    }
    ir::Expression *rhsExpr;
    if (rhsType->IsETSUndefinedType()) {
        rhsExpr = checker->Allocator()->New<ir::UndefinedLiteral>();
    } else if (rhsType->IsETSNullType()) {
        rhsExpr = checker->Allocator()->New<ir::NullLiteral>();
    } else {
        rhsExpr = checker->Allocator()->New<ir::Identifier>(rhsType->AsETSObjectType()->Name(), checker->Allocator());
        auto rhsVar = NearestScope(unionNode)->Find(rhsExpr->AsIdentifier()->Name());
        rhsExpr->AsIdentifier()->SetVariable(rhsVar.variable);
    }
    auto *const instanceofExpr =
        checker->Allocator()->New<ir::BinaryExpression>(rhsExpr, rhsExpr, lexer::TokenType::KEYW_INSTANCEOF);
    rhsExpr->SetParent(instanceofExpr);
    rhsExpr->SetParent(instanceofExpr);
    rhsExpr->SetTsType(rhsType);
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
    stmt->SetParent(localBlockStmt);
    localBlockStmt->SetRange(stmt->Range());
    localCtx.GetScope()->BindNode(localBlockStmt);
    return localBlockStmt;
}

ir::Expression *SetBoxFlagOrGenAsExpression(checker::ETSChecker *checker, checker::Type *constituentType,
                                            ir::Expression *otherNode)
{
    if (constituentType->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE) &&
        !otherNode->IsETSUnionType() && otherNode->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
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

ir::Expression *ProcessOperandsInBinaryExpr(checker::ETSChecker *checker, ir::BinaryExpression *expr,
                                            checker::Type *constituentType)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EQUAL ||
           expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    bool isLhsUnion;
    ir::Expression *unionNode =
        (isLhsUnion = expr->Left()->TsType()->IsETSUnionType()) ? expr->Left() : expr->Right();
    checker::Type *typeToCast = constituentType->IsETSNullLike()
                                      ? unionNode->TsType()->AsETSUnionType()->GetLeastUpperBoundType()
                                      : constituentType;
    auto *const asExpression = GenAsExpression(checker, typeToCast, unionNode, expr);
    if (isLhsUnion) {
        expr->SetLeft(asExpression);
        expr->SetRight(SetBoxFlagOrGenAsExpression(checker, constituentType, expr->Right()));
    } else {
        expr->SetRight(asExpression);
        expr->SetLeft(SetBoxFlagOrGenAsExpression(checker, constituentType, expr->Left()));
    }
    expr->SetOperationType(checker->GlobalETSObjectType());
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

void InsertInstanceofTreeBeforeStmt(ir::Statement *stmt, ir::VariableDeclaration *binaryVarDecl,
                                    ir::Statement *instanceofTree)
{
    if (stmt->IsVariableDeclarator()) {
        ASSERT(stmt->Parent()->IsVariableDeclaration());
        stmt = stmt->Parent()->AsVariableDeclaration();
    }
    ASSERT(stmt->Parent()->IsBlockStatement());
    auto *block = stmt->Parent()->AsBlockStatement();
    binaryVarDecl->SetParent(block);
    instanceofTree->SetParent(block);
    auto itStmt = std::find(block->Statements().begin(), block->Statements().end(), stmt);
    block->Statements().insert(itStmt, {binaryVarDecl, instanceofTree});
}

ir::BlockStatement *ReplaceBinaryExprInStmt(checker::ETSChecker *checker, ir::Expression *unionNode,
                                            ir::BlockStatement *block, ir::BinaryExpression *expr)
{
    auto *stmt = FindStatementFromNode(expr);
    ASSERT(stmt->IsVariableDeclarator() || block == stmt->Parent());  // statement with union
    auto *const binaryVarDecl = GenVariableDeclForBinaryExpr(checker, NearestScope(stmt), expr);
    auto *const varDeclId = binaryVarDecl->Declarators().front()->Id();  // only one declarator was generated
    ir::IfStatement *instanceofTree = nullptr;
    for (auto *uType : unionNode->TsType()->AsETSUnionType()->ConstituentTypes()) {
        auto *const test = GenInstanceofExpr(checker, unionNode, uType);
        auto *clonedBinary = expr->Clone(checker->Allocator(), expr->Parent())->AsBinaryExpression();
        clonedBinary->Check(checker);
        auto *const consequent = GenBlockStmtForAssignmentBinary(
            checker, varDeclId->AsIdentifier(), ProcessOperandsInBinaryExpr(checker, clonedBinary, uType));
        instanceofTree = checker->Allocator()->New<ir::IfStatement>(test, consequent, instanceofTree);
        test->SetParent(instanceofTree);
        consequent->SetParent(instanceofTree);
        if (instanceofTree->Alternate() != nullptr) {
            instanceofTree->Alternate()->SetParent(instanceofTree);
        }
    }
    ASSERT(instanceofTree != nullptr);
    // Replacing a binary expression with an identifier
    // that was set in one of the branches of the `instanceof_tree` tree
    stmt->TransformChildrenRecursively([varDeclId](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->OperationType() != nullptr &&
            ast->AsBinaryExpression()->OperationType()->IsETSUnionType()) {
            return varDeclId;
        }

        return ast;
    });
    InsertInstanceofTreeBeforeStmt(stmt, binaryVarDecl, instanceofTree);
    return block;
}

ir::BlockStatement *HandleBlockWithBinaryAndUnion(checker::ETSChecker *checker, ir::BlockStatement *block,
                                                  ir::BinaryExpression *binExpr)
{
    if (binExpr->OperatorType() != lexer::TokenType::PUNCTUATOR_EQUAL &&
        binExpr->OperatorType() != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        checker->ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.",
                                binExpr->Start());
    }
    ir::Expression *unionNode = binExpr->Left()->TsType()->IsETSUnionType() ? binExpr->Left() : binExpr->Right();
    return ReplaceBinaryExprInStmt(checker, unionNode, block, binExpr);
}

ir::BlockStatement *HandleBlockWithBinaryAndUnions(checker::ETSChecker *checker, ir::BlockStatement *block,
                                                   const ir::NodePredicate &handleBinary)
{
    ir::BlockStatement *modifiedAstBlock = block;
    while (modifiedAstBlock->IsAnyChild(handleBinary)) {
        modifiedAstBlock = HandleBlockWithBinaryAndUnion(
            checker, modifiedAstBlock, modifiedAstBlock->FindChild(handleBinary)->AsBinaryExpression());
    }
    return modifiedAstBlock;
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

    program->Ast()->TransformChildrenRecursively([checker](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr &&
            ast->AsMemberExpression()->Object()->TsType()->IsETSUnionType()) {
            HandleUnionPropertyAccess(checker, checker->VarBinder(), ast->AsMemberExpression());
            return ast;
        }

        if (ast->IsTSAsExpression() && ast->AsTSAsExpression()->Expr()->TsType() != nullptr &&
            ast->AsTSAsExpression()->Expr()->TsType()->IsETSUnionType() &&
            ast->AsTSAsExpression()->TsType() != nullptr &&
            ast->AsTSAsExpression()->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            return HandleUnionCastToPrimitive(checker, ast->AsTSAsExpression());
        }

        auto handleBinary = [](const ir::AstNode *astNode) {
            return astNode->IsBinaryExpression() && astNode->AsBinaryExpression()->OperationType() != nullptr &&
                   astNode->AsBinaryExpression()->OperationType()->IsETSUnionType();
        };
        if (ast->IsBlockStatement() && ast->IsAnyChild(handleBinary)) {
            return HandleBlockWithBinaryAndUnions(checker, ast->AsBlockStatement(), handleBinary);
        }

        return ast;
    });

    return true;
}

bool UnionLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    bool current = !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return ast->IsMemberExpression() && ast->AsMemberExpression()->Object()->TsType() != nullptr &&
               ast->AsMemberExpression()->Object()->TsType()->IsETSUnionType() &&
               ast->AsMemberExpression()->PropVar() == nullptr;
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

}  // namespace panda::es2panda::compiler
