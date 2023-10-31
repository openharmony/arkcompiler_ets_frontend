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
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/ts/tsAsExpression.h"
#include "type_helper.h"

namespace panda::es2panda::compiler {

std::string_view UnionLowering::Name()
{
    return "union-property-access";
}

ir::ClassDefinition *GetUnionFieldClass(checker::ETSChecker *checker, varbinder::VarBinder *varbinder)
{
    // Create the name for the synthetic class node
    util::UString union_field_class_name(util::StringView(panda_file::GetDummyClassName()), checker->Allocator());
    varbinder::Variable *found_var = nullptr;
    if ((found_var = checker->Scope()->FindLocal(union_field_class_name.View(),
                                                 varbinder::ResolveBindingOptions::BINDINGS)) != nullptr) {
        return found_var->Declaration()->Node()->AsClassDeclaration()->Definition();
    }
    auto *ident = checker->AllocNode<ir::Identifier>(union_field_class_name.View(), checker->Allocator());
    auto [decl, var] = varbinder->NewVarDecl<varbinder::ClassDecl>(ident->Start(), ident->Name());
    ident->SetVariable(var);

    auto class_ctx = varbinder::LexicalScope<varbinder::ClassScope>(varbinder);
    auto *class_def = checker->AllocNode<ir::ClassDefinition>(checker->Allocator(), class_ctx.GetScope(), ident,
                                                              ir::ClassDefinitionModifiers::GLOBAL,
                                                              ir::ModifierFlags::NONE, Language(Language::Id::ETS));

    auto *class_decl = checker->AllocNode<ir::ClassDeclaration>(class_def, checker->Allocator());
    class_def->Scope()->BindNode(class_decl);
    class_def->SetTsType(checker->GlobalETSObjectType());
    decl->BindNode(class_decl);
    var->SetScope(class_def->Scope());

    varbinder->AsETSBinder()->BuildClassDefinition(class_def);
    return class_def;
}

varbinder::LocalVariable *CreateUnionFieldClassProperty(checker::ETSChecker *checker, varbinder::VarBinder *varbinder,
                                                        checker::Type *field_type, const util::StringView &prop_name)
{
    auto *const allocator = checker->Allocator();
    auto *const dummy_class = GetUnionFieldClass(checker, varbinder);
    auto *class_scope = dummy_class->Scope()->AsClassScope();

    // Enter the union filed class instance field scope
    auto field_ctx =
        varbinder::LexicalScope<varbinder::LocalScope>::Enter(varbinder, class_scope->InstanceFieldScope());

    if (auto *var = class_scope->FindLocal(prop_name, varbinder::ResolveBindingOptions::VARIABLES); var != nullptr) {
        return var->AsLocalVariable();
    }

    // Create field name for synthetic class
    auto *field_ident = allocator->New<ir::Identifier>(prop_name, allocator);

    // Create the synthetic class property node
    auto *field =
        allocator->New<ir::ClassProperty>(field_ident, nullptr, nullptr, ir::ModifierFlags::NONE, allocator, false);

    // Add the declaration to the scope
    auto [decl, var] = varbinder->NewVarDecl<varbinder::LetDecl>(field_ident->Start(), field_ident->Name());
    var->AddFlag(varbinder::VariableFlags::PROPERTY);
    var->SetTsType(field_type);
    field_ident->SetVariable(var);
    field->SetTsType(field_type);
    decl->BindNode(field);

    ArenaVector<ir::AstNode *> field_decl {allocator->Adapter()};
    field_decl.push_back(field);
    dummy_class->AddProperties(std::move(field_decl));
    return var->AsLocalVariable();
}

void HandleUnionPropertyAccess(checker::ETSChecker *checker, varbinder::VarBinder *vbind, ir::MemberExpression *expr)
{
    ASSERT(expr->PropVar() == nullptr);
    expr->SetPropVar(
        CreateUnionFieldClassProperty(checker, vbind, expr->TsType(), expr->Property()->AsIdentifier()->Name()));
    ASSERT(expr->PropVar() != nullptr);
}

ir::TSAsExpression *GenAsExpression(checker::ETSChecker *checker, checker::Type *const opaque_type,
                                    ir::Expression *const node, ir::AstNode *const parent)
{
    auto *const type_node = checker->AllocNode<ir::OpaqueTypeNode>(opaque_type);
    auto *const as_expression = checker->AllocNode<ir::TSAsExpression>(node, type_node, false);
    as_expression->SetParent(parent);
    node->SetParent(as_expression);
    as_expression->Check(checker);
    return as_expression;
}

/*
 *  Function that generates conversion from (union) to (primitive) type as to `as` expressions:
 *      (union) as (prim) => ((union) as (ref)) as (prim),
 *      where (ref) is some unboxable type from union constituent types.
 *  Finally, `(union) as (prim)` expression replaces union_node that came above.
 */
ir::TSAsExpression *UnionCastToPrimitive(checker::ETSChecker *checker, checker::ETSObjectType *unboxable_ref,
                                         checker::Type *unboxed_prim, ir::Expression *union_node)
{
    auto *const union_as_ref_expression = GenAsExpression(checker, unboxable_ref, union_node, nullptr);
    union_as_ref_expression->SetBoxingUnboxingFlags(checker->GetUnboxingFlag(unboxed_prim));
    union_node->SetParent(union_as_ref_expression);

    auto *const ref_as_prim_expression =
        GenAsExpression(checker, unboxed_prim, union_as_ref_expression, union_node->Parent());
    union_as_ref_expression->SetParent(ref_as_prim_expression);

    return ref_as_prim_expression;
}

ir::TSAsExpression *HandleUnionCastToPrimitive(checker::ETSChecker *checker, ir::TSAsExpression *expr)
{
    auto *const union_type = expr->Expr()->TsType()->AsETSUnionType();
    auto *source_type = union_type->FindExactOrBoxedType(checker, expr->TsType());
    if (source_type == nullptr) {
        source_type = union_type->AsETSUnionType()->FindTypeIsCastableToSomeType(expr->Expr(), checker->Relation(),
                                                                                 expr->TsType());
    }
    if (source_type != nullptr && expr->Expr()->GetBoxingUnboxingFlags() != ir::BoxingUnboxingFlags::NONE) {
        if (expr->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
            auto *const boxed_expr_type = checker::BoxingConverter::ETSTypeFromSource(checker, expr->TsType());
            auto *const as_expr = GenAsExpression(checker, boxed_expr_type, expr->Expr(), expr);
            as_expr->SetBoxingUnboxingFlags(expr->Expr()->GetBoxingUnboxingFlags());
            expr->Expr()->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
            expr->SetExpr(as_expr);
        }
        return expr;
    }
    auto *const unboxable_union_type = source_type != nullptr ? source_type : union_type->FindUnboxableType();
    auto *const unboxed_union_type = checker->ETSBuiltinTypeAsPrimitiveType(unboxable_union_type);
    expr->SetExpr(
        UnionCastToPrimitive(checker, unboxable_union_type->AsETSObjectType(), unboxed_union_type, expr->Expr()));
    return expr;
}

ir::BinaryExpression *GenInstanceofExpr(checker::ETSChecker *checker, ir::Expression *union_node,
                                        checker::Type *constituent_type)
{
    auto *const lhs_expr = union_node->Clone(checker->Allocator())->AsExpression();
    lhs_expr->Check(checker);
    lhs_expr->SetBoxingUnboxingFlags(union_node->GetBoxingUnboxingFlags());
    auto *rhs_type = constituent_type;
    if (!constituent_type->HasTypeFlag(checker::TypeFlag::ETS_ARRAY_OR_OBJECT)) {
        checker->Relation()->SetNode(union_node);
        rhs_type = checker::conversion::Boxing(checker->Relation(), constituent_type);
        checker->Relation()->SetNode(nullptr);
    }
    auto *const rhs_expr =
        checker->Allocator()->New<ir::Identifier>(rhs_type->AsETSObjectType()->Name(), checker->Allocator());
    auto *const instanceof_expr =
        checker->Allocator()->New<ir::BinaryExpression>(lhs_expr, rhs_expr, lexer::TokenType::KEYW_INSTANCEOF);
    lhs_expr->SetParent(instanceof_expr);
    rhs_expr->SetParent(instanceof_expr);
    auto rhs_var = NearestScope(union_node)->Find(rhs_expr->Name());
    rhs_expr->SetVariable(rhs_var.variable);
    rhs_expr->SetTsType(rhs_var.variable->TsType());
    instanceof_expr->SetOperationType(checker->GlobalETSObjectType());
    instanceof_expr->SetTsType(checker->GlobalETSBooleanType());
    return instanceof_expr;
}

ir::VariableDeclaration *GenVariableDeclForBinaryExpr(checker::ETSChecker *checker, varbinder::Scope *scope,
                                                      ir::BinaryExpression *expr)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EQUAL ||
           expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    auto *var_id = Gensym(checker->Allocator());
    auto *var = scope->AddDecl<varbinder::LetDecl, varbinder::LocalVariable>(checker->Allocator(), var_id->Name(),
                                                                             varbinder::VariableFlags::LOCAL);
    var->SetTsType(checker->GlobalETSBooleanType());
    var_id->SetVariable(var);
    var_id->SetTsType(var->TsType());

    auto declarator = checker->AllocNode<ir::VariableDeclarator>(var_id);
    ArenaVector<ir::VariableDeclarator *> declarators(checker->Allocator()->Adapter());
    declarators.push_back(declarator);

    auto var_kind = ir::VariableDeclaration::VariableDeclarationKind::LET;
    auto *binary_var_decl =
        checker->AllocNode<ir::VariableDeclaration>(var_kind, checker->Allocator(), std::move(declarators), false);
    binary_var_decl->SetRange({expr->Start(), expr->End()});
    return binary_var_decl;
}

ir::ExpressionStatement *GenExpressionStmtWithAssignment(checker::ETSChecker *checker, ir::Identifier *var_decl_id,
                                                         ir::Expression *expr)
{
    auto *assignment_for_binary =
        checker->AllocNode<ir::AssignmentExpression>(var_decl_id, expr, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignment_for_binary->SetTsType(expr->TsType());
    return checker->AllocNode<ir::ExpressionStatement>(assignment_for_binary);
}

ir::BlockStatement *GenBlockStmtForAssignmentBinary(checker::ETSChecker *checker, ir::Identifier *var_decl_id,
                                                    ir::Expression *expr)
{
    auto local_ctx = varbinder::LexicalScope<varbinder::LocalScope>(checker->VarBinder());
    ArenaVector<ir::Statement *> stmts(checker->Allocator()->Adapter());
    auto *stmt = GenExpressionStmtWithAssignment(checker, var_decl_id, expr);
    stmts.push_back(stmt);
    auto *const local_block_stmt =
        checker->AllocNode<ir::BlockStatement>(checker->Allocator(), local_ctx.GetScope(), std::move(stmts));
    stmt->SetParent(local_block_stmt);
    local_block_stmt->SetRange(stmt->Range());
    local_ctx.GetScope()->BindNode(local_block_stmt);
    return local_block_stmt;
}

ir::Expression *SetBoxFlagOrGenAsExpression(checker::ETSChecker *checker, checker::Type *constituent_type,
                                            ir::Expression *other_node)
{
    if (constituent_type->AsETSObjectType()->HasObjectFlag(checker::ETSObjectFlags::UNBOXABLE_TYPE) &&
        !other_node->IsETSUnionType() && other_node->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        auto *unboxed_constituent_type = checker->ETSBuiltinTypeAsPrimitiveType(constituent_type);
        if (unboxed_constituent_type != other_node->TsType()) {
            auto *const prim_as_expression =
                GenAsExpression(checker, unboxed_constituent_type, other_node, other_node->Parent());
            prim_as_expression->SetBoxingUnboxingFlags(checker->GetBoxingFlag(constituent_type));
            return prim_as_expression;
        }
        return other_node;
    }
    if (other_node->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        other_node->SetBoxingUnboxingFlags(
            checker->GetBoxingFlag(checker::BoxingConverter::ETSTypeFromSource(checker, other_node->TsType())));
    }
    return other_node;
}

ir::Expression *ProcessOperandsInBinaryExpr(checker::ETSChecker *checker, ir::BinaryExpression *expr,
                                            checker::Type *constituent_type)
{
    ASSERT(expr->OperatorType() == lexer::TokenType::PUNCTUATOR_EQUAL ||
           expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    bool is_lhs_union;
    ir::Expression *union_node =
        (is_lhs_union = expr->Left()->TsType()->IsETSUnionType()) ? expr->Left() : expr->Right();
    auto *const as_expression = GenAsExpression(checker, constituent_type, union_node, expr);
    if (is_lhs_union) {
        expr->SetLeft(as_expression);
        expr->SetRight(SetBoxFlagOrGenAsExpression(checker, constituent_type, expr->Right()));
    } else {
        expr->SetRight(as_expression);
        expr->SetLeft(SetBoxFlagOrGenAsExpression(checker, constituent_type, expr->Left()));
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

void InsertInstanceofTreeBeforeStmt(ir::Statement *stmt, ir::VariableDeclaration *binary_var_decl,
                                    ir::Statement *instanceof_tree)
{
    if (stmt->IsVariableDeclarator()) {
        ASSERT(stmt->Parent()->IsVariableDeclaration());
        stmt = stmt->Parent()->AsVariableDeclaration();
    }
    ASSERT(stmt->Parent()->IsBlockStatement());
    auto *block = stmt->Parent()->AsBlockStatement();
    binary_var_decl->SetParent(block);
    instanceof_tree->SetParent(block);
    auto it_stmt = std::find(block->Statements().begin(), block->Statements().end(), stmt);
    block->Statements().insert(it_stmt, {binary_var_decl, instanceof_tree});
}

ir::BlockStatement *ReplaceBinaryExprInStmt(checker::ETSChecker *checker, ir::Expression *union_node,
                                            ir::BlockStatement *block, ir::BinaryExpression *expr)
{
    auto *stmt = FindStatementFromNode(expr);
    ASSERT(stmt->IsVariableDeclarator() || block == stmt->Parent());  // statement with union
    auto *const binary_var_decl = GenVariableDeclForBinaryExpr(checker, NearestScope(stmt), expr);
    auto *const var_decl_id = binary_var_decl->Declarators().front()->Id();  // only one declarator was generated
    ir::IfStatement *instanceof_tree = nullptr;
    for (auto *u_type : union_node->TsType()->AsETSUnionType()->ConstituentTypes()) {
        auto *const test = GenInstanceofExpr(checker, union_node, u_type);
        auto *cloned_binary = expr->Clone(checker->Allocator(), expr->Parent())->AsBinaryExpression();
        cloned_binary->Check(checker);
        auto *const consequent = GenBlockStmtForAssignmentBinary(
            checker, var_decl_id->AsIdentifier(), ProcessOperandsInBinaryExpr(checker, cloned_binary, u_type));
        instanceof_tree = checker->Allocator()->New<ir::IfStatement>(test, consequent, instanceof_tree);
        test->SetParent(instanceof_tree);
        consequent->SetParent(instanceof_tree);
        if (instanceof_tree->Alternate() != nullptr) {
            instanceof_tree->Alternate()->SetParent(instanceof_tree);
        }
    }
    ASSERT(instanceof_tree != nullptr);
    // Replacing a binary expression with an identifier
    // that was set in one of the branches of the `instanceof_tree` tree
    stmt->TransformChildrenRecursively([var_decl_id](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsBinaryExpression() && ast->AsBinaryExpression()->OperationType() != nullptr &&
            ast->AsBinaryExpression()->OperationType()->IsETSUnionType()) {
            return var_decl_id;
        }

        return ast;
    });
    InsertInstanceofTreeBeforeStmt(stmt, binary_var_decl, instanceof_tree);
    return block;
}

ir::BlockStatement *HandleBlockWithBinaryAndUnion(checker::ETSChecker *checker, ir::BlockStatement *block,
                                                  ir::BinaryExpression *bin_expr)
{
    if (bin_expr->OperatorType() != lexer::TokenType::PUNCTUATOR_EQUAL &&
        bin_expr->OperatorType() != lexer::TokenType::PUNCTUATOR_NOT_EQUAL) {
        checker->ThrowTypeError("Bad operand type, unions are not allowed in binary expressions except equality.",
                                bin_expr->Start());
    }
    ir::Expression *union_node = bin_expr->Left()->TsType()->IsETSUnionType() ? bin_expr->Left() : bin_expr->Right();
    return ReplaceBinaryExprInStmt(checker, union_node, block, bin_expr);
}

ir::BlockStatement *HandleBlockWithBinaryAndUnions(checker::ETSChecker *checker, ir::BlockStatement *block,
                                                   const ir::NodePredicate &handle_binary)
{
    ir::BlockStatement *modified_ast_block = block;
    while (modified_ast_block->IsAnyChild(handle_binary)) {
        modified_ast_block = HandleBlockWithBinaryAndUnion(
            checker, modified_ast_block, modified_ast_block->FindChild(handle_binary)->AsBinaryExpression());
    }
    return modified_ast_block;
}

bool UnionLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            Perform(ctx, ext_prog);
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

        auto handle_binary = [](const ir::AstNode *ast_node) {
            return ast_node->IsBinaryExpression() && ast_node->AsBinaryExpression()->OperationType() != nullptr &&
                   ast_node->AsBinaryExpression()->OperationType()->IsETSUnionType();
        };
        if (ast->IsBlockStatement() && ast->IsAnyChild(handle_binary)) {
            return HandleBlockWithBinaryAndUnions(checker, ast->AsBlockStatement(), handle_binary);
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
    if (!current || ctx->compiler_context->Options()->compilation_mode != CompilationMode::GEN_STD_LIB) {
        return current;
    }

    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *ext_prog : ext_programs) {
            if (!Postcondition(ctx, ext_prog)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace panda::es2panda::compiler
