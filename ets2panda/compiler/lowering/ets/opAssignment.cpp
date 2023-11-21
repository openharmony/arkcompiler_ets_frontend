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

//
// This is a sample lowering, of little value by itself.
//
// desc: A compound assignment expression of the form E1 op= E2 is equivalent to E1 =
//   	 ((E1) op (E2)) as T, where T is the type of E1, except that E1 is evaluated only
//   	 once.
//

#include "opAssignment.h"

#include "parser/ETSparser.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "ir/opaqueTypeNode.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/blockExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/expressionStatement.h"

namespace panda::es2panda::compiler {

std::string_view OpAssignmentLowering::Name()
{
    return "op-assignment";
}

struct Conversion {
    lexer::TokenType from;
    lexer::TokenType to;
};

// NOLINTNEXTLINE(readability-magic-numbers)
static constexpr std::array<Conversion, 16> OP_TRANSLATION {
    {{lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_LEFT_SHIFT},
     {lexer::TokenType::PUNCTUATOR_PLUS_EQUAL, lexer::TokenType::PUNCTUATOR_PLUS},
     {lexer::TokenType::PUNCTUATOR_MINUS_EQUAL, lexer::TokenType::PUNCTUATOR_MINUS},
     {lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL, lexer::TokenType::PUNCTUATOR_MULTIPLY},
     {lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL, lexer::TokenType::PUNCTUATOR_DIVIDE},
     {lexer::TokenType::PUNCTUATOR_MOD_EQUAL, lexer::TokenType::PUNCTUATOR_MOD},
     {lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_AND},
     {lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_OR},
     {lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL, lexer::TokenType::PUNCTUATOR_BITWISE_XOR},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_AND_EQUAL, lexer::TokenType::PUNCTUATOR_LOGICAL_AND},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_OR_EQUAL, lexer::TokenType::PUNCTUATOR_LOGICAL_OR},
     {lexer::TokenType::PUNCTUATOR_LOGICAL_NULLISH_EQUAL, lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING},
     {lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL, lexer::TokenType::PUNCTUATOR_EXPONENTIATION}}};

static lexer::TokenType OpEqualToOp(const lexer::TokenType op_equal)
{
    for (const auto &conv : OP_TRANSLATION) {
        if (conv.from == op_equal) {
            return conv.to;
        }
    }
    UNREACHABLE();
}

void AdjustBoxingUnboxingFlags(ir::Expression *new_expr, const ir::Expression *old_expr)
{
    // NOTE: gogabr. make sure that the checker never puts both a boxing and an unboxing flag on the same node.
    // Then this function will become unnecessary.
    const ir::BoxingUnboxingFlags old_boxing_flag {old_expr->GetBoxingUnboxingFlags() &
                                                   ir::BoxingUnboxingFlags::BOXING_FLAG};
    const ir::BoxingUnboxingFlags old_unboxing_flag {old_expr->GetBoxingUnboxingFlags() &
                                                     ir::BoxingUnboxingFlags::UNBOXING_FLAG};

    if (new_expr->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        new_expr->SetBoxingUnboxingFlags(old_boxing_flag);
    } else if (new_expr->TsType()->IsETSObjectType()) {
        new_expr->SetBoxingUnboxingFlags(old_unboxing_flag);
    }
}

ir::Expression *HandleOpAssignment(public_lib::Context *ctx, checker::ETSChecker *checker, parser::ETSParser *parser,
                                   ir::AssignmentExpression *assignment)
{
    if (assignment->TsType() == nullptr) {  // hasn't been through checker
        return assignment;
    }

    const auto op_equal = assignment->OperatorType();
    ASSERT(op_equal != lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    ASSERT(parser != nullptr);

    auto *const allocator = checker->Allocator();

    auto *const left = assignment->Left();
    auto *const right = assignment->Right();
    auto *const scope = NearestScope(assignment);

    std::string new_assignment_statements {};

    ir::Identifier *ident1;
    ir::Identifier *ident2 = nullptr;
    ir::Expression *object = nullptr;
    ir::Expression *property = nullptr;

    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY};

    // Create temporary variable(s) if left hand of assignment is not defined by simple identifier[s]
    if (left->IsIdentifier()) {
        ident1 = left->AsIdentifier();
    } else if (left->IsMemberExpression()) {
        auto *const member_expression = left->AsMemberExpression();

        if (object = member_expression->Object(); object->IsIdentifier()) {
            ident1 = object->AsIdentifier();
        } else {
            ident1 = Gensym(allocator);
            new_assignment_statements = "let @@I1 = (@@E2); ";
        }

        if (property = member_expression->Property(); property->IsIdentifier()) {
            ident2 = property->AsIdentifier();
        } else {
            ident2 = Gensym(allocator);
            new_assignment_statements += "let @@I3 = (@@E4); ";
        }
    } else {
        UNREACHABLE();
    }

    // Create proxy TypeNode for left hand of assignment expression
    auto *lc_type = left->TsType();
    if (auto *lc_type_as_primitive = checker->ETSBuiltinTypeAsPrimitiveType(lc_type); lc_type_as_primitive != nullptr) {
        lc_type = lc_type_as_primitive;
    }
    auto *expr_type = checker->AllocNode<ir::OpaqueTypeNode>(lc_type);

    // Generate ArkTS code string for new lowered assignment expression:
    std::string left_hand = "@@I5";
    std::string right_hand = "@@I7";

    if (ident2 != nullptr) {
        if (auto const kind = left->AsMemberExpression()->Kind(); kind == ir::MemberExpressionKind::PROPERTY_ACCESS) {
            left_hand += ".@@I6";
            right_hand += ".@@I8";
        } else if (kind == ir::MemberExpressionKind::ELEMENT_ACCESS) {
            left_hand += "[@@I6]";
            right_hand += "[@@I8]";
        } else {
            UNREACHABLE();
        }
    }

    new_assignment_statements += left_hand + " = (" + right_hand + ' ' +
                                 std::string {lexer::TokenToString(OpEqualToOp(op_equal))} + " (@@E9)) as @@T10";
    // std::cout << "Lowering statements: " << new_assignment_statements << std::endl;

    // Parse ArkTS code string and create and process corresponding AST node(s)
    auto expression_ctx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);

    auto *lowering_result = parser->CreateFormattedExpression(
        new_assignment_statements, parser::DEFAULT_SOURCE_FILE, ident1, object, ident2, property,
        ident1->Clone(allocator), ident2 != nullptr ? ident2->Clone(allocator) : nullptr, ident1->Clone(allocator),
        ident2 != nullptr ? ident2->Clone(allocator) : nullptr, right, expr_type);
    lowering_result->SetParent(assignment->Parent());
    ScopesInitPhaseETS::RunExternalNode(lowering_result, ctx->compiler_context->VarBinder());

    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(lowering_result, scope);
    lowering_result->Check(checker);

    // Adjust [un]boxing flag
    ir::AssignmentExpression *new_assignment;
    if (lowering_result->IsAssignmentExpression()) {
        new_assignment = lowering_result->AsAssignmentExpression();
    } else if (lowering_result->IsBlockExpression() && !lowering_result->AsBlockExpression()->Statements().empty() &&
               lowering_result->AsBlockExpression()->Statements().back()->IsExpressionStatement() &&
               lowering_result->AsBlockExpression()
                   ->Statements()
                   .back()
                   ->AsExpressionStatement()
                   ->GetExpression()
                   ->IsAssignmentExpression()) {
        new_assignment = lowering_result->AsBlockExpression()
                             ->Statements()
                             .back()
                             ->AsExpressionStatement()
                             ->GetExpression()
                             ->AsAssignmentExpression();
    } else {
        UNREACHABLE();
    }

    // NOTE(gogabr): make sure that the checker never puts both a boxing and an unboxing flag on the same node.
    // Then this code will become unnecessary.
    AdjustBoxingUnboxingFlags(new_assignment, assignment);

    return lowering_result;
}

bool OpAssignmentLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    if (ctx->compiler_context->Options()->compilation_mode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, ext_programs] : program->ExternalSources()) {
            (void)_;
            for (auto *ext_prog : ext_programs) {
                Perform(ctx, ext_prog);
            }
        }
    }

    auto *const parser = ctx->parser->AsETSParser();
    checker::ETSChecker *checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively([ctx, checker, parser](ir::AstNode *ast) -> ir::AstNode * {
        if (ast->IsAssignmentExpression() &&
            ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
            return HandleOpAssignment(ctx, checker, parser, ast->AsAssignmentExpression());
        }

        return ast;
    });

    return true;
}

bool OpAssignmentLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    if (ctx->compiler_context->Options()->compilation_mode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, ext_programs] : program->ExternalSources()) {
            (void)_;
            for (auto *ext_prog : ext_programs) {
                if (!Postcondition(ctx, ext_prog)) {
                    return false;
                }
            }
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->TsType() != nullptr &&
               ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION;
    });
}

}  // namespace panda::es2panda::compiler
