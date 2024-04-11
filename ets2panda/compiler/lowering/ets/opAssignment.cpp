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

namespace ark::es2panda::compiler {

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

static lexer::TokenType OpEqualToOp(const lexer::TokenType opEqual)
{
    for (const auto &conv : OP_TRANSLATION) {
        if (conv.from == opEqual) {
            return conv.to;
        }
    }
    UNREACHABLE();
}

void AdjustBoxingUnboxingFlags(ir::Expression *loweringResult, const ir::Expression *oldExpr)
{
    ir::AssignmentExpression *newAssignment = nullptr;
    if (loweringResult->IsAssignmentExpression()) {
        newAssignment = loweringResult->AsAssignmentExpression();
    } else if (loweringResult->IsBlockExpression() && !loweringResult->AsBlockExpression()->Statements().empty()) {
        auto *statement = loweringResult->AsBlockExpression()->Statements().back();
        if (statement->IsExpressionStatement() &&
            statement->AsExpressionStatement()->GetExpression()->IsAssignmentExpression()) {
            newAssignment = statement->AsExpressionStatement()->GetExpression()->AsAssignmentExpression();
        }
    } else {
        UNREACHABLE();
    }

    // NOTE: gogabr. make sure that the checker never puts both a boxing and an unboxing flag on the same node.
    // Then this function will become unnecessary.
    const ir::BoxingUnboxingFlags oldBoxingFlag {oldExpr->GetBoxingUnboxingFlags() &
                                                 ir::BoxingUnboxingFlags::BOXING_FLAG};
    const ir::BoxingUnboxingFlags oldUnboxingFlag {oldExpr->GetBoxingUnboxingFlags() &
                                                   ir::BoxingUnboxingFlags::UNBOXING_FLAG};

    if (newAssignment->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        newAssignment->SetBoxingUnboxingFlags(oldBoxingFlag);
    } else if (newAssignment->TsType()->IsETSObjectType()) {
        newAssignment->SetBoxingUnboxingFlags(oldUnboxingFlag);
    }
}

static ir::OpaqueTypeNode *CreateProxyTypeNode(checker::ETSChecker *checker, ir::Expression *expr)
{
    auto *lcType = expr->TsType();
    if (auto *lcTypeAsPrimitive = checker->ETSBuiltinTypeAsPrimitiveType(lcType); lcTypeAsPrimitive != nullptr) {
        lcType = lcTypeAsPrimitive;
    }
    return checker->AllocNode<ir::OpaqueTypeNode>(lcType);
}

static std::string GenerateStringForLoweredAssignment(lexer::TokenType opEqual, bool hasProperty, ir::Expression *expr)
{
    std::string leftHand = "@@I5";
    std::string rightHand = "@@I7";

    if (hasProperty) {
        auto const kind = expr->AsMemberExpression()->Kind();
        if (kind == ir::MemberExpressionKind::PROPERTY_ACCESS) {
            leftHand += ".@@I6";
            rightHand += ".@@I8";
        } else if (kind == ir::MemberExpressionKind::ELEMENT_ACCESS) {
            leftHand += "[@@I6]";
            rightHand += "[@@I8]";
        } else {
            UNREACHABLE();
        }
    }

    return leftHand + " = (" + rightHand + ' ' + std::string {lexer::TokenToString(OpEqualToOp(opEqual))} +
           " (@@E9)) as @@T10";
}

static ir::Identifier *GetClone(ArenaAllocator *allocator, ir::Identifier *node)
{
    return node != nullptr ? node->Clone(allocator, nullptr) : nullptr;
}

ir::Expression *HandleOpAssignment(public_lib::Context *ctx, checker::ETSChecker *checker, parser::ETSParser *parser,
                                   ir::AssignmentExpression *assignment)
{
    if (assignment->TsType() == nullptr) {  // hasn't been through checker
        return assignment;
    }

    const auto opEqual = assignment->OperatorType();
    ASSERT(opEqual != lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    ASSERT(parser != nullptr);

    auto *const allocator = checker->Allocator();

    auto *const left = assignment->Left();
    auto *const right = assignment->Right();
    auto *const scope = NearestScope(assignment);

    std::string newAssignmentStatements {};

    ir::Identifier *ident1;
    ir::Identifier *ident2 = nullptr;
    ir::Expression *object = nullptr;
    ir::Expression *property = nullptr;

    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY};

    // Create temporary variable(s) if left hand of assignment is not defined by simple identifier[s]
    if (left->IsIdentifier()) {
        ident1 = left->AsIdentifier();
    } else if (left->IsMemberExpression()) {
        auto *const memberExpression = left->AsMemberExpression();

        if (object = memberExpression->Object(); object->IsIdentifier()) {
            ident1 = object->AsIdentifier();
        } else {
            ident1 = Gensym(allocator);
            newAssignmentStatements = "let @@I1 = (@@E2); ";
        }

        if (property = memberExpression->Property(); property->IsIdentifier()) {
            ident2 = property->AsIdentifier();
        } else {
            ident2 = Gensym(allocator);
            newAssignmentStatements += "let @@I3 = (@@E4); ";
        }
    } else {
        UNREACHABLE();
    }

    auto *exprType = CreateProxyTypeNode(checker, left);

    // Generate ArkTS code string for new lowered assignment expression:
    newAssignmentStatements += GenerateStringForLoweredAssignment(opEqual, ident2 != nullptr, left);

    // Parse ArkTS code string and create and process corresponding AST node(s)
    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);

    auto *loweringResult = parser->CreateFormattedExpression(
        newAssignmentStatements, ident1, object, ident2, property, GetClone(allocator, ident1),
        GetClone(allocator, ident2), GetClone(allocator, ident1), GetClone(allocator, ident2), right, exprType);
    loweringResult->SetParent(assignment->Parent());
    InitScopesPhaseETS::RunExternalNode(loweringResult, ctx->compilerContext->VarBinder());

    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(loweringResult, NearestScope(loweringResult));
    loweringResult->Check(checker);

    AdjustBoxingUnboxingFlags(loweringResult, assignment);

    return loweringResult;
}

bool OpAssignmentLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    if (ctx->compilerContext->Options()->compilationMode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, ext_programs] : program->ExternalSources()) {
            (void)_;
            for (auto *extProg : ext_programs) {
                Perform(ctx, extProg);
            }
        }
    }

    auto *const parser = ctx->parser->AsETSParser();
    checker::ETSChecker *checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [ctx, checker, parser](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsAssignmentExpression() &&
                ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
                return HandleOpAssignment(ctx, checker, parser, ast->AsAssignmentExpression());
            }

            return ast;
        },
        Name());

    return true;
}

bool OpAssignmentLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    if (ctx->compilerContext->Options()->compilationMode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, ext_programs] : program->ExternalSources()) {
            (void)_;
            for (auto *extProg : ext_programs) {
                if (!Postcondition(ctx, extProg)) {
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

}  // namespace ark::es2panda::compiler
