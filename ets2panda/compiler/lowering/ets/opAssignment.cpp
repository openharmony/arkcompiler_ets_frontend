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
static constexpr std::array<Conversion, 18> OP_TRANSLATION {{
    {lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL, lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT},
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
    {lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL, lexer::TokenType::PUNCTUATOR_EXPONENTIATION},
    {lexer::TokenType::PUNCTUATOR_PLUS_PLUS, lexer::TokenType::PUNCTUATOR_PLUS},
    {lexer::TokenType::PUNCTUATOR_MINUS_MINUS, lexer::TokenType::PUNCTUATOR_MINUS},
}};

static lexer::TokenType CombinedOpToOp(const lexer::TokenType combinedOp)
{
    for (const auto &conv : OP_TRANSLATION) {
        if (conv.from == combinedOp) {
            return conv.to;
        }
    }
    UNREACHABLE();
}

void AdjustBoxingUnboxingFlags(ir::Expression *loweringResult, const ir::Expression *oldExpr)
{
    ir::Expression *exprToProcess = nullptr;
    if (loweringResult->IsAssignmentExpression()) {
        exprToProcess = loweringResult->AsAssignmentExpression();
    } else if (loweringResult->IsBlockExpression() && !loweringResult->AsBlockExpression()->Statements().empty()) {
        auto *statement = loweringResult->AsBlockExpression()->Statements().back();
        if (statement->IsExpressionStatement()) {
            exprToProcess = statement->AsExpressionStatement()->GetExpression();
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

    if (exprToProcess->TsType()->HasTypeFlag(checker::TypeFlag::ETS_PRIMITIVE)) {
        loweringResult->SetBoxingUnboxingFlags(oldBoxingFlag);
    } else if (exprToProcess->TsType()->IsETSObjectType()) {
        loweringResult->SetBoxingUnboxingFlags(oldUnboxingFlag);
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

static std::string GenFormatForExpression(ir::Expression *expr, size_t ix1, size_t ix2)
{
    std::string res = "@@I" + std::to_string(ix1);
    if (expr->IsMemberExpression()) {
        auto const kind = expr->AsMemberExpression()->Kind();
        if (kind == ir::MemberExpressionKind::PROPERTY_ACCESS) {
            res += ".@@I" + std::to_string(ix2);
        } else if (kind == ir::MemberExpressionKind::ELEMENT_ACCESS) {
            res += "[@@I" + std::to_string(ix2) + "]";
        }
    }
    return res;
}

static std::string GenerateStringForLoweredAssignment(lexer::TokenType opEqual, ir::Expression *expr)
{
    std::string leftHand = GenFormatForExpression(expr, 5, 6);
    std::string rightHand = GenFormatForExpression(expr, 7, 8);

    return leftHand + " = (" + rightHand + ' ' + std::string {lexer::TokenToString(CombinedOpToOp(opEqual))} +
           " (@@E9)) as @@T10";
}

static ir::Identifier *GetClone(ArenaAllocator *allocator, ir::Identifier *node)
{
    return node == nullptr ? nullptr : node->Clone(allocator, nullptr);
}

static ir::Expression *ConstructOpAssignmentResult(public_lib::Context *ctx, ir::AssignmentExpression *assignment)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *checker = ctx->checker->AsETSChecker();

    const auto opEqual = assignment->OperatorType();
    ASSERT(opEqual != lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    auto *const left = assignment->Left();
    auto *const right = assignment->Right();

    std::string newAssignmentStatements {};

    ir::Identifier *ident1;
    ir::Identifier *ident2 = nullptr;
    ir::Expression *object = nullptr;
    ir::Expression *property = nullptr;

    // Create temporary variable(s) if left hand of assignment is not defined by simple identifier[s]
    if (left->IsIdentifier()) {
        ident1 = left->AsIdentifier();
    } else if (left->IsMemberExpression()) {
        auto *const memberExpression = left->AsMemberExpression();

        if (object = memberExpression->Object(); object->IsIdentifier()) {
            ident1 = object->AsIdentifier();
        } else {
            ident1 = Gensym(allocator);
            newAssignmentStatements = "const @@I1 = (@@E2); ";
        }

        if (property = memberExpression->Property(); property->IsIdentifier()) {
            ident2 = property->AsIdentifier();
        } else {
            ident2 = Gensym(allocator);
            newAssignmentStatements += "const @@I3 = (@@E4); ";
        }
    } else {
        UNREACHABLE();
    }

    auto *exprType = CreateProxyTypeNode(checker, left);

    // Generate ArkTS code string for new lowered assignment expression:
    newAssignmentStatements += GenerateStringForLoweredAssignment(opEqual, left);

    // Parse ArkTS code string and create corresponding AST node(s)
    return parser->CreateFormattedExpression(newAssignmentStatements, ident1, object, ident2, property,
                                             GetClone(allocator, ident1), GetClone(allocator, ident2),
                                             GetClone(allocator, ident1), GetClone(allocator, ident2), right, exprType);
}

ir::AstNode *HandleOpAssignment(public_lib::Context *ctx, ir::AssignmentExpression *assignment)
{
    auto *checker = ctx->checker->AsETSChecker();

    if (assignment->TsType() == nullptr) {  // hasn't been through checker
        return assignment;
    }

    auto *loweringResult = ConstructOpAssignmentResult(ctx, assignment);

    loweringResult->SetParent(assignment->Parent());
    // NOTE(dslynko, #19200): required for correct debug-info
    loweringResult->SetRange(assignment->Range());

    auto *const scope = NearestScope(assignment);

    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
    InitScopesPhaseETS::RunExternalNode(loweringResult, ctx->parserProgram->VarBinder());
    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScopeWithContext(loweringResult, scope);

    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY, ContainingClass(assignment)};
    checker::ScopeContext sc {checker, scope};

    loweringResult->Check(checker);

    AdjustBoxingUnboxingFlags(loweringResult, assignment);

    return loweringResult;
}

static ir::Expression *ConstructUpdateResult(public_lib::Context *ctx, ir::UpdateExpression *upd)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *argument = upd->Argument();
    auto *checker = ctx->checker->AsETSChecker();

    std::string newAssignmentStatements {};

    ir::Identifier *id1;
    ir::Identifier *id2 = nullptr;
    ir::Identifier *id3 = nullptr;
    ir::Expression *object = nullptr;
    ir::Expression *property = nullptr;
    checker::Type *objType = checker->GlobalVoidType();  // placeholder
    checker::Type *propType = checker->GlobalVoidType();

    // Parse ArkTS code string and create the corresponding AST node(s)
    // We have to use extra caution with types and `as` conversions because of smart types, which we cannot reproduce in
    // re-checking.

    if (argument->IsIdentifier()) {
        id1 = GetClone(allocator, argument->AsIdentifier());
    } else if (argument->IsMemberExpression()) {
        auto *memberExpression = argument->AsMemberExpression();

        if (object = memberExpression->Object(); object != nullptr && object->IsIdentifier()) {
            id1 = GetClone(allocator, object->AsIdentifier());
        } else if (object != nullptr) {
            id1 = Gensym(allocator);
            newAssignmentStatements = "const @@I1 = (@@E2) as @@T3; ";
            objType = object->TsType();
        }

        if (property = memberExpression->Property(); property != nullptr && property->IsIdentifier()) {
            id2 = GetClone(allocator, property->AsIdentifier());
        } else if (property != nullptr) {
            id2 = Gensym(allocator);
            newAssignmentStatements += "const @@I4 = (@@E5) as @@T6; ";
            propType = property->TsType();
        }
    }

    std::string opSign = lexer::TokenToString(CombinedOpToOp(upd->OperatorType()));

    std::string suffix = (argument->TsType() == checker->GlobalETSBigIntType()) ? "n" : "";

    // NOLINTBEGIN(readability-magic-numbers)
    if (upd->IsPrefix()) {
        newAssignmentStatements += GenFormatForExpression(argument, 7U, 8U) + " = (" +
                                   GenFormatForExpression(argument, 9U, 10U) + opSign + " 1" + suffix + ") as @@T11;";
        return parser->CreateFormattedExpression(
            newAssignmentStatements, id1, object, objType, id2, property, propType, GetClone(allocator, id1),
            GetClone(allocator, id2), GetClone(allocator, id1), GetClone(allocator, id2), argument->TsType());
    }

    // upd is postfix
    id3 = Gensym(allocator);
    newAssignmentStatements += "const @@I7 = " + GenFormatForExpression(argument, 8, 9) + " as @@T10;" +
                               GenFormatForExpression(argument, 11U, 12U) + " = (@@I13 " + opSign + " 1" + suffix +
                               ") as @@T14; @@I15;";
    return parser->CreateFormattedExpression(newAssignmentStatements, id1, object, objType, id2, property, propType,
                                             id3, GetClone(allocator, id1), GetClone(allocator, id2),
                                             argument->TsType(), GetClone(allocator, id1), GetClone(allocator, id2),
                                             GetClone(allocator, id3), argument->TsType(), GetClone(allocator, id3));
    // NOLINTEND(readability-magic-numbers)
}

static ir::AstNode *HandleUpdate(public_lib::Context *ctx, ir::UpdateExpression *upd)
{
    auto *checker = ctx->checker->AsETSChecker();

    auto *const scope = NearestScope(upd);

    ir::Expression *loweringResult = ConstructUpdateResult(ctx, upd);

    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY, ContainingClass(upd)};
    checker::ScopeContext sc {checker, scope};

    loweringResult->SetParent(upd->Parent());
    // NOTE(dslynko, #19200): required for correct debug-info
    loweringResult->SetRange(upd->Range());
    InitScopesPhaseETS::RunExternalNode(loweringResult, ctx->checker->VarBinder());

    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScopeWithContext(loweringResult,
                                                                              NearestScope(loweringResult));
    loweringResult->Check(checker);

    AdjustBoxingUnboxingFlags(loweringResult, upd);

    return loweringResult;
}

bool OpAssignmentLowering::Perform(public_lib::Context *ctx, parser::Program *program)
{
    if (ctx->config->options->CompilerOptions().compilationMode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, ext_programs] : program->ExternalSources()) {
            (void)_;
            for (auto *extProg : ext_programs) {
                Perform(ctx, extProg);
            }
        }
    }

    program->Ast()->TransformChildrenRecursively(
        [ctx](ir::AstNode *ast) {
            if (ast->IsAssignmentExpression() &&
                ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
                return HandleOpAssignment(ctx, ast->AsAssignmentExpression());
            }
            if (ast->IsUpdateExpression()) {
                return HandleUpdate(ctx, ast->AsUpdateExpression());
            }

            return ast;
        },
        Name());

    return true;
}

bool OpAssignmentLowering::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    auto checkExternalPrograms = [this, ctx](const ArenaVector<parser::Program *> &programs) {
        for (auto *p : programs) {
            if (!Postcondition(ctx, p)) {
                return false;
            }
        }
        return true;
    };

    if (ctx->config->options->CompilerOptions().compilationMode == CompilationMode::GEN_STD_LIB) {
        for (auto &[_, extPrograms] : program->ExternalSources()) {
            (void)_;
            if (!checkExternalPrograms(extPrograms)) {
                return false;
            };
        }
    }

    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return (ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->TsType() != nullptr &&
                ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) ||
               ast->IsUpdateExpression();
    });
}

}  // namespace ark::es2panda::compiler
