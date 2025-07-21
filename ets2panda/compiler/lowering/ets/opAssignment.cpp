/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
    ES2PANDA_UNREACHABLE();
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
        ES2PANDA_UNREACHABLE();
    }

    // NOTE: gogabr. make sure that the checker never puts both a boxing and an unboxing flag on the same node.
    // Then this function will become unnecessary.
    const ir::BoxingUnboxingFlags oldBoxingFlag {oldExpr->GetBoxingUnboxingFlags() &
                                                 ir::BoxingUnboxingFlags::BOXING_FLAG};
    const ir::BoxingUnboxingFlags oldUnboxingFlag {oldExpr->GetBoxingUnboxingFlags() &
                                                   ir::BoxingUnboxingFlags::UNBOXING_FLAG};
    ES2PANDA_ASSERT(exprToProcess != nullptr);
    if (exprToProcess->TsType()->IsETSPrimitiveType()) {
        loweringResult->SetBoxingUnboxingFlags(oldBoxingFlag);
    } else if (exprToProcess->TsType()->IsETSObjectType()) {
        loweringResult->SetBoxingUnboxingFlags(oldUnboxingFlag);
    }
}

static ir::OpaqueTypeNode *CreateProxyTypeNode(public_lib::Context *ctx, ir::Expression *expr)
{
    auto *lcType = expr->TsType();
    auto *checker = ctx->checker->AsETSChecker();
    if (checker->IsExtensionETSFunctionType(lcType) && expr->IsMemberExpression() &&
        expr->AsMemberExpression()->HasMemberKind(ir::MemberExpressionKind::EXTENSION_ACCESSOR)) {
        lcType = expr->AsMemberExpression()->ExtensionAccessorType();
    }
    if (auto *lcTypeAsPrimitive = checker->MaybeUnboxInRelation(lcType); lcTypeAsPrimitive != nullptr) {
        lcType = lcTypeAsPrimitive;
    }
    return ctx->AllocNode<ir::OpaqueTypeNode>(lcType, ctx->Allocator());
}

static std::string GenFormatForExpression(ir::Expression *expr, size_t ix1, size_t ix2)
{
    std::string res = "@@I" + std::to_string(ix1);

    if (expr->IsTSNonNullExpression()) {
        expr = expr->AsTSNonNullExpression()->Expr();
    }

    if (expr->IsMemberExpression()) {
        auto const kind = expr->AsMemberExpression()->Kind();
        if ((kind & ir::MemberExpressionKind::PROPERTY_ACCESS) != 0) {
            res += ".@@I" + std::to_string(ix2);
        } else if (kind == ir::MemberExpressionKind::ELEMENT_ACCESS) {
            res += "[@@I" + std::to_string(ix2) + "]";
        }
    }
    return res;
}

static ir::Identifier *GetClone(ArenaAllocator *allocator, ir::Identifier *node)
{
    return node == nullptr ? nullptr : node->Clone(allocator, nullptr);
}

static std::string GetFormatPlaceholder(const ir::Expression *expr, const size_t counter)
{
    if (expr->IsIdentifier()) {
        return "@@I" + std::to_string(counter);
    }

    return "@@E" + std::to_string(counter);
}

static std::string UpdateStatementToAccessPropertyOrElement(const ir::MemberExpression *expr, std::string statement)
{
    if (auto const kind = expr->Kind();
        kind != ir::MemberExpressionKind::NONE && kind != ir::MemberExpressionKind::ELEMENT_ACCESS) {
        statement = "." + statement;
    } else if (kind == ir::MemberExpressionKind::ELEMENT_ACCESS) {
        statement = "[" + statement + "]";
    }

    return statement;
}

static std::tuple<std::string, ArenaVector<ir::Expression *>> GenerateNestedMemberAccess(
    ir::MemberExpression *expr, ArenaAllocator *const allocator, size_t counter = 1)
{
    // Generate a formatString and a vector of expressions(same order as the format string)
    // The formatString will look like this: "@@I1K@@I2...K@@IN"
    // Where K is either "." or "["
    // If "[", then after the number there will be a "]".
    // Where N is the number of nested member accesses (N == newAssignmentExpressions.size())
    auto member = expr->Object();
    ArenaVector<ir::Expression *> newAssignmentExpressions(allocator->Adapter());
    newAssignmentExpressions.push_back(expr->Property());

    while (member->IsMemberExpression()) {
        newAssignmentExpressions.push_back(member->AsMemberExpression()->Property());
        member = member->AsMemberExpression()->Object();
    }

    newAssignmentExpressions.push_back(member);
    // This is done because the vector is built from the innermost member access to the outermost,
    // but the format string is built from the outermost to the innermost
    std::reverse(newAssignmentExpressions.begin(), newAssignmentExpressions.end());

    // It is outside the loop to avoid calling `UpdateStringToAccessPropertyOrElement` for the first element
    std::string newAssignmentStatements = GetFormatPlaceholder(newAssignmentExpressions[0], counter);
    newAssignmentExpressions[0] = newAssignmentExpressions[0]->Clone(allocator, nullptr)->AsExpression();

    for (size_t i = 1; i < newAssignmentExpressions.size(); i++) {
        const std::string statement = GetFormatPlaceholder(newAssignmentExpressions[i], i + counter);
        newAssignmentStatements += UpdateStatementToAccessPropertyOrElement(
            newAssignmentExpressions[i]->Parent()->AsMemberExpression(), statement);
        newAssignmentExpressions[i] = newAssignmentExpressions[i]->Clone(allocator, nullptr)->AsExpression();
    }

    return {newAssignmentStatements, newAssignmentExpressions};
}

static std::tuple<std::string, ArenaVector<ir::Expression *>> GenerateStringForAssignment(
    const lexer::TokenType opEqual, ir::MemberExpression *expr, ArenaAllocator *const allocator, size_t counter)
{
    // Note: Handle "A `opAssign` B" to "A = (A `operation` B) as T"
    // opAssign is the operation like: "+=", "-=", "*=", "/=", etc.,
    // operation is the operation like: "+", "-", "*", "/", etc.
    auto [retStr, retVec] = GenerateNestedMemberAccess(expr, allocator, counter);
    counter += retVec.size();
    auto result = GenerateNestedMemberAccess(expr, allocator, counter);
    counter += std::get<1>(result).size();
    retStr += " = ( " + std::get<0>(result) + ' ' + std::string {lexer::TokenToString(CombinedOpToOp(opEqual))} +
              " (@@E" + std::to_string(counter) + ")) as @@T" + std::to_string(counter + 1);
    retVec.insert(retVec.end(), std::get<1>(result).begin(), std::get<1>(result).end());
    return {retStr, retVec};
}

static ir::Expression *GenerateLoweredResultForLoweredAssignment(
    const lexer::TokenType opEqual, ir::MemberExpression *expr, ArenaAllocator *const allocator,
    parser::ETSParser *parser, const std::array<ir::Expression *, 2> additionalAssignmentExpressions)
{
    // Generated a formatString for the new lowered assignment expression
    // The formatString will look like this: "A = (A `operation` B) as T"
    // Where A is a member access
    // `operation` is the operation of the assignment like: "+", "-", "*", "/", etc.,
    // B is the right hand side of the assignment
    // T is the type of the left hand side of the assignment
    if (expr->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS && !expr->Property()->IsLiteral()) {
        // Note: support such a situation could be okay: `a[idx++] += someExpr`.
        // It should be lowered as: `let dummyIdx = (lower result of `idx++`); a[dummyIdx] = a[dummyIdx] + someExpr`;
        ArenaVector<ir::Expression *> dummyIndexDeclExpression(allocator->Adapter());
        std::string dummyIndexDeclStr = "let @@I1 = @@E2;\n";
        auto dummyIndex = Gensym(allocator);
        dummyIndexDeclExpression.emplace_back(dummyIndex);
        dummyIndexDeclExpression.emplace_back(expr->Property()->Clone(allocator, nullptr)->AsExpression());
        ClearTypesVariablesAndScopes(dummyIndexDeclExpression[1]);

        // Note: Drop the old property, substitute it with dummyIdx.
        expr->Property()->SetParent(nullptr);
        expr->SetProperty(dummyIndex->Clone(allocator, expr));
        auto [retStr, retVec] =
            GenerateStringForAssignment(opEqual, expr, allocator, dummyIndexDeclExpression.size() + 1);
        retVec.push_back(additionalAssignmentExpressions[0]);
        retVec.push_back(additionalAssignmentExpressions[1]);
        retVec.insert(retVec.begin(), dummyIndexDeclExpression.begin(), dummyIndexDeclExpression.end());
        retStr = dummyIndexDeclStr + retStr;
        return parser->CreateFormattedExpression(retStr, retVec);
    }

    auto [retStr, retVec] = GenerateStringForAssignment(opEqual, expr, allocator, 1);
    retVec.push_back(additionalAssignmentExpressions[0]);
    retVec.push_back(additionalAssignmentExpressions[1]);
    return parser->CreateFormattedExpression(retStr, retVec);
}

static ir::Expression *ConstructOpAssignmentResult(public_lib::Context *ctx, ir::AssignmentExpression *assignment)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();

    const auto opEqual = assignment->OperatorType();
    ES2PANDA_ASSERT(opEqual != lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

    auto *const left = assignment->Left();
    auto *const right = assignment->Right();
    right->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);

    auto *exprType = CreateProxyTypeNode(ctx, left);
    ir::Expression *retVal = nullptr;

    // Create temporary variable(s) if left hand of assignment is not defined by simple identifier[s]
    if (left->IsIdentifier()) {
        const std::string formatString =
            "@@I1 = (@@I2 " + std::string(lexer::TokenToString(CombinedOpToOp(opEqual))) + " (@@E3)) as @@T4";
        retVal = parser->CreateFormattedExpression(formatString, GetClone(allocator, left->AsIdentifier()),
                                                   GetClone(allocator, left->AsIdentifier()), right, exprType);
    } else if (left->IsMemberExpression()) {
        // Generate ArkTS code string for new lowered assignment expression:
        retVal = GenerateLoweredResultForLoweredAssignment(opEqual, left->AsMemberExpression(), allocator, parser,
                                                           {right, exprType});
    } else {
        ES2PANDA_UNREACHABLE();
    }

    return retVal;
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
    auto rng = assignment->Range();
    loweringResult->SetRange(rng);
    loweringResult->TransformChildrenRecursively(
        [rng](auto *node) {
            node->SetRange(rng);
            return node;
        },
        "");

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

struct ArgumentInfo {
    std::string newAssignmentStatements {};
    ir::Identifier *id1 = nullptr;
    ir::Identifier *id2 = nullptr;
    ir::Identifier *id3 = nullptr;
    ir::Expression *object = nullptr;
    ir::Expression *property = nullptr;
    checker::Type *objType = nullptr;
    checker::Type *propType = nullptr;
};

static void ParseArgument(public_lib::Context *ctx, ir::Expression *argument, ArgumentInfo &info)
{
    auto *allocator = ctx->allocator;

    if (argument->IsTSNonNullExpression()) {
        argument = argument->AsTSNonNullExpression()->Expr();
    }

    if (argument->IsIdentifier()) {
        info.id1 = GetClone(allocator, argument->AsIdentifier());
    } else if (argument->IsMemberExpression()) {
        auto *memberExpression = argument->AsMemberExpression();

        if (info.object = memberExpression->Object(); info.object != nullptr && info.object->IsIdentifier()) {
            info.id1 = GetClone(allocator, info.object->AsIdentifier());
        } else if (info.object != nullptr) {
            info.id1 = Gensym(allocator);
            info.newAssignmentStatements = "const @@I1 = (@@E2) as @@T3; ";
            info.objType = info.object->TsType();
        }

        if (info.property = memberExpression->Property(); info.property != nullptr && info.property->IsIdentifier()) {
            info.id2 = GetClone(allocator, info.property->AsIdentifier());
        } else if (info.property != nullptr) {
            info.id2 = Gensym(allocator);
            info.newAssignmentStatements += "const @@I4 = (@@E5) as @@T6; ";
            info.propType = info.property->TsType();
        }
    }
}

static ir::Expression *ConstructUpdateResult(public_lib::Context *ctx, ir::UpdateExpression *upd)
{
    auto *allocator = ctx->allocator;
    auto *parser = ctx->parser->AsETSParser();
    auto *argument = upd->Argument();
    auto *checker = ctx->checker->AsETSChecker();

    ArgumentInfo argInfo {};
    argInfo.objType = checker->GlobalVoidType();
    argInfo.propType = checker->GlobalVoidType();
    argInfo.id3 = Gensym(allocator);

    // Parse ArkTS code string and create the corresponding AST node(s)
    // We have to use extra caution with types and `as` conversions because of smart types, which we cannot reproduce in
    // re-checking.
    ParseArgument(ctx, argument, argInfo);
    std::string opSign = lexer::TokenToString(CombinedOpToOp(upd->OperatorType()));

    std::string suffix = argument->TsType()->IsETSBigIntType() ? "n" : "";

    // NOLINTBEGIN(readability-magic-numbers)
    if (upd->IsPrefix()) {
        argInfo.newAssignmentStatements +=
            "const @@I7 = (" + GenFormatForExpression(argument, 8U, 9U) + opSign + " 1" + suffix + ") as @@T10;";
        argInfo.newAssignmentStatements += GenFormatForExpression(argument, 11U, 12U) + " = @@I13; @@I14";
        return parser->CreateFormattedExpression(
            argInfo.newAssignmentStatements, argInfo.id1, argInfo.object, argInfo.objType, argInfo.id2,
            argInfo.property, argInfo.propType, argInfo.id3, GetClone(allocator, argInfo.id1),
            GetClone(allocator, argInfo.id2), argument->TsType(), GetClone(allocator, argInfo.id1),
            GetClone(allocator, argInfo.id2), GetClone(allocator, argInfo.id3), GetClone(allocator, argInfo.id3));
    }

    // upd is postfix
    argInfo.newAssignmentStatements += "const @@I7 = " + GenFormatForExpression(argument, 8, 9) + " as @@T10;" +
                                       GenFormatForExpression(argument, 11U, 12U) + " = (@@I13 " + opSign + " 1" +
                                       suffix + ") as @@T14; @@I15;";
    return parser->CreateFormattedExpression(
        argInfo.newAssignmentStatements, argInfo.id1, argInfo.object, argInfo.objType, argInfo.id2, argInfo.property,
        argInfo.propType, argInfo.id3, GetClone(allocator, argInfo.id1), GetClone(allocator, argInfo.id2),
        argument->TsType(), GetClone(allocator, argInfo.id1), GetClone(allocator, argInfo.id2),
        GetClone(allocator, argInfo.id3), argument->TsType(), GetClone(allocator, argInfo.id3));
    // NOLINTEND(readability-magic-numbers)
}

static ir::AstNode *HandleUpdate(public_lib::Context *ctx, ir::UpdateExpression *upd)
{
    auto *const scope = NearestScope(upd);

    ir::Expression *loweringResult = ConstructUpdateResult(ctx, upd);

    auto *checker = ctx->checker->AsETSChecker();

    auto expressionCtx = varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), scope);
    checker::SavedCheckerContext scc {checker, checker::CheckerStatus::IGNORE_VISIBILITY, ContainingClass(upd)};
    checker::ScopeContext sc {checker, scope};

    loweringResult->SetParent(upd->Parent());
    // NOTE(dslynko, #19200): required for correct debug-info
    auto rng = upd->Range();
    loweringResult->SetRange(rng);
    loweringResult->TransformChildrenRecursively(
        [rng](auto *node) {
            node->SetRange(rng);
            return node;
        },
        "");

    InitScopesPhaseETS::RunExternalNode(loweringResult, checker->VarBinder());

    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScopeWithContext(loweringResult,
                                                                              NearestScope(loweringResult));
    loweringResult->Check(checker);

    AdjustBoxingUnboxingFlags(loweringResult, upd);

    return loweringResult;
}

bool OpAssignmentLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
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

bool OpAssignmentLowering::PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                                  const parser::Program *program)
{
    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        return (ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->TsType() != nullptr &&
                ast->AsAssignmentExpression()->OperatorType() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) ||
               ast->IsUpdateExpression();
    });
}

}  // namespace ark::es2panda::compiler
