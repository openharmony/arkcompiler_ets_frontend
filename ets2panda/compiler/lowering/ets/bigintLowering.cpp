/**
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

#include "bigintLowering.h"

#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::compiler {

std::string_view BigIntLowering::Name() const
{
    return "BigIntLowering";
}

ir::Expression *CreateBigInt(public_lib::Context *ctx, ir::BigIntLiteral *literal)
{
    auto parser = ctx->parser->AsETSParser();
    auto checker = ctx->checker->AsETSChecker();

    // This will change the bigint literal node into the new class instance expression:
    // 123456n => new BigInt("123456")
    std::string src {"new "};
    src += Signatures::BUILTIN_BIGINT_CLASS;
    src += "(\"";
    src += literal->Str().Utf8();
    src += "\")";

    auto loweringResult = parser->CreateExpression(src);
    loweringResult->SetParent(literal->Parent());

    InitScopesPhaseETS::RunExternalNode(loweringResult, checker->VarBinder());
    checker->VarBinder()->AsETSBinder()->ResolveReferencesForScope(loweringResult, NearestScope(loweringResult));
    loweringResult->Check(checker);

    return loweringResult;
}

bool ReplaceStrictEqualByNormalEqual(ir::BinaryExpression *expr)
{
    auto left = expr->Left()->TsType();
    auto isBigintLeft = (left != nullptr && left->IsETSBigIntType()) || expr->Left()->IsBigIntLiteral();
    auto right = expr->Right()->TsType();
    auto isBigintRight = (right != nullptr && right->IsETSBigIntType()) || expr->Right()->IsBigIntLiteral();
    if (!isBigintLeft && !isBigintRight) {
        return false;
    }

    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_STRICT_EQUAL) {
        expr->SetOperator(lexer::TokenType::PUNCTUATOR_EQUAL);
    } else if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL) {
        expr->SetOperator(lexer::TokenType::PUNCTUATOR_NOT_EQUAL);
    } else {
        return false;
    }

    return true;
}

// Currently there are no compile time operations for bigint.
bool RemoveConst(ir::BinaryExpression *expr)
{
    bool isRemoved = false;
    auto left = expr->Left()->TsType();
    if (left != nullptr && left->IsETSBigIntType()) {
        left->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        isRemoved = true;
    }

    auto right = expr->Right()->TsType();
    if (right != nullptr && right->IsETSBigIntType()) {
        right->RemoveTypeFlag(checker::TypeFlag::CONSTANT);
        isRemoved = true;
    }

    return isRemoved;
}

bool BigIntLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    auto checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [ctx, checker](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsBigIntLiteral() && ast->Parent() != nullptr && ast->Parent()->IsClassProperty()) {
                return CreateBigInt(ctx, ast->AsBigIntLiteral());
            }

            if (ast->IsBinaryExpression()) {
                auto expr = ast->AsBinaryExpression();
                bool doCheck = ReplaceStrictEqualByNormalEqual(expr);
                doCheck |= RemoveConst(expr);
                if (doCheck) {
                    expr->Check(checker);
                }
            }

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
