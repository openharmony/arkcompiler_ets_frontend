/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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

#include "enumPostCheckLowering.h"
#include "checker/types/ets/etsEnumType.h"
#include "checker/ETSchecker.h"
#include "checker/types/type.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"

namespace ark::es2panda::compiler {

ir::CallExpression *EnumPostCheckLoweringPhase::CreateGetValueCall(checker::ETSChecker *checker,
                                                                   ir::ClassDefinition *const classDef,
                                                                   ir::Expression *argument)
{
    auto *classId = checker->AllocNode<ir::Identifier>(classDef->Ident()->Name(), checker->Allocator());
    auto *methodId = checker->AllocNode<ir::Identifier>(
        argument->TsType()->AsEnumInterface()->GetValueMethod().memberProxyType->Name(), checker->Allocator());
    methodId->SetReference();
    auto *callee = checker->AllocNode<ir::MemberExpression>(classId, methodId,
                                                            ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    ArenaVector<ir::Expression *> callArguments(checker->Allocator()->Adapter());
    callArguments.push_back(argument);
    return checker->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
}

namespace {

bool NeedToGenerateGetValueForBinaryExpression(lexer::TokenType op)
{
    return op == lexer::TokenType::PUNCTUATOR_GREATER_THAN || op == lexer::TokenType::PUNCTUATOR_GREATER_THAN_EQUAL ||
           op == lexer::TokenType::PUNCTUATOR_LESS_THAN || op == lexer::TokenType::PUNCTUATOR_LESS_THAN_EQUAL ||
           op == lexer::TokenType::PUNCTUATOR_EQUAL || op == lexer::TokenType::PUNCTUATOR_NOT_EQUAL ||
           op == lexer::TokenType::PUNCTUATOR_BITWISE_AND || op == lexer::TokenType::PUNCTUATOR_BITWISE_OR ||
           op == lexer::TokenType::PUNCTUATOR_BITWISE_XOR;
}

}  // namespace

bool EnumPostCheckLoweringPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    if (program->Extension() != ScriptExtension::ETS) {
        return true;
    }

    for (auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : extPrograms) {
            Perform(ctx, extProg);
        }
    }

    program->Ast()->IterateRecursively([this, ctx](ir::AstNode *ast) -> void {
        if (ast->IsBinaryExpression()) {
            auto *binaryExpr = ast->AsBinaryExpression();
            if (!NeedToGenerateGetValueForBinaryExpression(binaryExpr->OperatorType())) {
                return;
            }

            auto *left = binaryExpr->Left();
            auto *right = binaryExpr->Right();
            auto *leftType = left->TsType();
            auto *rightType = right->TsType();

            if (leftType != nullptr && (leftType->IsETSEnumType() || leftType->IsETSStringEnumType())) {
                auto *enumIf = leftType->AsEnumInterface();
                auto *callExpr =
                    CreateGetValueCall(ctx->checker->AsETSChecker(), enumIf->GetDecl()->BoxedClass(), left);
                callExpr->SetParent(binaryExpr);
                binaryExpr->SetLeft(callExpr);
            }
            if (rightType != nullptr && (rightType->IsETSEnumType() || rightType->IsETSStringEnumType())) {
                auto *enumIf = rightType->AsEnumInterface();
                auto *callExpr =
                    CreateGetValueCall(ctx->checker->AsETSChecker(), enumIf->GetDecl()->BoxedClass(), right);
                callExpr->SetParent(binaryExpr);
                binaryExpr->SetRight(callExpr);
            }
            if (leftType != nullptr || rightType != nullptr) {
                binaryExpr->SetTsType(nullptr);  // force recheck
                binaryExpr->Check(ctx->checker->AsETSChecker());
            }
        }
    });
    return true;
}

}  // namespace ark::es2panda::compiler