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

#include "enumPostCheckLowering.h"
#include "checker/types/ets/etsEnumType.h"
#include "checker/ETSchecker.h"
#include "checker/types/type.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"

namespace ark::es2panda::compiler {

ir::CallExpression *EnumPostCheckLoweringPhase::CreateCall(
    checker::ETSChecker *checker, ir::ClassDefinition *const classDef,
    checker::ETSEnumType::Method (checker::ETSEnumType::*getMethod)() const, ir::Expression *argument)
{
    auto *classId = checker->AllocNode<ir::Identifier>(classDef->Ident()->Name(), checker->Allocator());
    auto *methodId = checker->AllocNode<ir::Identifier>(
        (argument->TsType()->AsETSEnumType()->*getMethod)().memberProxyType->Name(), checker->Allocator());
    auto *callee = checker->AllocNode<ir::MemberExpression>(classId, methodId,
                                                            ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);

    ArenaVector<ir::Expression *> callArguments(checker->Allocator()->Adapter());
    callArguments.push_back(argument);
    return checker->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
}

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
    program->Ast()->TransformChildrenRecursivelyPostorder(
        // clang-format off
        [this, ctx](ir::AstNode *const node) -> ir::AstNode* {
            if (node->HasAstNodeFlags(ir::AstNodeFlags::RECHECK)) {
                if (node->IsExpression()) {
                    node->AsExpression()->SetTsType(nullptr);  // force recheck
                }
                node->Check(ctx->checker->AsETSChecker());
                node->RemoveAstNodeFlags(ir::AstNodeFlags::RECHECK);
            }
            if (node->HasAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF)) {
                ASSERT(node->IsExpression());
                auto expr = node->AsExpression();
                auto parent = expr->Parent();
                parent->AddAstNodeFlags(ir::AstNodeFlags::RECHECK);
                ASSERT((node->AsExpression()->TsType()->IsETSEnumType()));
                auto *enumIf = expr->TsType()->AsETSEnumType();
                auto *callExpr = CreateCall(ctx->checker->AsETSChecker(), enumIf->GetDecl()->BoxedClass(),
                                            &checker::ETSEnumType::ValueOfMethod, expr);
                callExpr->SetParent(parent);
                callExpr->Check(ctx->checker->AsETSChecker());
                node->RemoveAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
                return callExpr;
            }
            if (node->HasAstNodeFlags(ir::AstNodeFlags::GENERATE_GET_NAME)) {
                ASSERT(node->IsMemberExpression());
                auto memberExpr = node->AsMemberExpression();

                auto *enumIf = memberExpr->Object()->TsType()->AsETSEnumType();
                auto *callExpr = CreateCall(ctx->checker->AsETSChecker(), enumIf->GetDecl()->BoxedClass(),
                                            &checker::ETSEnumType::GetNameMethod, memberExpr->Property());

                callExpr->SetParent(node->Parent());
                callExpr->Check(ctx->checker->AsETSChecker());
                node->RemoveAstNodeFlags(ir::AstNodeFlags::GENERATE_GET_NAME);
                return callExpr;
            }
            return node;
        },
        // clang-format on
        Name());
    return true;
}

}  // namespace ark::es2panda::compiler
