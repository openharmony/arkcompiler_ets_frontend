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
#include "compiler/lowering/util.h"
#include "varbinder/ETSBinder.h"
#include "varbinder/variable.h"

namespace ark::es2panda::compiler {

static ir::ClassDeclaration *FindEnclosingClass(ir::AstNode *ast)
{
    for (ir::AstNode *curr = ast->Parent(); curr != nullptr; curr = curr->Parent()) {
        if (curr->IsClassDeclaration()) {
            return curr->AsClassDeclaration();
        }
    }
    UNREACHABLE();
}

static ir::CallExpression *CallStaticEnumMethod(checker::ETSChecker *checker, checker::ETSEnumType *enumType,
                                                checker::ETSEnumType::Method (checker::ETSEnumType::*getMethod)() const,
                                                ir::Expression *argument)
{
    auto classDef = enumType->BoxedType()->AsETSObjectType()->GetDeclNode()->AsClassDefinition();
    auto methodName = (enumType->*getMethod)().memberProxyType->Name();

    auto classId = checker->AllocNode<ir::Identifier>(classDef->Ident()->Name(), checker->Allocator());
    auto methodId = checker->AllocNode<ir::Identifier>(methodName, checker->Allocator());
    auto callee = checker->AllocNode<ir::MemberExpression>(classId, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                           false, false);

    ArenaVector<ir::Expression *> callArguments({argument}, checker->Allocator()->Adapter());
    return checker->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
}

static ir::CallExpression *CallInstanceEnumMethod(checker::ETSChecker *checker, checker::ETSEnumType *enumType,
                                                  checker::ETSEnumType::Method (checker::ETSEnumType::*getMethod)()
                                                      const,
                                                  ir::Expression *thisArg)
{
    auto methodName = (enumType->*getMethod)().memberProxyType->Name();

    auto methodId = checker->AllocNode<ir::Identifier>(methodName, checker->Allocator());
    auto callee = checker->AllocNode<ir::MemberExpression>(thisArg, methodId, ir::MemberExpressionKind::PROPERTY_ACCESS,
                                                           false, false);

    ArenaVector<ir::Expression *> callArguments({}, checker->Allocator()->Adapter());
    return checker->AllocNode<ir::CallExpression>(callee, std::move(callArguments), nullptr, false);
}

static ir::CallExpression *GenerateValueOfCall(checker::ETSChecker *checker, ir::AstNode *const node)
{
    ASSERT(node->IsExpression());
    auto expr = node->AsExpression();
    auto parent = expr->Parent();
    parent->AddAstNodeFlags(ir::AstNodeFlags::RECHECK);

    checker::ETSEnumType *enumIf;

    if (!expr->TsType()->IsETSEnumType()) {
        expr->RemoveBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOX_TO_ENUM);
        enumIf = expr->TsType()->AsETSObjectType()->GetUnboxedEnumType();
        expr = CallInstanceEnumMethod(checker, enumIf, &checker::ETSEnumType::UnboxMethod, expr);
    } else {
        enumIf = expr->TsType()->AsETSEnumType();
    }

    auto *callExpr = CallStaticEnumMethod(checker, enumIf, &checker::ETSEnumType::ValueOfMethod, expr);
    callExpr->SetParent(parent);

    auto *calleClass = FindEnclosingClass(expr);

    auto *varBinder = checker->VarBinder()->AsETSBinder();

    auto *nearestScope = NearestScope(parent);
    auto lexScope = varbinder::LexicalScope<varbinder::Scope>::Enter(varBinder, nearestScope);
    varBinder->ResolveReferencesForScopeWithContext(callExpr, nearestScope);

    auto checkerCtx = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_CLASS,
                                                   calleClass->Definition()->TsType()->AsETSObjectType());
    auto scopeCtx = checker::ScopeContext(checker, nearestScope);

    callExpr->Check(checker);
    node->RemoveAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF);
    return callExpr;
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
        [ctx](ir::AstNode *const node) -> ir::AstNode* {
            if (node->HasAstNodeFlags(ir::AstNodeFlags::RECHECK)) {
                if (node->IsExpression()) {
                    node->AsExpression()->SetTsType(nullptr);  // force recheck
                }
                node->Check(ctx->checker->AsETSChecker());
                node->RemoveAstNodeFlags(ir::AstNodeFlags::RECHECK);
            }
            if (node->HasAstNodeFlags(ir::AstNodeFlags::GENERATE_VALUE_OF)) {
                return GenerateValueOfCall(ctx->checker->AsETSChecker(), node);
            }
            if (node->HasAstNodeFlags(ir::AstNodeFlags::GENERATE_GET_NAME)) {
                ASSERT(node->IsMemberExpression());
                auto memberExpr = node->AsMemberExpression();

                auto *enumIf = memberExpr->Object()->TsType()->AsETSEnumType();
                auto *callExpr = CallStaticEnumMethod(ctx->checker->AsETSChecker(), enumIf,
                                            // CC-OFFNXT(G.FMT.06-CPP) project code style
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
