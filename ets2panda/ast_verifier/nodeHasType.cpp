/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "helpers.h"
#include "nodeHasType.h"
#include "ir/base/classDefinition.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceDeclaration.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult NodeHasType::operator()(CheckContext &ctx, const ir::AstNode *ast)
{
    // NOTE(orlovskymaxim) In TS some ETS constructs are expressions (i.e. class/interface definition)
    // Because ETS uses some AST classes from TS this introduces semantical problem
    // Solution for now - manually filter expressions that are statements in ETS
    if (ast->IsETSPackageDeclaration()) {
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (IsImportLike(ast)) {
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (IsExportLike(ast)) {
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }

    if (ast->IsTSTypeAliasDeclaration()) {
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (auto [decision, action] = CheckCompound(ctx, ast); action == CheckAction::SKIP_SUBTREE) {
        return {decision, action};
    }

    if (ast->IsTyped() && ast->IsExpression()) {
        if (ast->IsClassDefinition() && ast->AsClassDefinition()->Ident()->Name() == "ETSGLOBAL") {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsIdentifier() && ast->AsIdentifier()->Name() == "") {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        const auto *typed = static_cast<const ir::TypedAstNode *>(ast);
        if (typed->TsType() == nullptr) {
            ctx.AddCheckMessage("NULL_TS_TYPE", *ast, ast->Start());
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

CheckResult NodeHasType::CheckCompound(CheckContext &ctx, const ir::AstNode *ast)
{
    if (ast->IsTSInterfaceDeclaration()) {
        for (const auto &member : ast->AsTSInterfaceDeclaration()->Body()->Body()) {
            [[maybe_unused]] auto _ = (*this)(ctx, member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsTSEnumDeclaration()) {
        for (const auto &member : ast->AsTSEnumDeclaration()->Members()) {
            [[maybe_unused]] auto _ = (*this)(ctx, member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsClassDefinition()) {
        for (const auto &member : ast->AsClassDefinition()->Body()) {
            [[maybe_unused]] auto _ = (*this)(ctx, member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
