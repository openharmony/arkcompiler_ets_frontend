/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ir/statements/annotationDeclaration.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsInterfaceDeclaration.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult NodeHasType::operator()(const ir::AstNode *ast)
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
    if (auto [decision, action] = CheckCompound(ast); action == CheckAction::SKIP_SUBTREE) {
        return {decision, action};
    }

    if (ast->IsTyped() && ast->IsExpression()) {
        if (ast->IsClassDefinition() && ast->AsClassDefinition()->Ident()->Name() == Signatures::ETS_GLOBAL) {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        if (ast->IsIdentifier() && ast->AsIdentifier()->Name() == "") {
            return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
        }
        const auto *typed = static_cast<const ir::TypedAstNode *>(ast);
        if (typed->TsType() == nullptr) {
            AddCheckMessage("NULL_TS_TYPE", *ast);
            return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
        }
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

CheckResult NodeHasType::CheckCompound(const ir::AstNode *ast)
{
    if (ast->IsTSInterfaceDeclaration()) {
        for (const auto &member : ast->AsTSInterfaceDeclaration()->Body()->Body()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsTSEnumDeclaration()) {
        for (const auto &member : ast->AsTSEnumDeclaration()->Members()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsClassDefinition()) {
        for (const auto &member : ast->AsClassDefinition()->Body()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    if (ast->IsAnnotationDeclaration()) {
        for (const auto &member : ast->AsAnnotationDeclaration()->Properties()) {
            [[maybe_unused]] auto _ = (*this)(member);
        }
        return {CheckDecision::CORRECT, CheckAction::SKIP_SUBTREE};
    }
    return {CheckDecision::CORRECT, CheckAction::CONTINUE};
}

}  // namespace ark::es2panda::compiler::ast_verifier
