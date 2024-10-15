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
#include "identifierHasVariable.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/memberExpression.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/typeNode.h"

namespace ark::es2panda::compiler::ast_verifier {

CheckResult IdentifierHasVariable::operator()(CheckContext &ctx, const ir::AstNode *ast)
{
    if (!ast->IsIdentifier()) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    if (ast->AsIdentifier()->Variable() != nullptr) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    const auto *id = ast->AsIdentifier();
    if (CheckAstExceptions(id)) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    // Another function with exceptions to reduce function size
    if (CheckMoreAstExceptions(id)) {
        return {CheckDecision::CORRECT, CheckAction::CONTINUE};
    }

    ctx.AddCheckMessage("NULL_VARIABLE", *id, id->Start());
    return {CheckDecision::INCORRECT, CheckAction::CONTINUE};
}

bool IdentifierHasVariable::CheckMoreAstExceptions(const ir::Identifier *ast) const
{
    // NOTE(kkonkuznetsov): skip async functions
    auto parent = ast->Parent();
    while (parent != nullptr) {
        if (parent->IsScriptFunction()) {
            auto script = parent->AsScriptFunction();
            if (script->IsAsyncFunc()) {
                return true;
            }

            break;
        }

        parent = parent->Parent();
    }

    // NOTE(kkonkuznetsov): skip reexport declarations
    if (ast->Parent() != nullptr && ast->Parent()->Parent() != nullptr) {
        parent = ast->Parent()->Parent();
        if (parent->IsETSReExportDeclaration()) {
            return true;
        }
    }

    // NOTE(kkonkuznetsov): object expressions
    parent = ast->Parent();
    while (parent != nullptr) {
        if (parent->IsObjectExpression()) {
            return true;
        }

        parent = parent->Parent();
    }

    // NOTE(kkonkuznetsov): some identifiers have empty names
    if (ast->Name().Empty()) {
        return true;
    }

    // NOTE(mmartin): find a better solution to handle utility type resolution
    if (ast->Name().Is(Signatures::PARTIAL_TYPE_NAME) || ast->Name().Is(Signatures::REQUIRED_TYPE_NAME) ||
        ast->Name().Is(Signatures::READONLY_TYPE_NAME)) {
        return true;
    }

    return false;
}

bool IdentifierHasVariable::CheckAstExceptions(const ir::Identifier *ast) const
{
    // NOTE(kkonkuznetsov): skip enums
    if (ast->Parent()->IsMemberExpression() &&
        (ast->Parent()->AsMemberExpression()->Object()->TsType() == nullptr ||
         ast->Parent()->AsMemberExpression()->Object()->TsType()->IsETSEnumType())) {
        return true;
    }

    // NOTE(kkonkuznetsov): skip length property
    if (ast->Parent()->IsMemberExpression() && ast->Name().Is("length")) {
        return true;
    }

    // NOTE(kkonkuznetsov): skip anonymous class id
    if (ast->Parent()->Parent() != nullptr && ast->Parent()->Parent()->IsETSNewClassInstanceExpression()) {
        return true;
    }

    // NOTE(kkonkuznetsov): skip package declarations
    auto parent = ast->Parent();
    while (parent != nullptr) {
        if (parent->IsETSPackageDeclaration()) {
            return true;
        }

        parent = parent->Parent();
    }

    return false;
}

}  // namespace ark::es2panda::compiler::ast_verifier
