/*
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

#include "ASTVerifier.h"

namespace ark::es2panda::compiler::ast_verifier {

using AstToCheck = ArenaMap<ASTVerifier::AstPath, const ir::AstNode *>;

static auto ExtractAst(const parser::Program *program, bool checkFullProgram)
{
    ASSERT(program != nullptr);
    auto &allocator = *program->Allocator();
    auto astToCheck = AstToCheck {allocator.Adapter()};
    astToCheck.insert(std::make_pair(program->SourceFilePath(), program->Ast()));
    if (checkFullProgram) {
        for (const auto &externalSource : program->ExternalSources()) {
            for (auto *external : externalSource.second) {
                astToCheck.insert(std::make_pair(external->SourceFilePath(), external->Ast()));
            }
        }
    }
    return astToCheck;
}

void ASTVerifier::Verify(std::string_view phaseName)
{
    auto astToCheck = ExtractAst(program_, checkFullProgram_);

    for (const auto &p : astToCheck) {
        const auto &sourceName = p.first;
        auto *ast = p.second;
        ASSERT(ast != nullptr);
        auto messages = std::apply(
            [this, ast](auto &...invariant) {
                CheckContext ctx {};
                ((NeedCheckVariant(invariant) ? invariant.VerifyAst(&ctx, ast) : void()), ...);
                return ctx.GetMessages();
            },
            invariants_);

        const auto source = Source(sourceName, phaseName);
        auto &sourcedReport = report_[source];
        std::copy(messages.begin(), messages.end(), std::back_inserter(sourcedReport));
    }
}

ASTVerifier::Result ASTVerifier::DumpMessages()
{
    auto warnings = JsonArrayBuilder {};
    auto errors = JsonArrayBuilder {};
    const auto filterMessages = [this, &warnings, &errors](const ast_verifier::CheckMessage &message,
                                                           const std::string &sourceName,
                                                           const std::string &phaseName) {
        auto invariantId = message.InvariantId();
        if (IsAsError(invariantId)) {
            errors.Add(message.DumpJSON(ast_verifier::CheckSeverity::ERROR, sourceName, phaseName));
        } else if (IsAsWarning(invariantId)) {
            warnings.Add(message.DumpJSON(ast_verifier::CheckSeverity::WARNING, sourceName, phaseName));
        }
    };

    for (const auto &[source, messages] : report_) {
        const auto &[sourceName, phaseName] = source;
        for (const auto &message : messages) {
            filterMessages(message, sourceName, phaseName);
        }
    }

    return Result {std::move(warnings), std::move(errors)};
}

}  // namespace ark::es2panda::compiler::ast_verifier
