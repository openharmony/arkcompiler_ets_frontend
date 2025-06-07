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

#include "lsp/include/code_fix_provider.h"
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <regex>
#include <stdexcept>
#include "lsp/include/internal_api.h"

namespace ark::es2panda::lsp {

void CodeFixProvider::RegisterCodeFix(const std::string &aliasName, std::unique_ptr<CodeFixRegistration> registration)
{
    (void)aliasName;
    ASSERT(!aliasName.empty());
    auto shared = std::shared_ptr<CodeFixRegistration>(std::move(registration));

    for (auto error : shared->GetErrorCodes()) {
        errorCodeToFixes_.emplace(std::to_string(error), shared);
    }
    if (!shared->GetFixIds().empty()) {
        for (const auto &fixId : shared->GetFixIds()) {
            fixIdToRegistration_.emplace(fixId, shared);
        }
    }
}

CodeFixProvider &CodeFixProvider::Instance()
{
    static CodeFixProvider instance;
    return instance;
}

std::string CodeFixProvider::FormatWithArgs(const std::string &text)
{
    std::string result = text;
    const std::string regExp = R"(\{(\d+)\})";
    std::regex pattern(regExp);
    std::smatch match;
    return result;
}

std::string CodeFixProvider::DiagnosticToString(const DiagnosticAndArguments &diag)
{
    std::string message;
    if (diag.arguments.empty()) {
        message = diag.message.message;
    } else {
        message = FormatWithArgs(diag.message.message);
    }
    return message;
}

CodeFixAction CodeFixProvider::CreateCodeFixActionWorker(std::string &fixName, std::string &description,
                                                         std::vector<FileTextChanges> &changes, std::string &fixId,
                                                         std::string &fixAllDescription,
                                                         std::vector<CodeActionCommand> command = {})
{
    CodeAction codeAction;
    codeAction.description = description;
    codeAction.changes = changes;
    codeAction.commands = std::move(command);
    return {codeAction, fixName, fixId, fixAllDescription};
}

CodeFixAction CodeFixProvider::CreateCodeFixActionWithoutFixAll(std::string &fixName,
                                                                std::vector<FileTextChanges> &changes,
                                                                DiagnosticAndArguments &description)
{
    std::string fixId;
    std::string descriptionMessage = DiagnosticToString(description);
    std::string fixAllDescription;
    return CreateCodeFixActionWorker(fixName, descriptionMessage, changes, fixId, fixAllDescription);
}

CodeFixAction CodeFixProvider::CreateCodeFixAction(std::string fixName, std::vector<FileTextChanges> changes,
                                                   DiagnosticAndArguments &description, std::string fixId,
                                                   DiagnosticAndArguments &fixAllDescription,
                                                   std::vector<CodeActionCommand> &command)
{
    std::string descriptionMessage = DiagnosticToString(description);
    std::string fixAllDescriptionMessage = DiagnosticToString(fixAllDescription);
    return CreateCodeFixActionWorker(fixName, descriptionMessage, changes, fixId, fixAllDescriptionMessage,
                                     std::move(command));
}

std::string CodeFixProvider::GetFileName(const std::string &filePath)
{
    if (filePath.empty()) {
        return "";
    }

    std::size_t pos = filePath.find_last_of('/');
    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }

    pos = filePath.find_last_of('\\');
    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }

    return filePath;
}

std::vector<std::string> CodeFixProvider::GetSupportedErrorCodes()
{
    std::vector<std::string> result;
    for (const auto &kv : errorCodeToFixes_) {
        result.push_back(kv.first);
    }
    return result;
}

DiagnosticReferences *CodeFixProvider::GetDiagnostics(const CodeFixContextBase &context)
{
    DiagnosticReferences *result = nullptr;
    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    auto it = reinterpret_cast<public_lib::Context *>(context.context);
    std::string fileNameStr(GetFileName(std::string(it->sourceFile->filePath)));
    std::string sourceStr(it->sourceFile->source);
    const auto ctx = initializer.CreateContext(fileNameStr.c_str(), ES2PANDA_STATE_CHECKED, sourceStr.c_str());
    DiagnosticReferences semantic = lspApi->getSemanticDiagnostics(ctx);
    DiagnosticReferences syntactic = lspApi->getSyntacticDiagnostics(ctx);
    DiagnosticReferences suggestions = lspApi->getSuggestionDiagnostics(ctx);

    for (const auto &d : semantic.diagnostic) {
        result->diagnostic.push_back(d);
    }
    for (const auto &d : syntactic.diagnostic) {
        result->diagnostic.push_back(d);
    }
    for (const auto &d : suggestions.diagnostic) {
        result->diagnostic.push_back(d);
    }
    initializer.DestroyContext(ctx);
    return result;
}

bool CodeFixProvider::ShouldIncludeFixAll(const CodeFixRegistration &registration,
                                          const std::vector<Diagnostic> &diagnostics)
{
    int maybeFixableDiagnostics = 0;
    const int minFixableDiagnostics = 1;
    for (size_t i = 0; i <= diagnostics.size(); i++) {
        if (std::find(registration.GetErrorCodes().begin(), registration.GetErrorCodes().end(), i) !=
            registration.GetErrorCodes().end()) {
            ++maybeFixableDiagnostics;
            if (maybeFixableDiagnostics > minFixableDiagnostics) {
                break;
            }
        }
    }
    return maybeFixableDiagnostics > minFixableDiagnostics;
}

CombinedCodeActions CodeFixProvider::GetAllFixes(const CodeFixAllContext &context)
{
    auto it = fixIdToRegistration_.find(context.fixId);
    if (it == fixIdToRegistration_.end() || !it->second) {
        return CombinedCodeActions();
    }
    const std::shared_ptr<CodeFixRegistration> &registration = it->second;
    return registration->GetAllCodeActions(context);
}

void CodeFixProvider::EachDiagnostic(const CodeFixAllContext &context, const std::vector<int> &errorCodes,
                                     const std::function<void(const DiagnosticWithLocation &)> &cb)
{
    if (errorCodes.empty()) {
    }
    if (cb) {
    }
    auto diagnostics = GetDiagnostics(context);
    if (diagnostics != nullptr) {
        for (size_t i = 0; i <= diagnostics->diagnostic.size(); i++) {
        }
    }
}

std::vector<CodeFixAction> CodeFixProvider::GetFixes(const CodeFixContext &context)
{
    std::vector<CodeFixAction> result;
    auto it = errorCodeToFixes_.find(std::to_string(context.errorCode));
    if (it != errorCodeToFixes_.end()) {
        const auto &registrations = it->second;
        if (registrations) {
            auto actions = registrations->GetCodeActions(context);
            for (auto &action : actions) {
                result.push_back(action);
            }
        }
    }
    return result;
}

CombinedCodeActions CodeFixProvider::CodeFixAll(
    const CodeFixAllContext &context, const std::vector<int> &errorCodes,
    std::function<void(ChangeTracker &, const DiagnosticWithLocation &)> use)
{
    std::vector<CodeActionCommand> commands;
    TextChangesContext textChangesContext {context.host, context.formatContext, context.preferences};
    auto changes = ChangeTracker::With(textChangesContext, [&](ChangeTracker &tracker) {
        EachDiagnostic(context, errorCodes, [&](const DiagnosticWithLocation &diag) { use(tracker, diag); });
    });
    return {changes, commands};
}

FileTextChanges CodeFixProvider::CreateFileTextChanges(const std::string &fileName,
                                                       const std::vector<TextChange> &textChanges)
{
    return {fileName, textChanges};
}

}  // namespace ark::es2panda::lsp
