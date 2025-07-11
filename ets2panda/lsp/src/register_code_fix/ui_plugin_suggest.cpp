/**
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

#include "lsp/include/register_code_fix/ui_plugin_suggest.h"
#include <iostream>
#include <string>
#include "lsp/include/code_fix_provider.h"
#include "lsp/include/internal_api.h"

namespace ark::es2panda::lsp {
const int G_UI_PLUGIN_SUGGEST_CODE = 4000;  // change this to the error code you want to handle

UIPluginSuggest::UIPluginSuggest()
{
    const char *uiPluginSuggestId = "UIPluginSuggest";
    SetErrorCodes({G_UI_PLUGIN_SUGGEST_CODE});
    SetFixIds({uiPluginSuggestId});
}

std::vector<TextChange> GetTextChangesFromSuggestions(const ark::es2panda::util::Diagnostic *diag, size_t pos,
                                                      bool isAll)
{
    std::vector<TextChange> textChanges;
    if (!diag->HasSuggestions()) {
        return textChanges;
    }
    for (auto suggestion : diag->Suggestion()) {
        auto sourceStart = suggestion->SourceRange()->start.index;
        auto sourceEnd = suggestion->SourceRange()->end.index;
        auto span = TextSpan(sourceStart, sourceEnd - sourceStart);
        if (isAll) {
            textChanges.emplace_back(TextChange(span, suggestion->SubstitutionCode()));
        } else if (pos >= sourceStart && pos <= sourceEnd) {
            textChanges.emplace_back(TextChange(span, suggestion->SubstitutionCode()));
        }
    }
    return textChanges;
}

std::vector<FileTextChanges> GetUIPluginCodeFixesByDiagType(public_lib::Context *ctx, size_t pos,
                                                            util::DiagnosticType type, bool isAll)
{
    auto filename = ctx->sourceFileName;
    std::vector<FileTextChanges> res;
    const auto &diagnostics = ctx->diagnosticEngine->GetDiagnosticStorage(type);
    auto diagnosticStorage = reinterpret_cast<const ark::es2panda::util::DiagnosticStorage *>(&diagnostics);
    // NOLINTNEXTLINE(modernize-loop-convert,-warnings-as-errors)
    for (size_t i = 0; i < diagnosticStorage->size(); ++i) {
        auto diag = reinterpret_cast<const ark::es2panda::util::Diagnostic *>(&(*(*diagnosticStorage)[i]));
        auto textChanges = GetTextChangesFromSuggestions(diag, pos, isAll);
        FileTextChanges fileTextChanges(filename, textChanges);
        res.emplace_back(fileTextChanges);
    }
    return res;
}

std::vector<FileTextChanges> UIPluginSuggest::GetUIPluginCodeFixes(es2panda_Context *context, size_t pos, bool isAll)
{
    if (context == nullptr) {
        return {};
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    std::vector<FileTextChanges> res;
    auto errorFixes = GetUIPluginCodeFixesByDiagType(ctx, pos, util::DiagnosticType::PLUGIN_ERROR, isAll);
    res.insert(res.end(), errorFixes.begin(), errorFixes.end());
    auto warningFixes = GetUIPluginCodeFixesByDiagType(ctx, pos, util::DiagnosticType::PLUGIN_WARNING, isAll);
    res.insert(res.end(), warningFixes.begin(), warningFixes.end());
    return res;
}

std::vector<CodeFixAction> UIPluginSuggest::GetCodeActions(const CodeFixContext &context)
{
    std::vector<CodeFixAction> returnedActions;
    auto changes = GetUIPluginCodeFixes(context.context, context.span.start, false);
    if (!changes.empty()) {
        CodeFixAction codeAction;
        codeAction.fixName = "Fix";
        codeAction.description = "Fix Description";
        codeAction.changes = changes;
        codeAction.fixId = "UI_PLUGIN_SUGGEST";
        codeAction.fixAllDescription = "Fix All Description";
        InstallPackageAction codeActionCommand;
        codeActionCommand.file = reinterpret_cast<public_lib::Context *>(context.context)->sourceFileName;
        codeActionCommand.packageName = "";
        codeAction.commands.push_back(codeActionCommand);
        returnedActions.push_back(codeAction);
    }
    return returnedActions;
}

CombinedCodeActions UIPluginSuggest::GetAllCodeActions(const CodeFixAllContext &codeFixAll)
{
    CombinedCodeActions combinedCodeActions;
    auto changes = GetUIPluginCodeFixes(codeFixAll.context, 0, true);
    combinedCodeActions.changes = changes;
    InstallPackageAction codeActionCommand;
    codeActionCommand.file = reinterpret_cast<public_lib::Context *>(codeFixAll.context)->sourceFileName;
    codeActionCommand.packageName = "";
    combinedCodeActions.commands.push_back(codeActionCommand);

    return combinedCodeActions;
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoCodeFixRegister<UIPluginSuggest> g_uiPluginSuggest("UIPluginSuggest");
}  // namespace ark::es2panda::lsp
