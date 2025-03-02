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

#include <iostream>
#include <string>
#include "api.h"
#include "napi.h"

const int INPUT_NUMBER = 2;

Napi::Object DefinitionInfoToNapiObject(const DefinitionInfo &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("fileName", info.fileName);
    obj.Set("start", static_cast<double>(info.start));
    obj.Set("length", static_cast<double>(info.length));
    return obj;
}

Napi::Value GetDefinitionAtPositionWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DefinitionInfo result = lsp->getDefinitionAtPosition(fileName.c_str(), position);
    return DefinitionInfoToNapiObject(result, env);
}

Napi::Object TextSpanToNapiObject(const TextSpan &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("start", Napi::Number::New(env, static_cast<double>(info.start)));
    obj.Set("length", Napi::Number::New(env, static_cast<double>(info.length)));
    return obj;
}

Napi::Object HighlightSpanToNapiObject(const HighlightSpan &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("fileName", Napi::String::New(env, info.fileName_));
    obj.Set("isInString", Napi::Boolean::New(env, info.isInString_));
    obj.Set("textSpan", TextSpanToNapiObject(info.textSpan_, env));
    obj.Set("contextSpan", TextSpanToNapiObject(info.contextSpan_, env));
    obj.Set("kind", static_cast<int>(info.kind_));

    return obj;
}

Napi::Object DocumentHighlightsToNapiObject(const DocumentHighlights &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("fileName", Napi::String::New(env, info.fileName_));

    Napi::Object highlightSpansArray = Napi::Object::New(env);
    for (size_t i = 0; i < info.highlightSpans_.size(); i++) {
        highlightSpansArray.Set(std::to_string(i), HighlightSpanToNapiObject(info.highlightSpans_[i], env));
    }

    obj.Set("highlightSpans", highlightSpansArray);
    return obj;
}

Napi::Object DocumentHighlightsReferencesToNapiObject(const DocumentHighlightsReferences &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    Napi::Object highlightsArray = Napi::Object::New(env);

    for (size_t i = 0; i < info.documentHighlights_.size(); i++) {
        highlightsArray.Set(std::to_string(i), DocumentHighlightsToNapiObject(info.documentHighlights_[i], env));
    }

    obj.Set("documentHighlights", highlightsArray);
    return obj;
}

Napi::Value GetDocumentHighlightsWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DocumentHighlightsReferences result = lsp->getDocumentHighlights(fileName.c_str(), position);
    return DocumentHighlightsReferencesToNapiObject(result, env);
}

Napi::Object PositionToNapiObject(const Position &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("line", Napi::Number::New(env, info.line_));
    obj.Set("character", Napi::Number::New(env, info.character_));
    return obj;
}

Napi::Object RangeToNapiObject(const Range &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("start", PositionToNapiObject(info.start, env));
    obj.Set("end", PositionToNapiObject(info.end, env));
    return obj;
}

Napi::Object LocationToNapiObject(const Location &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("uri", Napi::String::New(env, info.uri_));
    obj.Set("range", RangeToNapiObject(info.range_, env));
    return obj;
}

Napi::Value DiagnosticSeverityToNapiValue(DiagnosticSeverity severity, Napi::Env env)
{
    return Napi::Number::New(env, static_cast<int>(severity));
}

Napi::Object DiagnosticToNapiObject(const Diagnostic &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("range", RangeToNapiObject(info.range_, env));
    obj.Set("severity", DiagnosticSeverityToNapiValue(info.severity_, env));
    obj.Set("message", Napi::String::New(env, info.message_));

    return obj;
}

Napi::Object DiagnosticReferencesToNapiObject(const DiagnosticReferences &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    Napi::Object diagnosticArray = Napi::Object::New(env);
    for (size_t i = 0; i < info.diagnostic.size(); i++) {
        diagnosticArray.Set(std::to_string(i), DiagnosticToNapiObject(info.diagnostic[i], env));
    }

    obj.Set("diagnostic", diagnosticArray);
    return obj;
}

Napi::Value GetSemanticDiagnosticsWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected one arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DiagnosticReferences result = lsp->getSemanticDiagnostics(fileName.c_str());
    return DiagnosticReferencesToNapiObject(result, env);
}

Napi::Value GetSyntacticDiagnosticsWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected one arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DiagnosticReferences result = lsp->getSyntacticDiagnostics(fileName.c_str());
    return DiagnosticReferencesToNapiObject(result, env);
}

Napi::Object FileDiagnosticToNapiObject(const FileDiagnostic &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("diagnostic", DiagnosticToNapiObject(info.diagnostic, env));

    return obj;
}

Napi::Object GetSuggestionDiagnosticsToNapiArray(std::vector<FileDiagnostic> diagnostics, Napi::Env env)
{
    Napi::Object arr = Napi::Object::New(env);

    for (size_t i = 0; i < diagnostics.size(); i++) {
        arr.Set(std::to_string(i), FileDiagnosticToNapiObject(diagnostics[i], env));
    }

    return arr;
}

Napi::Value GetSuggestionDiagnosticsWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected one arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DiagnosticReferences result = lsp->getSuggestionDiagnostics(fileName.c_str());
    return DiagnosticReferencesToNapiObject(result, env);
}

Napi::Object SymbolDisplayPartToNapiObject(const SymbolDisplayPart &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("text", Napi::String::New(env, info.GetText()));
    obj.Set("kind", Napi::String::New(env, info.GetKind()));
    return obj;
}

Napi::Object QuickInfoToNapiObject(const QuickInfo &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("kind", Napi::String::New(env, info.GetKind()));
    obj.Set("kindModifiers", Napi::String::New(env, info.GetKindModifiers()));
    obj.Set("textSpan", TextSpanToNapiObject(info.GetTextSpan(), env));

    Napi::Object displayPartsArray = Napi::Object::New(env);
    for (size_t i = 0; i < info.GetDisplayParts().size(); i++) {
        displayPartsArray.Set(std::to_string(i), SymbolDisplayPartToNapiObject(info.GetDisplayParts()[i], env));
    }
    obj.Set("displayParts", displayPartsArray);

    obj.Set("fileName", Napi::String::New(env, info.GetFileName()));

    return obj;
}

Napi::Value GetQuickInfoAtPositionWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    QuickInfo result = lsp->getQuickInfoAtPosition(fileName.c_str(), position);
    return QuickInfoToNapiObject(result, env);
}

Napi::Object ReferenceInfoToNapiObject(const ReferenceInfo &info, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("fileName", Napi::String::New(env, info.fileName));
    obj.Set("start", Napi::Number::New(env, info.start));
    obj.Set("length", Napi::Number::New(env, info.length));
    return obj;
}

Napi::Object ReferencesToNapiObject(const References &info, Napi::Env env)
{
    Napi::Object referencesArray = Napi::Object::New(env);

    for (size_t i = 0; i < info.referenceInfos.size(); i++) {
        referencesArray.Set(std::to_string(i), ReferenceInfoToNapiObject(info.referenceInfos[i], env));
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("referenceInfos", referencesArray);
    return obj;
}

Napi::Value GetReferencesAtPositionWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    References result = lsp->getReferencesAtPosition(fileName.c_str(), position);
    return ReferencesToNapiObject(result, env);
}

Napi::Value GetImplementationAtPositionWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    DefinitionInfo result = lsp->getImplementationAtPosition(fileName.c_str(), position);
    return DefinitionInfoToNapiObject(result, env);
}

Napi::Value GetFileReferencesWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Expected one argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    References result = lsp->getFileReferences(fileName.c_str());
    return ReferencesToNapiObject(result, env);
}

Napi::Object CompletionEntryToNapiObject(const ark::es2panda::lsp::CompletionEntry &entry, Napi::Env env)
{
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("name", Napi::String::New(env, entry.GetName()));
    obj.Set("kind", Napi::Number::New(env, static_cast<int>(entry.GetCompletionKind())));
    obj.Set("sortText", Napi::String::New(env, entry.GetSortText()));
    obj.Set("insertText", Napi::String::New(env, entry.GetInsertText()));

    return obj;
}

Napi::Object CompletionInfoToNapiObject(ark::es2panda::lsp::CompletionInfo &info, Napi::Env env)
{
    Napi::Object entriesArray = Napi::Object::New(env);

    for (size_t i = 0; i < info.GetEntries().size(); i++) {
        entriesArray.Set(std::to_string(i), CompletionEntryToNapiObject(info.GetEntries()[i], env));
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("entries", entriesArray);
    return obj;
}

Napi::Value GetCompletionsAtPositionWrapper(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (info.Length() < INPUT_NUMBER) {
        Napi::TypeError::New(env, "Expected two arguments").ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string fileName = info[0].As<Napi::String>();
    size_t position = info[1].As<Napi::Number>().Uint32Value();

    const LSPAPI *lsp = GetImpl();
    if (!lsp) {
        Napi::Error::New(env, "Failed to get LSP implementation").ThrowAsJavaScriptException();
        return env.Null();
    }

    ark::es2panda::lsp::CompletionInfo result = lsp->getCompletionsAtPosition(fileName.c_str(), position);
    return CompletionInfoToNapiObject(result, env);
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports.Set("getDefinitionAtPosition", Napi::Function::New(env, GetDefinitionAtPositionWrapper));
    exports.Set("getDocumentHighlights", Napi::Function::New(env, GetDocumentHighlightsWrapper));
    exports.Set("getSemanticDiagnostics", Napi::Function::New(env, GetSemanticDiagnosticsWrapper));
    exports.Set("getSyntacticDiagnostics", Napi::Function::New(env, GetSyntacticDiagnosticsWrapper));
    exports.Set("getSuggestionDiagnostics", Napi::Function::New(env, GetSuggestionDiagnosticsWrapper));
    exports.Set("getQuickInfoAtPosition", Napi::Function::New(env, GetQuickInfoAtPositionWrapper));
    exports.Set("getReferencesAtPosition", Napi::Function::New(env, GetReferencesAtPositionWrapper));
    exports.Set("getImplementationAtPosition", Napi::Function::New(env, GetImplementationAtPositionWrapper));
    exports.Set("getFileReferences", Napi::Function::New(env, GetFileReferencesWrapper));
    exports.Set("getCompletionsAtPosition", Napi::Function::New(env, GetCompletionsAtPositionWrapper));
    return exports;
}

NODE_API_MODULE(addon, Init);