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

#ifndef ES2PANDA_LSP_COMPLETIONS_H
#define ES2PANDA_LSP_COMPLETIONS_H

#include <string>
#include <vector>

namespace ark::es2panda::lsp {

enum class ScriptElementKind {
    UNKNOWN,
    WARNING,
    KEYWORD,
    SCRIPT_ELEMENT,
    MODULE_ELEMENT,
    CLASS_ELEMENT,
    LOCAL_CLASS_ELEMENT,
    INTERFACE_ELEMENT,
    TYPE_ELEMENT,
    ENUM_ELEMENT,
    ENUM_MEMBER_ELEMENT,
    VARIABLE_ELEMENT,
    LOCAL_VARIABLE_ELEMENT,
    FUNCTION_ELEMENT,
    LOCAL_FUNCTION_ELEMENT,
    MEMBER_FUNCTION_ELEMENT,
    MEMBER_GET_ACCESSOR_ELEMENT,
    MEMBER_SET_ACCESSOR_ELEMENT,
    MEMBER_VARIABLE_ELEMENT,
    CONSTRUCTOR_IMPLEMENTATION_ELEMENT,
    CALL_SIGNATURE_ELEMENT,
    INDEX_SIGNATURE_ELEMENT,
    CONSTRUCT_SIGNATURE_ELEMENT,
    PARAMETER_ELEMENT,
    TYPE_PARAMETER_ELEMENT,
    PRIMITIVE_TYPE,
    LABEL,
    ALIAS,
    CONST_ELEMENT,
    LET_ELEMENT,
    DIRECTORY,
    EXTERNAL_MODULE_NAME
};

namespace sort_text {
constexpr std::string_view LOCAL_DECLARATION_PRIORITY = "10";
constexpr std::string_view LOCATION_PRIORITY = "11";
constexpr std::string_view OPTIONAL_MEMBER = "12";
constexpr std::string_view MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT = "13";
constexpr std::string_view SUGGESTED_CLASS_MEMBERS = "14";
constexpr std::string_view GLOBALS_OR_KEYWORDS = "15";
constexpr std::string_view AUTO_IMPORT_SUGGESTIONS = "16";
constexpr std::string_view CLASS_MEMBER_SNIPPETS = "17";
}  // namespace sort_text

struct CompletionEntry {
    std::string name;
    ScriptElementKind kind;
    std::string_view sortText;
};

enum class CompletionDataKind { DATA, KEYWORDS };

struct Request {
    CompletionDataKind kind;
    std::vector<CompletionEntry> keywordCompletions;
};

std::vector<CompletionEntry> AllKeywordsCompletions();
std::vector<CompletionEntry> GetKeywordCompletions(const std::string &input);
Request KeywordCompletionData(const std::string &input);
std::string ToLowerCase(const std::string &str);

}  // namespace ark::es2panda::lsp
#endif