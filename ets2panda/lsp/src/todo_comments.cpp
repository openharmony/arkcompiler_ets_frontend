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

#include <regex>
#include "internal_api.h"
#include "todo_comments.h"
#include "lexer/token/letters.h"
#include "public/public.h"

namespace {
bool IsNodeModulesFile(const std::string_view &path)
{
    return path.find("/node_modules/") != std::string::npos;
}

bool IsOHModulesFile(const std::string_view &path)
{
    return path.find("/oh_modules/") != std::string::npos;
}

bool IsLetterOrDigit(char32_t c)
{
    return (c >= ark::es2panda::lexer::LEX_CHAR_LOWERCASE_A && c <= ark::es2panda::lexer::LEX_CHAR_LOWERCASE_Z) ||
           (c >= ark::es2panda::lexer::LEX_CHAR_UPPERCASE_A && c <= ark::es2panda::lexer::LEX_CHAR_UPPERCASE_Z) ||
           (c >= ark::es2panda::lexer::LEX_CHAR_0 && c <= ark::es2panda::lexer::LEX_CHAR_9);
}

// Function to escape regex special characters
std::string EscapeRegExp(const std::string &str)
{
    std::string escaped;
    for (char c : str) {
        if (std::string("-[]/{}()*+?.\\^$|").find(c) != std::string::npos) {
            escaped += '\\';  // Escape special characters
        }
        escaped += c;
    }
    return escaped;
}

std::regex GetTodoCommentsRegExp(const std::vector<ark::es2panda::lsp::TodoCommentDescriptor> &descriptors)
{
    // Single-line comments: // TO-DO or //// TO-DO
    std::string singleLineCommentStart = R"((?:\/\/+\s*))";

    // Multi-line comment start: /* TO-DO or /** TO-DO
    std::string multiLineCommentStart = R"((?:\/\*+\s*))";

    // Any number of spaces or `*` at the start of a line (for block comments)
    std::string anyNumberOfSpacesAndAsterisksAtStartOfLine = R"((?:^(?:\s|\*)*))";

    // Match any of the comment start patterns
    std::string preamble = "(" + singleLineCommentStart + "|" + multiLineCommentStart + "|" +
                           anyNumberOfSpacesAndAsterisksAtStartOfLine + ")";

    /*
     * This comments includes commonly flagged descriptors such as "TO-DO", "FIX-ME", "NOTE", "HACK", "FIX", "WARNING".
     * A regex is created to identify these patterns intentionally.
     */
    std::vector<std::string> literalGroups;
    literalGroups.reserve(descriptors.size());
    for (const auto &d : descriptors) {
        literalGroups.push_back("(" + EscapeRegExp(d.GetText()) + ")");
    }

    // Join the literal groups with '|'
    std::string literals;
    for (size_t i = 0; i < literalGroups.size(); ++i) {
        if (i > 0) {
            literals += "|";
        }
        literals += literalGroups[i];
    }
    literals = "(?:" + literals + ")";

    // Match the remainder of the line (up to the end of line or block comment end `*/`)
    std::string messageRemainder = R"((?:.*?))";
    std::string endOfLineOrEndOfComment = R"((?:$|\*\/))";

    // Final regex string
    std::string regExpString = preamble + "(" + literals + messageRemainder + ")" + endOfLineOrEndOfComment;

    // Return compiled regex (case insensitive only)
    return std::regex(regExpString, std::regex_constants::icase);
}

std::vector<std::string> SplitLines(const std::string_view &input)
{
    std::vector<std::string> lines;
    size_t pos = 0;
    size_t newLinePos = 0;

    while ((newLinePos = input.find('\n', pos)) != std::string_view::npos) {
        lines.emplace_back(input.substr(pos, newLinePos - pos));
        pos = newLinePos + 1;
    }

    // Add the last line if there's content after the last newline
    if (pos < input.length()) {
        lines.emplace_back(input.substr(pos));
    }

    return lines;
}

// Helper function to find the correct descriptor
const ark::es2panda::lsp::TodoCommentDescriptor *FindMatchedDescriptor(
    const std::cmatch &match, const std::vector<ark::es2panda::lsp::TodoCommentDescriptor> &descriptors,
    size_t &firstDescriptorCaptureIndex)
{
    for (size_t i = 0; i < descriptors.size(); i++) {
        if (match[i + firstDescriptorCaptureIndex].matched) {
            return &descriptors[i];
        }
    }
    return nullptr;
}

std::string ExtractAndCleanMessage(const std::string &rawMessage, const std::string &preamble)
{
    std::string message = rawMessage;

    // For block comments, strip leading asterisks if present
    if (message.find('*') != std::string::npos &&
        (preamble.find("/*") != std::string::npos || preamble.find('*') != std::string::npos)) {
        // This is a block comment - clean up asterisks
        size_t firstNonAsterisk = message.find_first_not_of("* \t");
        if (firstNonAsterisk != std::string::npos) {
            message = message.substr(firstNonAsterisk);
        }
    }

    return message;
}

bool ProcessMatchedTodo(const ark::es2panda::lsp::TodoMatchContext &ctx, const std::cmatch &match)
{
    const size_t preambleIndex = 1;
    size_t firstDescriptorCaptureIndex = 3;
    const size_t messageIndex = 2;

    // Find which descriptor matched
    const ark::es2panda::lsp::TodoCommentDescriptor *descriptor =
        FindMatchedDescriptor(match, ctx.descriptors, firstDescriptorCaptureIndex);

    if (descriptor == nullptr) {
        return false;
    }

    std::string preamble = match[preambleIndex].str();

    // Calculate absolute position in the file
    size_t matchPositionInLine = std::distance(ctx.line->c_str(), match[0].first);
    size_t matchPosition = ctx.lineStart + matchPositionInLine;
    size_t descriptorPosition = matchPosition + preamble.length();

    // We don't want to match something like 'TODOBY'
    size_t afterTodoPos = descriptorPosition + descriptor->GetText().length();
    if (afterTodoPos < ctx.fileContents.length() && IsLetterOrDigit(ctx.fileContents[afterTodoPos])) {
        return false;
    }

    // Verify this is in a comment
    if (ark::es2panda::lsp::GetTouchingToken(ctx.context, descriptorPosition, true) != nullptr) {
        return false;
    }

    std::string message = ExtractAndCleanMessage(match[messageIndex].str(), preamble);

    ctx.result.emplace_back(*descriptor, message, descriptorPosition);
    return true;
}
}  // namespace

namespace ark::es2panda::lsp {
std::vector<ark::es2panda::lsp::TodoComment> GetTodoCommentsImpl(
    es2panda_Context *context, std::vector<ark::es2panda::lsp::TodoCommentDescriptor> &descriptors,
    CancellationToken *cancellationToken)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);

    if (cancellationToken->IsCancellationRequested()) {
        return {};
    }

    if (descriptors.empty() || IsNodeModulesFile(ctx->sourceFile->filePath) ||
        IsOHModulesFile(ctx->sourceFile->filePath)) {
        return {};
    }

    auto fileContents = ctx->sourceFile->source;
    std::vector<TodoComment> result;

    // Split the file content into lines to handle line-by-line processing
    std::vector<std::string> lines = SplitLines(fileContents);
    std::regex regExp = GetTodoCommentsRegExp(descriptors);

    TodoMatchContext matchContext = {context, descriptors, 0, nullptr, fileContents, result};

    size_t lineStart = 0;
    for (const auto &line : lines) {
        if (cancellationToken->IsCancellationRequested()) {
            return {};
        }

        matchContext.lineStart = lineStart;
        matchContext.line = &line;

        std::cmatch match;
        std::string_view lineView(line);
        const char *lineData = lineView.data();
        const char *lineEnd = lineData;
        std::advance(lineEnd, lineView.size());

        while (std::regex_search(lineData, lineEnd, match, regExp)) {
            ProcessMatchedTodo(matchContext, match);
            lineData = match.suffix().first;
        }

        // Move to next line (add +1 for newline character)
        lineStart += lineView.size() + 1;
    }

    return result;
}
}  // namespace ark::es2panda::lsp
