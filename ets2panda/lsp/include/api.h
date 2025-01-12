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

#ifndef ES2PANDA_LSP_INCLUDE_API_H
#define ES2PANDA_LSP_INCLUDE_API_H

// Switch off the linter for C header
// NOLINTBEGIN
//

#include <stddef.h>
#include <string>
#include <variant>
#include <vector>
#include "utils/arena_containers.h"
#include "public/es2panda_lib.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DefinitionInfo {
    char *fileName;
} DefinitionInfo;

typedef struct FileReferenceInfo {
    char const *fileName;
    size_t start;
    size_t length;
} FileReferenceInfo;

typedef struct FileReferences {
    ark::ArenaVector<FileReferenceInfo *> *referenceInfos;
    FileReferences(ark::ArenaVector<FileReferenceInfo *> *referenceInfos_)
    {
        this->referenceInfos = referenceInfos_;
    }
} FileReferences;

typedef struct TextSpan {
    size_t start;
    size_t length;
    TextSpan(size_t s, size_t l) : start(s), length(l) {}
} TextSpan;

typedef struct LSPAPI {
    DefinitionInfo *(*getDefinitionAtPosition)(char const *fileName, size_t position);
    FileReferences *(*getFileReferences)(char const *fileName);
    es2panda_AstNode *(*getPrecedingToken)(es2panda_Context *context, const size_t pos);
    std::string (*getCurrentTokenValue)(char const *fileName, size_t position);
    TextSpan *(*getSpanOfEnclosingComment)(char const *fileName, size_t pos, bool onlyMultiLine);
} LSPAPI;

LSPAPI const *GetImpl();

typedef struct Position {
    unsigned int line_;       // Line number
    unsigned int character_;  // Character position in the line

    Position(unsigned int line_num = 0, unsigned int character_pos = 0) : line_(line_num), character_(character_pos) {}
} Position;

typedef struct Range {
    Position start;  // Start position
    Position end;    // End position

    Range(Position start_pos = Position(), Position end_pos = Position()) : start(start_pos), end(end_pos) {}
} Range;

typedef struct Location {
    std::string uri_;  // The URI of the document
    Range range_;      // The range of the diagnostic in the document
    Location(const std::string &uri = "", const Range &range = Range()) : uri_(uri), range_(range) {}
} Location;

enum class DiagnosticSeverity { Error = 1, Warning = 2, Information = 3, Hint = 4 };

enum class DiagnosticTag { Unnecessary = 1, Deprecated = 2 };

typedef struct CodeDescription {
    std::string href_;
    CodeDescription(const std::string &href = "") : href_(href) {}
} CodeDescription;

typedef struct DiagnosticRelatedInformation {
    Location location_;
    std::string message_;

    DiagnosticRelatedInformation(const Location &location = Location(), const std::string &message = "")
        : location_(location), message_(message)
    {
    }
} DiagnosticRelatedInformation;

typedef struct Diagnostic {
    Range range_;                                                   // The range at which the message applies.
    DiagnosticSeverity severity_;                                   // The diagnostic's severity.
    std::variant<int, std::string> code_;                           // The diagnostic's code.
    CodeDescription codeDescription_;                               // The error code description.
    std::string source_;                                            // The source of the diagnostic.
    std::string message_;                                           // The diagnostic's message.
    std::vector<DiagnosticTag> tags_;                               // Additional metadata about the diagnostic.
    std::vector<DiagnosticRelatedInformation> relatedInformation_;  // Related diagnostics.
    std::variant<int, std::string> data_;                           // Additional data.

    Diagnostic(const Range &range, DiagnosticSeverity severity = DiagnosticSeverity::Warning,
               const std::variant<int, std::string> &code = 100, const std::string &message = "default message",
               const CodeDescription &codeDescription = {}, const std::string &source = "default source",
               const std::vector<DiagnosticTag> &tags = {},
               const std::vector<DiagnosticRelatedInformation> &relatedInformation = {},
               const std::variant<int, std::string> &data = {})
        : range_(range),
          severity_(severity),
          code_(code),
          codeDescription_(codeDescription),
          source_(source),
          message_(message),
          tags_(tags),
          relatedInformation_(relatedInformation),
          data_(data)
    {
    }
} Diagnostic;

enum class CommentKind { SINGLE_LINE, MULTI_LINE };

typedef struct CommentRange {
private:
    size_t pos_;
    size_t end_;
    CommentKind kind_;

public:
    CommentRange(size_t p, size_t e, CommentKind k) : pos_(p), end_(e), kind_(k) {}
    size_t GetPos() const
    {
        return pos_;
    }
    size_t GetEnd() const
    {
        return end_;
    }
    CommentKind GetKind() const
    {
        return kind_;
    }
    void SetPos(size_t p)
    {
        pos_ = p;
    }
    void SetKind(CommentKind k)
    {
        kind_ = k;
    }
} CommentRange;

// NOLINTEND

#ifdef __cplusplus
}
#endif

#endif
