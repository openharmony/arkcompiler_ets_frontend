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

#include "diagnosticEngine.h"
#include "util/options.h"
#include "lexer/token/sourceLocation.h"
#include "parser/program/program.h"
#include "checker/types/type.h"
#include "checker/types/signature.h"

namespace ark::es2panda::util {

void CLIDiagnosticPrinter::Print(const Error &diagnostic) const
{
    std::cout << Error::TypeString(diagnostic.Type()) << ": " << diagnostic.Message();
    if (!diagnostic.File().empty()) {
        std::cout << " [" << util::BaseName(diagnostic.File()) << ":" << diagnostic.Line() << ":" << diagnostic.Offset()
                  << "]";
    }
    std::cout << std::endl;
}

std::vector<Error> &DiagnosticEngine::GetDiagnosticStorage(ErrorType type)
{
    return diagnostics_[type];
}

void DiagnosticEngine::WriteLog(const Error &error)
{
    GetDiagnosticStorage(error.Type()).emplace_back(error);
}

void DiagnosticEngine::Log(const Error &error)
{
    WriteLog(error);
}

void DiagnosticEngine::LogDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                                     const lexer::SourcePosition &pos)
{
    if (program != nullptr) {
        lexer::SourceLocation loc = pos.ToLocation(program);
        WriteLog(Error {type, program->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col});
    } else {
        WriteLog(Error {type, "", errorMessage, 0, 0});
    }
}

void DiagnosticEngine::LogDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                                     const lexer::SourceLocation &pos)
{
    if (program != nullptr) {
        WriteLog(Error {type, program->SourceFilePath().Utf8(), errorMessage, pos.line, pos.col});
    } else {
        WriteLog(Error {type, "", errorMessage, 0, 0});
    }
}

void DiagnosticEngine::ThrowDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                                       const lexer::SourcePosition &pos)
{
    lexer::SourceLocation loc = pos.ToLocation(program);
    throw Error {type, program->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col};
}

void DiagnosticEngine::LogSyntaxError(const parser::Program *program, std::string_view errorMessage,
                                      const lexer::SourceLocation &pos)
{
    LogDiagnostic(ErrorType::SYNTAX, program, errorMessage, pos);
}

void DiagnosticEngine::LogSyntaxError(const parser::Program *program, std::string_view errorMessage,
                                      const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::SYNTAX, program, errorMessage, pos);
}

void DiagnosticEngine::LogSyntaxError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                      const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::SYNTAX, program, Format(errorMessageParts), pos);
}

void DiagnosticEngine::LogFatalError(std::string_view errorMessage)
{
    LogDiagnostic(ErrorType::FATAL, nullptr, errorMessage, lexer::SourcePosition {});
}

void DiagnosticEngine::LogFatalError(DiagnosticMessageParams errorMessageParts)
{
    LogDiagnostic(ErrorType::FATAL, nullptr, Format(errorMessageParts), lexer::SourcePosition {});
}

void DiagnosticEngine::LogFatalError(const parser::Program *program, std::string_view errorMessage,
                                     const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::FATAL, program, errorMessage, pos);
}

void DiagnosticEngine::LogFatalError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                     const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::FATAL, program, Format(errorMessageParts), pos);
}

void DiagnosticEngine::LogSemanticError(const parser::Program *program, std::string_view errorMessage,
                                        const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::SEMANTIC, program, errorMessage, pos);
}

void DiagnosticEngine::LogSemanticError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                        const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::SEMANTIC, program, Format(errorMessageParts), pos);
}

void DiagnosticEngine::LogWarning(const parser::Program *program, std::string_view errorMessage,
                                  const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::WARNING, program, errorMessage, pos);
}

void DiagnosticEngine::LogWarning(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                  const lexer::SourcePosition &pos)
{
    LogDiagnostic(ErrorType::WARNING, program, Format(errorMessageParts), pos);
}

void DiagnosticEngine::LogWarning(std::string_view errorMessage)
{
    LogDiagnostic(ErrorType::WARNING, nullptr, errorMessage, lexer::SourcePosition {});
}

void DiagnosticEngine::LogWarning(DiagnosticMessageParams errorMessageParts)
{
    LogDiagnostic(ErrorType::WARNING, nullptr, Format(errorMessageParts), lexer::SourcePosition {});
}

void DiagnosticEngine::ThrowFatalError(const parser::Program *program, std::string_view errorMessage,
                                       const lexer::SourcePosition &pos)
{
    ThrowDiagnostic(ErrorType::FATAL, program, errorMessage, pos);
}

void DiagnosticEngine::ThrowFatalError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                       const lexer::SourcePosition &pos)
{
    ThrowDiagnostic(ErrorType::FATAL, program, Format(errorMessageParts), pos);
}

void DiagnosticEngine::ThrowSemanticError(const parser::Program *program, std::string_view errorMessage,
                                          const lexer::SourcePosition &pos)
{
    ThrowDiagnostic(ErrorType::SEMANTIC, program, errorMessage, pos);
}

void DiagnosticEngine::ThrowSemanticError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                          const lexer::SourcePosition &pos)
{
    ThrowDiagnostic(ErrorType::SEMANTIC, program, Format(errorMessageParts), pos);
}

std::string DiagnosticEngine::Format(DiagnosticMessageParams list)
{
    std::stringstream ss;

    for (const auto &it : list) {
        if (std::holds_alternative<char *>(it)) {
            ss << (std::get<char *>(it));
        } else if (std::holds_alternative<util::StringView>(it)) {
            ss << (std::get<util::StringView>(it));
        } else if (std::holds_alternative<lexer::TokenType>(it)) {
            ss << (TokenToString(std::get<lexer::TokenType>(it)));
        } else if (std::holds_alternative<const checker::Type *>(it)) {
            std::get<const checker::Type *>(it)->ToString(ss);
        } else if (std::holds_alternative<AsSrc>(it)) {
            std::get<AsSrc>(it).GetType()->ToStringAsSrc(ss);
        } else if (std::holds_alternative<size_t>(it)) {
            ss << (std::to_string(std::get<size_t>(it)));
        } else if (std::holds_alternative<const checker::Signature *>(it)) {
            std::get<const checker::Signature *>(it)->ToString(ss, nullptr, true);
        } else {
            UNREACHABLE();
        }
    }

    return ss.str();
}

std::vector<Error> DiagnosticEngine::GetAllDiagnostic()
{
    size_t totalSize = 0;
    for (const auto &vec : diagnostics_) {
        totalSize += vec.size();
    }

    std::vector<Error> merged;
    merged.reserve(totalSize);
    for (const auto &vec : diagnostics_) {
        merged.insert(merged.end(), vec.begin(), vec.end());
    }

    return merged;
}

void DiagnosticEngine::FlushDiagnostic()
{
    auto log = GetAllDiagnostic();
    std::sort(log.begin(), log.end());
    auto last = std::unique(log.begin(), log.end());
    for (auto it = log.begin(); it != last; it++) {
        printer_->Print(*it);
    }
}

bool DiagnosticEngine::IsAnyError() const
{
    for (size_t i = ErrorType::BEGIN; i < ErrorType::COUNT; ++i) {
        if (IsError(static_cast<ErrorType>(i)) && !diagnostics_[i].empty()) {
            return true;
        }
    }
    return false;
}

Error DiagnosticEngine::GetAnyError() const
{
    ASSERT(IsAnyError());
    for (size_t i = ErrorType::BEGIN; i < ErrorType::COUNT; ++i) {
        if (IsError(static_cast<ErrorType>(i)) && !diagnostics_[i].empty()) {
            return diagnostics_[i].front();
        }
    }
    UNREACHABLE();
}

bool DiagnosticEngine::IsError(ErrorType type) const
{
    switch (type) {
        case ErrorType::FATAL:
        case ErrorType::SYNTAX:
        case ErrorType::SEMANTIC:
        case ErrorType::PLUGIN:
            return true;
        case ErrorType::WARNING:
            return wError_;
        default:
            UNREACHABLE();
    }
}

}  // namespace ark::es2panda::util
