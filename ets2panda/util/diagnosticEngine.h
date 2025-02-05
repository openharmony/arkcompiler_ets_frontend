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

#ifndef ES2PANDA_UTIL_DIAGNOSTIC_ENGINE_H
#define ES2PANDA_UTIL_DIAGNOSTIC_ENGINE_H

#include "es2panda.h"
#include "lexer/token/tokenType.h"
#include "generated/diagnostic.h"

namespace ark::es2panda::lexer {
class SourcePosition;
class SourceLocation;
}  // namespace ark::es2panda::lexer

namespace ark::es2panda::parser {
class Program;
}  // namespace ark::es2panda::parser

namespace ark::es2panda::checker {
class Type;
class Signature;
}  // namespace ark::es2panda::checker
namespace ark::es2panda::util {

class AsSrc {
public:
    explicit AsSrc(const checker::Type *type) : type_(const_cast<checker::Type *>(type)) {}

    const checker::Type *GetType() const
    {
        return type_;
    }

private:
    checker::Type *type_;
};

using DiagnosticMessageElement = std::variant<const checker::Type *, AsSrc, char *, util::StringView, lexer::TokenType,
                                              size_t, const checker::Signature *>;
using DiagnosticMessageParams = std::initializer_list<DiagnosticMessageElement>;

class DiagnosticPrinter {
public:
    DiagnosticPrinter() = default;
    NO_COPY_SEMANTIC(DiagnosticPrinter);
    NO_MOVE_SEMANTIC(DiagnosticPrinter);
    virtual ~DiagnosticPrinter() = default;

    virtual void Print(const Error &diagnostic) const = 0;
};

class CLIDiagnosticPrinter : public DiagnosticPrinter {
public:
    CLIDiagnosticPrinter() = default;
    NO_COPY_SEMANTIC(CLIDiagnosticPrinter);
    NO_MOVE_SEMANTIC(CLIDiagnosticPrinter);
    ~CLIDiagnosticPrinter() override = default;

    void Print(const Error &diagnostic) const override;
};

class DiagnosticEngine {
public:
    explicit DiagnosticEngine() : printer_(std::make_unique<CLIDiagnosticPrinter>())
    {
        g_diagnosticEngine = this;
    }
    NO_COPY_SEMANTIC(DiagnosticEngine);
    NO_MOVE_SEMANTIC(DiagnosticEngine);
    ~DiagnosticEngine()
    {
        FlushDiagnostic();
        g_diagnosticEngine = nullptr;
    }

    // NOTE(schernykh): should be removed
    Error GetAnyError() const;

    bool IsAnyError() const;

    template <typename... T>
    void LogDiagnostic(const es2panda::diagnostic::DiagnosticKind *diagnosticKind, T &&...args)
    {
        diagnostics_[diagnosticKind->Type()].emplace_back(diagnosticKind, std::forward<T>(args)...);
    }
    // NOTE(schernykh): should be removed
    void Log(const Error &error);

    // NOTE(schernykh): revisit after implementing yaml files
    void LogSyntaxError(const parser::Program *program, std::string_view errorMessage,
                        const lexer::SourceLocation &pos);
    void LogSyntaxError(const parser::Program *program, std::string_view errorMessage,
                        const lexer::SourcePosition &pos);
    void LogSyntaxError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                        const lexer::SourcePosition &pos);
    void LogFatalError(std::string_view errorMessage);
    void LogFatalError(DiagnosticMessageParams errorMessageParts);
    void LogFatalError(const parser::Program *program, std::string_view errorMessage, const lexer::SourcePosition &pos);
    void LogFatalError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                       const lexer::SourcePosition &pos);
    void LogSemanticError(const parser::Program *program, std::string_view errorMessage,
                          const lexer::SourcePosition &pos);
    void LogSemanticError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                          const lexer::SourcePosition &pos);
    void LogWarning(std::string_view errorMessage);
    void LogWarning(DiagnosticMessageParams errorMessageParts);
    void LogWarning(const parser::Program *program, std::string_view errorMessage, const lexer::SourcePosition &pos);
    void LogWarning(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                    const lexer::SourcePosition &pos);

    // NOTE(schernykh): should not be able from STS
    [[noreturn]] void ThrowFatalError(const parser::Program *program, std::string_view errorMessage,
                                      const lexer::SourcePosition &pos);
    [[noreturn]] void ThrowFatalError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                      const lexer::SourcePosition &pos);
    [[noreturn]] void ThrowSemanticError(const parser::Program *program, std::string_view errorMessage,
                                         const lexer::SourcePosition &pos);
    [[noreturn]] void ThrowSemanticError(const parser::Program *program, DiagnosticMessageParams errorMessageParts,
                                         const lexer::SourcePosition &pos);

    void FlushDiagnostic();
    void SetWError(bool wError)
    {
        wError_ = wError;
    }

    std::vector<Error> &GetDiagnosticStorage(ErrorType type);

private:
    bool IsError(ErrorType type) const;
    std::vector<Error> GetAllDiagnostic();
    std::string Format(DiagnosticMessageParams list);
    void LogDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                       const lexer::SourcePosition &pos);
    void LogDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                       const lexer::SourceLocation &pos);
    [[noreturn]] void ThrowDiagnostic(ErrorType type, const parser::Program *program, std::string_view errorMessage,
                                      const lexer::SourcePosition &pos);
    void WriteLog(const Error &error);

private:
    std::array<std::vector<Error>, static_cast<size_t>(ErrorType::COUNT)> diagnostics_;
    std::unique_ptr<const DiagnosticPrinter> printer_;
    bool wError_ {false};
};

}  // namespace ark::es2panda::util

#endif  // ES2PANDA_UTIL_DIAGNOSTIC_ENGINE_H
