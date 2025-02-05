/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_PUBLIC_H
#define ES2PANDA_PUBLIC_H

#include "macros.h"
#include "util/arktsconfig.h"
#include "util/plugin.h"
#include "util/ustring.h"
#include "generated/options.h"

namespace ark::pandasm {
struct Program;
}  // namespace ark::pandasm

namespace ark::es2panda {
using ETSWarnings = util::gen::ets_warnings::Enum;
using EvalMode = util::gen::eval_mode::Enum;
using ScriptExtension = util::gen::extension::Enum;

constexpr std::string_view ES2PANDA_VERSION = "0.1";
namespace util {
class Options;
class DiagnosticEngine;
}  // namespace util
namespace parser {
class ParserImpl;
}  // namespace parser

namespace compiler {
class CompilerImpl;
}  // namespace compiler

namespace varbinder {
class VarBinder;
}  // namespace varbinder

namespace diagnostic {
class DiagnosticKind;
}  // namespace diagnostic

enum class CompilationMode {
    GEN_STD_LIB,
    PROJECT,
    SINGLE_FILE,
};
// CC-OFFNXT(G.FUD.06) switch-case, ODR
inline Language ToLanguage(ScriptExtension ext)
{
    switch (ext) {
        case ScriptExtension::JS:
            return Language(Language::Id::JS);
        case ScriptExtension::TS:
            return Language(Language::Id::TS);
        case ScriptExtension::AS:
            return Language(Language::Id::AS);
        case ScriptExtension::STS:
            return Language(Language::Id::ETS);
        default:
            UNREACHABLE();
    }
    UNREACHABLE();
}

struct SourceFile {
    SourceFile(std::string_view fn, std::string_view s);
    SourceFile(std::string_view fn, std::string_view s, bool m);
    SourceFile(std::string_view fn, std::string_view s, std::string_view rp, bool m);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    std::string_view filePath {};
    std::string_view fileFolder {};
    std::string_view source {};
    std::string_view resolvedPath {};
    bool isModule {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

enum ErrorType { BEGIN = 0, FATAL = BEGIN, SYNTAX, SEMANTIC, WARNING, PLUGIN, COUNT = PLUGIN, INVALID };

// NOLINTBEGIN(modernize-avoid-c-arrays)
inline static constexpr char const ERROR_LITERAL[] = "*ERROR_LITERAL*";
inline static constexpr char const ERROR_TYPE[] = "*ERROR_TYPE*";
inline static constexpr char const INVALID_EXPRESSION[] = "...";
// NOLINTEND(modernize-avoid-c-arrays)

class Error : public std::exception {
public:
    Error() noexcept = default;
    explicit Error(ErrorType type, std::string_view file, std::string_view message) noexcept
        : type_(type), file_(file), message_(message)
    {
    }
    explicit Error(ErrorType type, std::string_view file, std::string_view message, size_t line, size_t offset) noexcept
        : type_(type), file_(file), message_(message), line_(line), offset_(offset)
    {
    }
    // NOTE(schernykh): replace with util::DiagnosticMessegeParams
    explicit Error(const diagnostic::DiagnosticKind *diagnostic, std::vector<std::string> diagnosticParams,
                   std::string_view file, size_t line, size_t offset) noexcept
        : file_(file),
          line_(line),
          offset_(offset),
          diagnosticKind_(diagnostic),
          diagnosticParams_(std::move(diagnosticParams))
    {
    }
    ~Error() override = default;
    DEFAULT_COPY_SEMANTIC(Error);
    DEFAULT_MOVE_SEMANTIC(Error);

    ErrorType Type() const noexcept;

    // NOTE(schernykh): move out from class
    static const char *TypeString(ErrorType type)
    {
        switch (type) {
            case ErrorType::FATAL:
                return "Fatal error";
            case ErrorType::SYNTAX:
                return "SyntaxError";
            case ErrorType::SEMANTIC:
                return "TypeError";
            case ErrorType::WARNING:
                return "Warning";
            case ErrorType::PLUGIN:
                return "Plugin error";
            default:
                UNREACHABLE();
        }
    }

    static bool IsError(ErrorType type)
    {
        switch (type) {
            case ErrorType::FATAL:
            case ErrorType::SYNTAX:
            case ErrorType::SEMANTIC:
            case ErrorType::PLUGIN:
                return true;
            case ErrorType::WARNING:
                return false;
            default:
                UNREACHABLE();
        }
    }

    std::string Message() const;

    const std::string &File() const
    {
        return file_;
    }

    std::pair<size_t, size_t> GetLoc() const
    {
        return {line_, offset_};
    }

    size_t Line() const
    {
        return line_;
    }

    size_t Offset() const
    {
        return offset_;
    }

    bool operator<(const Error &rhs) const
    {
        if (file_ != rhs.File()) {
            return file_ < rhs.File();
        }
        if (line_ != rhs.Line()) {
            return line_ < rhs.Line();
        }
        if (offset_ != rhs.Offset()) {
            return offset_ < rhs.Offset();
        }
        if (type_ != rhs.Type()) {
            return type_ < rhs.Type();
        }
        return false;
    }

    bool operator==(const Error &rhs) const
    {
        if (file_ != rhs.File()) {
            return false;
        }
        if (line_ != rhs.Line()) {
            return false;
        }
        if (offset_ != rhs.Offset()) {
            return false;
        }
        if (type_ != rhs.Type()) {
            return false;
        }
        return message_ == rhs.Message();
    }

private:
    ErrorType type_ {ErrorType::INVALID};
    std::string file_;
    std::string message_ {};
    size_t line_ {};
    size_t offset_ {};
    const diagnostic::DiagnosticKind *diagnosticKind_ {nullptr};
    std::vector<std::string> diagnosticParams_ {};
};

class Compiler {
public:
    explicit Compiler(ScriptExtension ext);
    explicit Compiler(ScriptExtension ext, size_t threadCount);
    explicit Compiler(ScriptExtension ext, size_t threadCount, std::vector<util::Plugin> &&plugins);
    ~Compiler();
    NO_COPY_SEMANTIC(Compiler);
    NO_MOVE_SEMANTIC(Compiler);

    pandasm::Program *Compile(const SourceFile &input, const util::Options &options,
                              util::DiagnosticEngine &diagnosticEngine, uint32_t parseStatus = 0);

    static void DumpAsm(const pandasm::Program *prog);

    // This is used as a _different_ channel of error reporting than GetError().
    // If this is true, the errors in question have already been reported to the user.
    bool IsAnyError() const noexcept;

    const Error &GetError() const noexcept
    {
        return error_;
    }

    std::string GetPhasesList() const;

    std::vector<util::Plugin> const &Plugins()
    {
        return plugins_;
    }

private:
    std::vector<util::Plugin> const plugins_;
    compiler::CompilerImpl *compiler_;
    Error error_;
    ScriptExtension ext_;
};

// g_diagnosticEngine used only for flush diagnostic before unexpected process termination:
// - inside SIGSEGV handler
extern util::DiagnosticEngine *g_diagnosticEngine;
}  // namespace ark::es2panda

#endif
