/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <string>
#include <functional>
#include <memory>

namespace panda::pandasm {
struct Program;
}  // namespace panda::pandasm

namespace panda::es2panda {
namespace parser {
class ParserImpl;
}  // namespace parser

namespace compiler {
class CompilerImpl;
class CompilerContext;
}  // namespace compiler

namespace binder {
class Binder;
}  // namespace binder

enum class ScriptExtension {
    JS,
    TS,
    AS,
    ETS,
};

enum class CompilationMode {
    GEN_STD_LIB,
    PROJECT,
    SINGLE_FILE,
};

inline Language ToLanguage(ScriptExtension ext)
{
    switch (ext) {
        case ScriptExtension::JS:
            return Language(Language::Id::JS);
        case ScriptExtension::TS:
            return Language(Language::Id::TS);
        case ScriptExtension::AS:
            return Language(Language::Id::AS);
        case ScriptExtension::ETS:
            return Language(Language::Id::ETS);
    }
    UNREACHABLE();
}

struct SourceFile {
    SourceFile(std::string_view fn, std::string_view s);
    SourceFile(std::string_view fn, std::string_view s, bool m);
    SourceFile(std::string_view fn, std::string_view s, std::string_view rp, bool m);

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    std::string_view file_name {};
    std::string_view file_path {};
    std::string_view source {};
    std::string_view resolved_path {};
    bool is_module {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

struct CompilerOptions {
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    bool is_debug {};
    bool is_ets_module {};
    bool is_eval {};
    bool is_direct_eval {};
    bool is_function_eval {};
    bool dump_ast {};
    bool dump_checked_ast {};
    bool dump_asm {};
    bool dump_debug_info {};
    bool parse_only {};
    std::string std_lib {};
    std::string ts_decl_out {};
    std::shared_ptr<ArkTsConfig> arkts_config {};
    CompilationMode compilation_mode {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

enum class ErrorType {
    INVALID,
    GENERIC,
    SYNTAX,
    TYPE,
};

class Error : public std::exception {
public:
    Error() noexcept = default;
    explicit Error(ErrorType type, std::string_view file, std::string_view message) noexcept
        : type_(type), file_(file), message_(message)
    {
    }
    explicit Error(ErrorType type, std::string_view file, std::string_view message, size_t line, size_t column) noexcept
        : type_(type), file_(file), message_(message), line_(line), col_(column)
    {
    }
    ~Error() override = default;
    DEFAULT_COPY_SEMANTIC(Error);
    DEFAULT_MOVE_SEMANTIC(Error);

    ErrorType Type() const noexcept
    {
        return type_;
    }

    const char *TypeString() const noexcept
    {
        switch (type_) {
            case ErrorType::SYNTAX:
                return "SyntaxError";
            case ErrorType::TYPE:
                return "TypeError";
            default:
                break;
        }

        return "Error";
    }

    const char *what() const noexcept override
    {
        return message_.c_str();
    }

    int ErrorCode() const noexcept
    {
        return error_code_;
    }

    const std::string &Message() const noexcept
    {
        return message_;
    }

    const std::string &File() const noexcept
    {
        return file_;
    }

    size_t Line() const
    {
        return line_;
    }

    size_t Col() const
    {
        return col_;
    }

private:
    ErrorType type_ {ErrorType::INVALID};
    std::string file_;
    std::string message_;
    size_t line_ {};
    size_t col_ {};
    int error_code_ {1};
};

class Compiler {
public:
    explicit Compiler(ScriptExtension ext);
    explicit Compiler(ScriptExtension ext, size_t thread_count);
    ~Compiler();
    NO_COPY_SEMANTIC(Compiler);
    NO_MOVE_SEMANTIC(Compiler);

    pandasm::Program *Compile(const SourceFile &input, const CompilerOptions &options, uint32_t parse_status = 0);

    inline pandasm::Program *Compile(const SourceFile &input)
    {
        CompilerOptions options;

        return Compile(input, options, 0);
    }

    static void DumpAsm(const pandasm::Program *prog);

    const Error &GetError() const noexcept
    {
        return error_;
    }

private:
    compiler::CompilerImpl *compiler_;
    Error error_;
    ScriptExtension ext_;
};
}  // namespace panda::es2panda

#endif
