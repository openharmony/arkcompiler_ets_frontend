/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_AOT_OPTIONS_H
#define ES2PANDA_AOT_OPTIONS_H

#include "libpandabase/os/file.h"
#include "plugins/ecmascript/es2panda/es2panda.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"

#include <exception>
#include <fstream>
#include <iostream>

namespace panda {
class PandArgParser;
class PandaArg;
}  // namespace panda

namespace panda::es2panda::aot {
enum class OptionFlags : uint32_t {
    DEFAULT = 0U,
    PARSE_ONLY = 1U << 0U,
    PARSE_MODULE = 1U << 1U,
    SIZE_STAT = 1U << 2U,
};

inline std::underlying_type_t<OptionFlags> operator&(OptionFlags a, OptionFlags b)
{
    using Utype = std::underlying_type_t<OptionFlags>;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    return static_cast<Utype>(static_cast<Utype>(a) & static_cast<Utype>(b));
}

inline OptionFlags &operator|=(OptionFlags &a, OptionFlags b)
{
    using Utype = std::underlying_type_t<OptionFlags>;
    /* NOLINTNEXTLINE(hicpp-signed-bitwise) */
    return a = static_cast<OptionFlags>(static_cast<Utype>(a) | static_cast<Utype>(b));
}

template <class T>
T BaseName(T const &path)
{
    return path.substr(path.find_last_of(panda::os::file::File::GetPathDelim()) + 1);
}

class Options {
public:
    Options();
    NO_COPY_SEMANTIC(Options);
    NO_MOVE_SEMANTIC(Options);
    ~Options();

    bool Parse(int argc, const char **argv);

    es2panda::ScriptExtension Extension() const
    {
        return extension_;
    }

    const es2panda::CompilerOptions &CompilerOptions() const
    {
        return compiler_options_;
    }

    const std::string &ParserInput() const
    {
        return parser_input_;
    }

    const std::string &CompilerOutput() const
    {
        return compiler_output_;
    }

    void SetCompilerOutput(const std::string &compiler_output)
    {
        compiler_output_ = compiler_output;
    }

    std::string_view LogLevel() const
    {
        switch (log_level_) {
            case util::LogLevel::DEBUG: {
                return "debug";
            }
            case util::LogLevel::INFO: {
                return "info";
            }
            case util::LogLevel::WARNING: {
                return "warning";
            }
            case util::LogLevel::ERROR: {
                return "error";
            }
            case util::LogLevel::FATAL: {
                return "fatal";
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    const std::string &SourceFile() const
    {
        return source_file_;
    }

    const std::string &ErrorMsg() const
    {
        return error_msg_;
    }

    int OptLevel() const
    {
        return opt_level_;
    }

    int ThreadCount() const
    {
        return thread_count_;
    }

    bool ParseModule() const
    {
        return (options_ & OptionFlags::PARSE_MODULE) != 0;
    }

    bool ParseOnly() const
    {
        return (options_ & OptionFlags::PARSE_ONLY) != 0;
    }

    bool SizeStat() const
    {
        return (options_ & OptionFlags::SIZE_STAT) != 0;
    }

    bool IsDynamic() const
    {
        return extension_ != es2panda::ScriptExtension::ETS;
    }

    bool ListFiles() const
    {
        return list_files_;
    }

private:
    es2panda::ScriptExtension extension_ {es2panda::ScriptExtension::JS};
    OptionFlags options_ {OptionFlags::DEFAULT};
    es2panda::CompilerOptions compiler_options_ {};
    panda::PandArgParser *argparser_;
    std::string parser_input_;
    std::string compiler_output_;
    std::string result_;
    std::string source_file_;
    std::string error_msg_;
    int opt_level_ {0};
    int thread_count_ {0};
    bool list_files_ {false};
    util::LogLevel log_level_ {util::LogLevel::ERROR};
};
}  // namespace panda::es2panda::aot

#endif  // AOT_OPTIONS_H
