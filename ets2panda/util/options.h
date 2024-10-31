/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_OPTIONS_H
#define ES2PANDA_UTIL_OPTIONS_H

#include "libpandabase/os/file.h"
#include "es2panda.h"
#include "util/helpers.h"
#include "utils/pandargs.h"
#include "arktsconfig.h"

#include <exception>
#include <fstream>
#include <iostream>
#include <variant>

namespace ark {
class PandArgParser;
class PandaArg;
}  // namespace ark

namespace ark::es2panda::util {
enum class OptionFlags : uint32_t {
    DEFAULT = 0U,
    PARSE_ONLY = 1U << 0U,
    PARSE_MODULE = 1U << 1U,
    SIZE_STAT = 1U << 2U,
};

constexpr int MAX_OPT_LEVEL = 2;

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
    return path.substr(path.find_last_of(ark::os::file::File::GetPathDelim()) + 1);
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
        return compilerOptions_;
    }

    void SetCompilerOptions(const es2panda::CompilerOptions &options)
    {
        compilerOptions_ = options;
    }

    const std::string &ParserInput() const
    {
        return parserInput_;
    }

    const std::string &CompilerOutput() const
    {
        return compilerOutput_;
    }

    void SetCompilerOutput(const std::string &compilerOutput)
    {
        compilerOutput_ = compilerOutput;
    }

    std::string_view LogLevel() const
    {
        switch (logLevel_) {
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

    void DetermineLogLevel(const ark::PandArg<std::string> &logLevel)
    {
        if (const auto logLevelStr = logLevel.GetValue(); !logLevelStr.empty()) {
            if (logLevelStr == "debug") {
                logLevel_ = util::LogLevel::DEBUG;
            } else if (logLevelStr == "info") {
                logLevel_ = util::LogLevel::INFO;
            } else if (logLevelStr == "warning") {
                logLevel_ = util::LogLevel::WARNING;
            } else if (logLevelStr == "error") {
                logLevel_ = util::LogLevel::ERROR;
            } else if (logLevelStr == "fatal") {
                logLevel_ = util::LogLevel::FATAL;
            } else {
                logLevel_ = util::LogLevel::INVALID;
                std::cerr << "Invalid log level: '" << logLevelStr
                          << R"('. Possible values: ["debug", "info", "warning", "error", "fatal"])";
            }
        }
    }

    void DetermineExtension(const ark::PandArg<std::string> &inputExtension,
                            const ark::PandArg<std::string> &arktsConfig, const es2panda::CompilationMode &compMode)
    {
        std::string extension = inputExtension.GetValue();
        std::string sourceFileExtension = sourceFile_.substr(sourceFile_.find_last_of('.') + 1);

        bool extensionIsEmpty = extension.empty();
        if (!sourceFile_.empty() && !extensionIsEmpty && extension != sourceFileExtension) {
            std::cerr << "Warning: Not matching extensions! Sourcefile: " << sourceFileExtension
                      << ", Manual(used): " << extension << std::endl;
        }
        auto tempExtension = !extensionIsEmpty ? extension : sourceFileExtension;
        if (tempExtension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
#ifndef PANDA_WITH_ECMASCRIPT
            errorMsg_ = "js extension is not supported within current build";
            extension_ = es2panda::ScriptExtension::INVALID;
            return;
#endif
        } else if (tempExtension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (tempExtension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else if (tempExtension == "sts") {
            extension_ = es2panda::ScriptExtension::ETS;

            std::ifstream inputStream(arktsConfig.GetValue());
            if (inputStream.fail()) {
                errorMsg_ = "Failed to open arktsconfig: ";
                errorMsg_.append(arktsConfig.GetValue());
                extension_ = es2panda::ScriptExtension::INVALID;
                return;
            }
        } else if (extensionIsEmpty && (compMode == CompilationMode::PROJECT)) {
            extension_ = es2panda::ScriptExtension::ETS;
        } else {
            if (!extensionIsEmpty) {
                errorMsg_ = "Invalid extension (available options: js, ts, as, sts)";
            } else {
                errorMsg_ =
                    "Unknown extension of sourcefile, set the extension manually or change the file format (available "
                    "options: js, ts, as, sts)";
            }
            extension_ = es2panda::ScriptExtension::INVALID;
            return;
        }
    }

    CompilationMode DetermineCompilationMode(const ark::PandArg<bool> &genStdLib,
                                             const ark::PandArg<std::string> &inputFile) const
    {
        return genStdLib.GetValue()           ? CompilationMode::GEN_STD_LIB
               : inputFile.GetValue().empty() ? CompilationMode::PROJECT
                                              : CompilationMode::SINGLE_FILE;
    }

    void AddOptionFlags(const ark::PandArg<bool> &opParseOnly, const ark::PandArg<bool> &opModule,
                        const ark::PandArg<bool> &opSizeStat)
    {
        if (opParseOnly.GetValue()) {
            options_ |= OptionFlags::PARSE_ONLY;
        }

        if (opModule.GetValue()) {
            options_ |= OptionFlags::PARSE_MODULE;
        }

        if (opSizeStat.GetValue()) {
            options_ |= OptionFlags::SIZE_STAT;
        }
    }

    std::optional<ArkTsConfig> ParseArktsConfig(std::string_view path)
    {
        auto config = ArkTsConfig {path};
        if (!config.Parse()) {
            errorMsg_ = "Invalid ArkTsConfig path: ";
            errorMsg_.append(path);
            return std::nullopt;
        }
        return std::make_optional(config);
    }

    bool ProcessEtsSpecificOptions(std::string_view arktsConfigPath, const es2panda::CompilationMode &compMode)
    {
        if (extension_ != es2panda::ScriptExtension::ETS && compMode == CompilationMode::PROJECT) {
            errorMsg_ = "Error: only --extension=sts is supported for project compilation mode.";
            return false;
        }

        if (extension_ != es2panda::ScriptExtension::ETS) {
            return true;
        }

        if (auto config = ParseArktsConfig(arktsConfigPath); config != std::nullopt) {
            compilerOptions_.arktsConfig = std::make_shared<ArkTsConfig>(*config);
        } else {
            return false;
        }

        return true;
    }

    const std::string &SourceFile() const
    {
        return sourceFile_;
    }

    const std::string &ErrorMsg() const
    {
        return errorMsg_;
    }

    int OptLevel() const
    {
        return optLevel_;
    }

    int ThreadCount() const
    {
        return threadCount_;
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
        return listFiles_;
    }

    bool ListPhases() const
    {
        return listPhases_;
    }

private:
    es2panda::ScriptExtension extension_ {es2panda::ScriptExtension::JS};
    OptionFlags options_ {OptionFlags::DEFAULT};
    es2panda::CompilerOptions compilerOptions_ {};
    ark::PandArgParser *argparser_;
    std::string parserInput_;
    std::string compilerOutput_;
    std::string result_;
    std::string sourceFile_;
    std::string errorMsg_;
    int optLevel_ {0};
    int threadCount_ {0};
    bool listFiles_ {false};
    bool listPhases_ {false};
    util::LogLevel logLevel_ {util::LogLevel::ERROR};
};
}  // namespace ark::es2panda::util

#endif  // UTIL_OPTIONS_H
