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

#ifndef ES2PANDA_UTIL_OPTIONS_H
#define ES2PANDA_UTIL_OPTIONS_H

#include "libpandabase/os/file.h"
#include "libpandabase/utils/logger.h"
#include "util/helpers.h"
#include "utils/pandargs.h"
#include "arktsconfig.h"
#include "es2panda.h"

#include <exception>
#include <fstream>
#include <iostream>
#include <variant>

namespace ark::es2panda::util {

namespace eval_mode = gen::eval_mode;
namespace extension = gen::extension;
namespace ets_warnings = gen::ets_warnings;

template <class T>
T BaseName(T const &path)
{
    return path.substr(path.find_last_of(ark::os::file::File::GetPathDelim()) + 1);
}

class Options : public gen::Options {
public:
    explicit Options(std::string_view execPath) : gen::Options(std::string(execPath)) {}
    NO_COPY_SEMANTIC(Options);
    NO_MOVE_SEMANTIC(Options);
    ~Options() = default;

    bool Parse(Span<const char *const> args);

    ScriptExtension GetExtension() const
    {
        return extension_;
    }

    // NOTE(dkofanov): Replace this getter with something that does 'std::move(parserInputContents_)' as currently it
    // encourages copying of 'parserInputContents_' data.
    auto CStrParserInputContents() const
    {
        return std::pair<const char *, size_t> {parserInputContents_.c_str(), parserInputContents_.size()};
    }

    const auto &ArkTSConfig() const
    {
        return arktsConfig_;
    }

    auto LogLevel() const
    {
        return logLevel_;
    }

    void DetermineCompilationMode()
    {
        compilationMode_ = IsGenStdlib()         ? CompilationMode::GEN_STD_LIB
                           : inputFile_.WasSet() ? CompilationMode::SINGLE_FILE
                                                 : CompilationMode::PROJECT;
    }

    auto GetCompilationMode() const
    {
        return compilationMode_;
    }

    void SetEvalMode(std::string_view evalModeStr)
    {
        ASSERT(eval_mode::FromString(evalModeStr) != eval_mode::INVALID);
        gen::Options::SetEvalMode(std::string(evalModeStr));
        evalMode_ = eval_mode::FromString(evalModeStr);
    }
    bool IsEval() const
    {
        return evalMode_ != eval_mode::NONE;
    }
    bool IsDirectEval() const
    {
        return evalMode_ == eval_mode::DIRECT;
    }
    bool IsFunctionEval() const
    {
        return evalMode_ == eval_mode::FUNCTION;
    }

    auto SourceFileName() const
    {
        return inputFile_.GetValue();
    }

    const std::string &ErrorMsg() const
    {
        return errorMsg_;
    }

    bool IsDynamic() const
    {
        return extension_ != ScriptExtension::STS;
    }

    const auto &GetAstVerifierWarnings() const
    {
        return verifierWarnings_;
    }
    const auto &GetAstVerifierErrors() const
    {
        return verifierErrors_;
    }
    const auto &GetSkipPhases() const
    {
        return skipPhases_;
    }
    const auto &GetDumpBeforePhases() const
    {
        return dumpBeforePhases_;
    }
    const auto &GetDumpEtsSrcBeforePhases() const
    {
        return dumpEtsSrcBeforePhases_;
    }
    const auto &GetDumpAfterPhases() const
    {
        return dumpAfterPhases_;
    }
    const auto &GetDumpEtsSrcAfterPhases() const
    {
        return dumpEtsSrcAfterPhases_;
    }

    const auto &GetEtsWarningCollection() const
    {
        return etsWarningCollection_;
    }

    bool IsAstVerifierBeforePhases() const
    {
        return astVerifierBeforePhases_;
    }

    bool IsAstVerifierEachPhase() const
    {
        return astVerifierEachPhase_;
    }

    bool IsAstVerifierAfterPhases() const
    {
        return astVerifierAfterPhases_;
    }

    bool HasVerifierPhase(std::string_view phase) const
    {
        return astVerifierPhases_.find(std::string(phase)) != astVerifierPhases_.end();
    }

private:
    template <typename T>
    static bool CallPandArgParser(const std::vector<std::string> &args, T &options);
    bool CallPandArgParser(const std::vector<std::string> &args);
    bool ParseInputOutput();
    bool DetermineExtension();
    bool ProcessEtsSpecificOptions();
    std::optional<ArkTsConfig> ParseArktsConfig();
    void InitCompilerOptions();
    void InitAstVerifierOptions();
    void InitializeWarnings();

private:
    ark::PandArg<std::string> inputFile_ {"input", "", "input file"};
    std::shared_ptr<ArkTsConfig> arktsConfig_ {};
    ScriptExtension extension_ {ScriptExtension::INVALID};
    CompilationMode compilationMode_ {};
    std::set<std::string> skipPhases_ {};
    std::array<bool, gen::ast_verifier::COUNT> verifierWarnings_ {};
    std::array<bool, gen::ast_verifier::COUNT> verifierErrors_ {};
    bool astVerifierBeforePhases_ {};
    bool astVerifierEachPhase_ {};
    bool astVerifierAfterPhases_ {};
    std::set<std::string> astVerifierPhases_ {};
    std::set<std::string> dumpBeforePhases_ {};
    std::set<std::string> dumpEtsSrcBeforePhases_ {};
    std::set<std::string> dumpAfterPhases_ {};
    std::set<std::string> dumpEtsSrcAfterPhases_ {};
    std::vector<ETSWarnings> etsWarningCollection_ = {};
    std::string parserInputContents_;
    std::string errorMsg_;
    Logger::Level logLevel_ {Logger::Level::ERROR};
    EvalMode evalMode_ = {EvalMode::NONE};
};
}  // namespace ark::es2panda::util

#endif  // UTIL_OPTIONS_H
