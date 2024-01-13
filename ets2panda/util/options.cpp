/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "options.h"

#include "utils/pandargs.h"

#include "arktsconfig.h"

#include <utility>

#ifdef PANDA_WITH_BYTECODE_OPTIMIZER
#include "bytecode_optimizer/bytecodeopt_options.h"
#include "compiler/compiler_options.h"
#endif

namespace panda::es2panda::util {
template <class T>
T RemoveExtension(T const &filename)
{
    typename T::size_type const p(filename.find_last_of('.'));
    return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}

// Options

Options::Options() : argparser_(new panda::PandArgParser()) {}

Options::~Options()
{
    delete argparser_;
}

static std::vector<std::string> SplitToStringVector(std::string const &str)
{
    std::vector<std::string> res;
    std::string_view currStr {str};
    auto ix = currStr.find(',');
    while (ix != std::string::npos) {
        if (ix != 0) {
            res.emplace_back(currStr.substr(0, ix));
        }
        currStr = currStr.substr(ix + 1);
        ix = currStr.find(',');
    }

    if (!currStr.empty()) {
        res.emplace_back(currStr);
    }
    return res;
}

static std::unordered_set<std::string> SplitToStringSet(std::string const &str)
{
    std::vector<std::string> vec = SplitToStringVector(str);
    std::unordered_set<std::string> res;
    for (auto &elem : vec) {
        res.emplace(elem);
    }
    return res;
}

// NOLINTNEXTLINE(modernize-avoid-c-arrays, hicpp-avoid-c-arrays)
static void SplitArgs(int argc, const char *argv[], std::vector<std::string> &es2pandaArgs,
                      std::vector<std::string> &bcoCompilerArgs, std::vector<std::string> &bytecodeoptArgs)
{
    constexpr std::string_view COMPILER_PREFIX = "--bco-compiler";
    constexpr std::string_view OPTIMIZER_PREFIX = "--bco-optimizer";

    enum class OptState { ES2PANDA, JIT_COMPILER, OPTIMIZER };
    OptState optState = OptState::ES2PANDA;

    std::unordered_map<OptState, std::vector<std::string> *> argsMap = {{OptState::ES2PANDA, &es2pandaArgs},
                                                                        {OptState::JIT_COMPILER, &bcoCompilerArgs},
                                                                        {OptState::OPTIMIZER, &bytecodeoptArgs}};

    for (int i = 1; i < argc; i++) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        const char *argI = argv[i];
        if (COMPILER_PREFIX == argI) {
            optState = OptState::JIT_COMPILER;
            continue;
        }

        if (OPTIMIZER_PREFIX == argI) {
            optState = OptState::OPTIMIZER;
            continue;
        }

        argsMap[optState]->emplace_back(argI);
        optState = OptState::ES2PANDA;
    }
}

template <class T>
static bool ParseComponentArgs(const std::vector<std::string> &args, T &options)
{
    panda::PandArgParser parser;
    options.AddOptions(&parser);
    if (!parser.Parse(args)) {
        std::cerr << parser.GetErrorString();
        std::cerr << parser.GetHelpString();
        return false;
    }

    if (auto optionsErr = options.Validate(); optionsErr) {
        std::cerr << "Error: " << optionsErr.value().GetMessage() << std::endl;
        return false;
    }

    return true;
}

static bool ParseBCOCompilerOptions([[maybe_unused]] const std::vector<std::string> &compilerArgs,
                                    [[maybe_unused]] const std::vector<std::string> &bytecodeoptArgs)
{
#ifdef PANDA_WITH_BYTECODE_OPTIMIZER
    if (!ParseComponentArgs(compilerArgs, panda::compiler::g_options)) {
        return false;
    }
    if (!ParseComponentArgs(bytecodeoptArgs, panda::bytecodeopt::g_options)) {
        return false;
    }
#endif

    return true;
}

// NOLINTNEXTLINE(readability-function-size)
bool Options::Parse(int argc, const char **argv)
{
    std::vector<std::string> es2pandaArgs;
    std::vector<std::string> bcoCompilerArgs;
    std::vector<std::string> bytecodeoptArgs;

    SplitArgs(argc, argv, es2pandaArgs, bcoCompilerArgs, bytecodeoptArgs);
    if (!ParseBCOCompilerOptions(bcoCompilerArgs, bytecodeoptArgs)) {
        return false;
    }

    panda::PandArg<bool> opHelp("help", false, "Print this message and exit");

    // parser
    panda::PandArg<std::string> inputExtension("extension", "",
                                               "Parse the input as the given extension (options: js | ts | as | ets)");
    panda::PandArg<bool> opModule("module", false, "Parse the input as module (JS only option)");
    panda::PandArg<bool> opParseOnly("parse-only", false, "Parse the input only");
    panda::PandArg<bool> opDumpAst("dump-ast", false, "Dump the parsed AST");
    panda::PandArg<bool> opDumpAstOnlySilent("dump-ast-only-silent", false,
                                             "Dump parsed AST with all dumpers available but don't print to stdout");
    panda::PandArg<bool> opDumpCheckedAst("dump-dynamic-ast", false,
                                          "Dump AST with synthetic nodes for dynamic languages");
    panda::PandArg<bool> opListFiles("list-files", false, "Print names of files that are part of compilation");

    // compiler
    panda::PandArg<bool> opDumpAssembly("dump-assembly", false, "Dump pandasm");
    panda::PandArg<bool> opDebugInfo("debug-info", false, "Compile with debug info");
    panda::PandArg<bool> opDumpDebugInfo("dump-debug-info", false, "Dump debug info");
    panda::PandArg<int> opOptLevel("opt-level", 0, "Compiler optimization level (options: 0 | 1 | 2)");
    panda::PandArg<bool> opEtsModule("ets-module", false, "Compile the input as ets-module");
    panda::PandArg<std::string> opTsDeclOut("gen-ts-decl", "", "For given .ets file, generate .ts interop file");

    auto constexpr DEFAULT_THREAD_COUNT = 0;
    panda::PandArg<int> opThreadCount("thread", DEFAULT_THREAD_COUNT, "Number of worker threads");
    panda::PandArg<bool> opSizeStat("dump-size-stat", false, "Dump size statistics");
    panda::PandArg<std::string> outputFile("output", "", "Compiler binary output (.abc)");
    panda::PandArg<std::string> logLevel("log-level", "error", "Log-level");
    panda::PandArg<std::string> stdLib("stdlib", "", "Path to standard library");
    panda::PandArg<bool> genStdLib("gen-stdlib", false, "Gen standard library");
    panda::PandArg<std::string> plugins("plugins", "", "Plugins");
    panda::PandArg<std::string> skipPhases("skip-phases", "", "Phases to skip");
    panda::PandArg<std::string> dumpBeforePhases("dump-before-phases", "",
                                                 "Generate program dump before running phases in the list");
    panda::PandArg<std::string> dumpEtsSrcBeforePhases(
        "dump-ets-src-before-phases", "", "Generate program dump as ets source code before running phases in the list");
    panda::PandArg<std::string> dumpEtsSrcAfterPhases(
        "dump-ets-src-after-phases", "", "Generate program dump as ets source code after running phases in the list");
    panda::PandArg<std::string> dumpAfterPhases("dump-after-phases", "",
                                                "Generate program dump after running phases in the list");
    panda::PandArg<std::string> arktsConfig(
        "arktsconfig",
        panda::es2panda::JoinPaths(
            panda::es2panda::ParentPath(argv[0]),  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            "arktsconfig.json"),
        "Path to arkts configuration file");

    // tail arguments
    panda::PandArg<std::string> inputFile("input", "", "input file");

    argparser_->Add(&opHelp);
    argparser_->Add(&opModule);
    argparser_->Add(&opDumpAst);
    argparser_->Add(&opDumpAstOnlySilent);
    argparser_->Add(&opDumpCheckedAst);
    argparser_->Add(&opParseOnly);
    argparser_->Add(&opDumpAssembly);
    argparser_->Add(&opDebugInfo);
    argparser_->Add(&opDumpDebugInfo);

    argparser_->Add(&opOptLevel);
    argparser_->Add(&opEtsModule);
    argparser_->Add(&opThreadCount);
    argparser_->Add(&opSizeStat);
    argparser_->Add(&opListFiles);

    argparser_->Add(&inputExtension);
    argparser_->Add(&outputFile);
    argparser_->Add(&logLevel);
    argparser_->Add(&stdLib);
    argparser_->Add(&genStdLib);
    argparser_->Add(&plugins);
    argparser_->Add(&skipPhases);
    argparser_->Add(&dumpBeforePhases);
    argparser_->Add(&dumpEtsSrcBeforePhases);
    argparser_->Add(&dumpAfterPhases);
    argparser_->Add(&dumpEtsSrcAfterPhases);
    argparser_->Add(&arktsConfig);
    argparser_->Add(&opTsDeclOut);

    argparser_->PushBackTail(&inputFile);
    argparser_->EnableTail();
    argparser_->EnableRemainder();

    if (!argparser_->Parse(es2pandaArgs) || opHelp.GetValue()) {
        std::stringstream ss;

        ss << argparser_->GetErrorString() << std::endl;
        ss << "Usage: "
           << "es2panda"
           << " [OPTIONS] [input file] -- [arguments]" << std::endl;
        ss << std::endl;
        ss << "optional arguments:" << std::endl;
        ss << argparser_->GetHelpString() << std::endl;

        ss << std::endl;
        ss << "--bco-optimizer: Argument directly to bytecode optimizer can be passed after this prefix" << std::endl;
        ss << "--bco-compiler: Argument directly to jit-compiler inside bytecode optimizer can be passed after this "
              "prefix"
           << std::endl;

        errorMsg_ = ss.str();
        return false;
    }

    // Determine compilation mode
    auto compilationMode = genStdLib.GetValue()           ? CompilationMode::GEN_STD_LIB
                           : inputFile.GetValue().empty() ? CompilationMode::PROJECT
                                                          : CompilationMode::SINGLE_FILE;

    sourceFile_ = inputFile.GetValue();
    std::ifstream inputStream;

    if (compilationMode == CompilationMode::SINGLE_FILE) {
        inputStream.open(sourceFile_.c_str());

        if (inputStream.fail()) {
            errorMsg_ = "Failed to open file: ";
            errorMsg_.append(sourceFile_);
            return false;
        }

        std::stringstream ss;
        ss << inputStream.rdbuf();
        parserInput_ = ss.str();
        inputStream.close();
    }

    if (!outputFile.GetValue().empty()) {
        if (compilationMode == CompilationMode::PROJECT) {
            errorMsg_ = "Error: When compiling in project mode --output key is not needed";
            return false;
        }
        compilerOutput_ = outputFile.GetValue();
    } else {
        compilerOutput_ = RemoveExtension(BaseName(sourceFile_)).append(".abc");
    }

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
            std::cerr << "Invalid log level: '" << logLevelStr
                      << R"('. Possible values: ["debug", "info", "warning", "error", "fatal"])";
            return false;
        }
    }

    std::string extension = inputExtension.GetValue();
    std::string sourceFileExtension = sourceFile_.substr(sourceFile_.find_last_of('.') + 1);

    if (!extension.empty()) {
        if (extension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
        } else if (extension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (extension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else if (extension == "ets") {
            extension_ = es2panda::ScriptExtension::ETS;

            inputStream.open(arktsConfig.GetValue());
            if (inputStream.fail()) {
                errorMsg_ = "Failed to open arktsconfig: ";
                errorMsg_.append(arktsConfig.GetValue());
                return false;
            }
            inputStream.close();
        } else {
            errorMsg_ = "Invalid extension (available options: js, ts, as, ets)";
            return false;
        }

        if (!sourceFile_.empty() && extension != sourceFileExtension) {
            std::cerr << "Warning: Not matching extensions! Sourcefile: " << sourceFileExtension
                      << ", Manual(used): " << extension << std::endl;
        }
    } else {
        if (compilationMode == CompilationMode::PROJECT) {
            extension_ = es2panda::ScriptExtension::ETS;
        } else if (sourceFileExtension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
        } else if (sourceFileExtension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (sourceFileExtension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else if (sourceFileExtension == "ets") {
            extension_ = es2panda::ScriptExtension::ETS;
        } else {
            errorMsg_ =
                "Unknown extension of sourcefile, set the extension manually or change the file format (available "
                "options: js, ts, as, ets)";
            return false;
        }
    }

#ifndef PANDA_WITH_ECMASCRIPT
    if (extension_ == es2panda::ScriptExtension::JS) {
        errorMsg_ = "js extension is not supported within current build";
        return false;
    }
#endif

    if (extension_ != es2panda::ScriptExtension::JS && opModule.GetValue()) {
        errorMsg_ = "Error: --module is not supported for this extension.";
        return false;
    }

    if (extension_ != es2panda::ScriptExtension::ETS) {
        if (compilationMode == CompilationMode::PROJECT) {
            errorMsg_ = "Error: only --extension=ets is supported for project compilation mode.";
            return false;
        }
        if (!opTsDeclOut.GetValue().empty()) {
            errorMsg_ = "Error: only --extension=ets is supported for --gen-ts-decl option";
            return false;
        }
    }

    optLevel_ = opOptLevel.GetValue();
    threadCount_ = opThreadCount.GetValue();
    listFiles_ = opListFiles.GetValue();

    if (opParseOnly.GetValue()) {
        options_ |= OptionFlags::PARSE_ONLY;
    }

    if (opModule.GetValue()) {
        options_ |= OptionFlags::PARSE_MODULE;
    }

    if (opSizeStat.GetValue()) {
        options_ |= OptionFlags::SIZE_STAT;
    }

    compilerOptions_.arktsConfig = std::make_shared<panda::es2panda::ArkTsConfig>(arktsConfig.GetValue());
    if (extension_ == es2panda::ScriptExtension::ETS) {
        if (!compilerOptions_.arktsConfig->Parse()) {
            errorMsg_ = "Invalid ArkTsConfig: ";
            errorMsg_.append(arktsConfig.GetValue());
            return false;
        }
    }

    if ((dumpEtsSrcBeforePhases.GetValue().size() + dumpEtsSrcAfterPhases.GetValue().size() > 0) &&
        extension_ != es2panda::ScriptExtension::ETS) {
        errorMsg_ = "--dump-ets-src-* option is valid only with ETS extension";
        return false;
    }

    compilerOptions_.tsDeclOut = opTsDeclOut.GetValue();
    compilerOptions_.dumpAsm = opDumpAssembly.GetValue();
    compilerOptions_.dumpAst = opDumpAst.GetValue();
    compilerOptions_.opDumpAstOnlySilent = opDumpAstOnlySilent.GetValue();
    compilerOptions_.dumpCheckedAst = opDumpCheckedAst.GetValue();
    compilerOptions_.dumpDebugInfo = opDumpDebugInfo.GetValue();
    compilerOptions_.isDebug = opDebugInfo.GetValue();
    compilerOptions_.parseOnly = opParseOnly.GetValue();
    compilerOptions_.stdLib = stdLib.GetValue();
    compilerOptions_.compilationMode = compilationMode;
    compilerOptions_.isEtsModule = opEtsModule.GetValue();
    compilerOptions_.plugins = SplitToStringVector(plugins.GetValue());
    compilerOptions_.skipPhases = SplitToStringSet(skipPhases.GetValue());
    compilerOptions_.dumpBeforePhases = SplitToStringSet(dumpBeforePhases.GetValue());
    compilerOptions_.dumpEtsSrcBeforePhases = SplitToStringSet(dumpEtsSrcBeforePhases.GetValue());
    compilerOptions_.dumpAfterPhases = SplitToStringSet(dumpAfterPhases.GetValue());
    compilerOptions_.dumpEtsSrcAfterPhases = SplitToStringSet(dumpEtsSrcAfterPhases.GetValue());

    return true;
}
}  // namespace panda::es2panda::util
