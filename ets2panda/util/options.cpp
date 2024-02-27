/**
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

namespace ark::es2panda::util {
template <class T>
T RemoveExtension(T const &filename)
{
    typename T::size_type const p(filename.find_last_of('.'));
    return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}

// Options

Options::Options() : argparser_(new ark::PandArgParser()) {}

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
    ark::PandArgParser parser;
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
    if (!ParseComponentArgs(compilerArgs, ark::compiler::g_options)) {
        return false;
    }
    if (!ParseComponentArgs(bytecodeoptArgs, ark::bytecodeopt::g_options)) {
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

    ark::PandArg<bool> opHelp("help", false, "Print this message and exit");

    // parser
    ark::PandArg<std::string> inputExtension("extension", "",
                                             "Parse the input as the given extension (options: js | ts | as | ets)");
    ark::PandArg<bool> opModule("module", false, "Parse the input as module (JS only option)");
    ark::PandArg<bool> opParseOnly("parse-only", false, "Parse the input only");
    ark::PandArg<bool> opDumpAst("dump-ast", false, "Dump the parsed AST");
    ark::PandArg<bool> opDumpAstOnlySilent("dump-ast-only-silent", false,
                                           "Dump parsed AST with all dumpers available but don't print to stdout");
    ark::PandArg<bool> opDumpCheckedAst("dump-dynamic-ast", false,
                                        "Dump AST with synthetic nodes for dynamic languages");
    ark::PandArg<bool> opListFiles("list-files", false, "Print names of files that are part of compilation");

    // compiler
    ark::PandArg<bool> opDumpAssembly("dump-assembly", false, "Dump pandasm");
    ark::PandArg<bool> opDebugInfo("debug-info", false, "Compile with debug info");
    ark::PandArg<bool> opDumpDebugInfo("dump-debug-info", false, "Dump debug info");
    ark::PandArg<int> opOptLevel("opt-level", 0, "Compiler optimization level (options: 0 | 1 | 2)");
    ark::PandArg<bool> opEtsModule("ets-module", false, "Compile the input as ets-module");
    ark::PandArg<std::string> opTsDeclOut("gen-ts-decl", "", "For given .ets file, generate .ts interop file");

    auto constexpr DEFAULT_THREAD_COUNT = 0;
    ark::PandArg<int> opThreadCount("thread", DEFAULT_THREAD_COUNT, "Number of worker threads");
    ark::PandArg<bool> opSizeStat("dump-size-stat", false, "Dump size statistics");
    ark::PandArg<std::string> outputFile("output", "", "Compiler binary output (.abc)");
    ark::PandArg<std::string> logLevel("log-level", "error", "Log-level");
    ark::PandArg<std::string> stdLib("stdlib", "", "Path to standard library");
    ark::PandArg<bool> genStdLib("gen-stdlib", false, "Gen standard library");
    ark::PandArg<std::string> plugins("plugins", "", "Plugins");
    ark::PandArg<std::string> skipPhases("skip-phases", "", "Phases to skip");
    ark::PandArg<std::string> verifierWarnings(
        "verifier-warnings", "",
        "Print errors and continue compilation if AST tree is incorrect. "
        "Possible values: "
        "NodeHasParentForAll,EveryChildHasValidParentForAll,VariableHasScopeForAll,NodeHasTypeForAll,"
        "IdentifierHasVariableForAll,ArithmeticOperationValidForAll,SequenceExpressionHasLastTypeForAll,"
        "ForLoopCorrectlyInitializedForAll,VariableHasEnclosingScopeForAll,ModifierAccessValidForAll,"
        "ImportExportAccessValid");
    ark::PandArg<std::string> verifierErrors(
        "verifier-errors",
        "ForLoopCorrectlyInitializedForAll,SequenceExpressionHasLastTypeForAll,NodeHasTypeForAll,NodeHasParentForAll,"
        "EveryChildHasValidParentForAll,ModifierAccessValidForAll,ArithmeticOperationValidForAll,"
        "VariableHasScopeForAll,IdentifierHasVariableForAll,VariableHasEnclosingScopeForAll",
        "Print errors and stop compilation if AST tree is incorrect. "
        "Possible values: "
        "NodeHasParentForAll,EveryChildHasValidParentForAll,VariableHasScopeForAll,NodeHasTypeForAll,"
        "IdentifierHasVariableForAll,ArithmeticOperationValidForAll,SequenceExpressionHasLastTypeForAll,"
        "ForLoopCorrectlyInitializedForAll,VariableHasEnclosingScopeForAll,ModifierAccessValidForAll,"
        "ImportExportAccessValid");
    ark::PandArg<bool> verifierAllChecks(
        "verifier-all-checks", false,
        "Run verifier checks on every phase, monotonically expanding them on every phase");
    ark::PandArg<bool> verifierFullProgram("verifier-full-program", false,
                                           "Analyze full program, including program AST and it's dependencies");
    ark::PandArg<std::string> dumpBeforePhases("dump-before-phases", "",
                                               "Generate program dump before running phases in the list");
    ark::PandArg<std::string> dumpEtsSrcBeforePhases(
        "dump-ets-src-before-phases", "", "Generate program dump as ets source code before running phases in the list");
    ark::PandArg<std::string> dumpEtsSrcAfterPhases(
        "dump-ets-src-after-phases", "", "Generate program dump as ets source code after running phases in the list");
    ark::PandArg<std::string> dumpAfterPhases("dump-after-phases", "",
                                              "Generate program dump after running phases in the list");
    ark::PandArg<std::string> arktsConfig(
        "arktsconfig",
        ark::es2panda::JoinPaths(
            ark::es2panda::ParentPath(argv[0]),  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            "arktsconfig.json"),
        "Path to arkts configuration file");

    // tail arguments
    ark::PandArg<std::string> inputFile("input", "", "input file");

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
    argparser_->Add(&verifierAllChecks);
    argparser_->Add(&verifierFullProgram);
    argparser_->Add(&verifierWarnings);
    argparser_->Add(&verifierErrors);
    argparser_->Add(&dumpBeforePhases);
    argparser_->Add(&dumpEtsSrcBeforePhases);
    argparser_->Add(&dumpAfterPhases);
    argparser_->Add(&dumpEtsSrcBeforePhases);
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
    auto compilationMode = DetermineCompilationMode(genStdLib, inputFile);

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

    DetermineLogLevel(logLevel);
    if (logLevel_ == util::LogLevel::INVALID) {
        return false;
    }

    std::string extension = inputExtension.GetValue();
    std::string sourceFileExtension = sourceFile_.substr(sourceFile_.find_last_of('.') + 1);

    // Determine Extension
    DetermineExtension(extension, sourceFileExtension, inputStream, arktsConfig, compilationMode);
    if (extension_ == es2panda::ScriptExtension::INVALID) {
        return false;
    }

    if (extension_ != es2panda::ScriptExtension::JS && opModule.GetValue()) {
        errorMsg_ = "Error: --module is not supported for this extension.";
        return false;
    }

    optLevel_ = opOptLevel.GetValue();
    threadCount_ = opThreadCount.GetValue();
    listFiles_ = opListFiles.GetValue();

    // Add Option Flags
    AddOptionFlags(opParseOnly, opModule, opSizeStat);

    compilerOptions_.arktsConfig = std::make_shared<ark::es2panda::ArkTsConfig>(arktsConfig.GetValue());

    // Some additional checks for ETS extension
    if (!CheckEtsSpecificOptions(opTsDeclOut, compilationMode, arktsConfig)) {
        return false;
    }

    if ((dumpEtsSrcAfterPhases.GetValue().size() + dumpEtsSrcAfterPhases.GetValue().size() > 0) &&
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
    compilerOptions_.verifierFullProgram = verifierFullProgram.GetValue();
    compilerOptions_.verifierAllChecks = verifierAllChecks.GetValue();
    compilerOptions_.verifierWarnings = SplitToStringSet(verifierWarnings.GetValue());
    compilerOptions_.verifierErrors = SplitToStringSet(verifierErrors.GetValue());
    compilerOptions_.dumpBeforePhases = SplitToStringSet(dumpBeforePhases.GetValue());
    compilerOptions_.dumpEtsSrcBeforePhases = SplitToStringSet(dumpEtsSrcBeforePhases.GetValue());
    compilerOptions_.dumpAfterPhases = SplitToStringSet(dumpBeforePhases.GetValue());
    compilerOptions_.dumpEtsSrcAfterPhases = SplitToStringSet(dumpEtsSrcAfterPhases.GetValue());

    return true;
}
}  // namespace ark::es2panda::util
