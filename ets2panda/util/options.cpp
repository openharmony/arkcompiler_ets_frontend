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

#include "os/filesystem.h"
#include "utils/pandargs.h"

#include "arktsconfig.h"

#include <random>
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

static inline bool ETSWarningsGroupSetter(const ark::PandArg<bool> &option)
{
    return !option.WasSet() || (option.WasSet() && option.GetValue());
}

static std::tuple<std::string_view, std::string_view, std::string_view> SplitPath(std::string_view path)
{
    std::string_view fileDirectory;
    std::string_view fileBaseName = path;
    auto lastDelimPos = fileBaseName.find_last_of(ark::os::file::File::GetPathDelim());
    if (lastDelimPos != std::string_view::npos) {
        ++lastDelimPos;
        fileDirectory = fileBaseName.substr(0, lastDelimPos);
        fileBaseName = fileBaseName.substr(lastDelimPos);
    }

    // Save all extensions.
    std::string_view fileExtensions;
    auto fileBaseNamePos = fileBaseName.find_first_of('.');
    if (fileBaseNamePos > 0 && fileBaseNamePos != std::string_view::npos) {
        fileExtensions = fileBaseName.substr(fileBaseNamePos);
        fileBaseName = fileBaseName.substr(0, fileBaseNamePos);
    }

    return {fileDirectory, fileBaseName, fileExtensions};
}

/**
 * @brief Generate evaluated expression wrapping code.
 * @param sourceFilePath used for generating a unique package name.
 * @param input expression source code file stream.
 * @param output stream for generating expression wrapper.
 */
static void GenerateEvaluationWrapper(std::string_view sourceFilePath, std::ifstream &input, std::stringstream &output)
{
    static constexpr std::string_view EVAL_PREFIX = "eval_";
    static constexpr std::string_view EVAL_SUFFIX = "_eval";

    auto splittedPath = SplitPath(sourceFilePath);
    auto fileBaseName = std::get<1>(splittedPath);

    std::random_device rd;
    std::stringstream ss;
    ss << EVAL_PREFIX << fileBaseName << '_' << rd() << EVAL_SUFFIX;
    auto methodName = ss.str();

    output << "package " << methodName << "; class " << methodName << " { private static " << methodName << "() { "
           << input.rdbuf() << " } }";
}

static auto constexpr DEFAULT_THREAD_COUNT = 0;

struct AllArgs {
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    ark::PandArg<bool> opHelp {"help", false, "Print this message and exit"};
    ark::PandArg<bool> opVersion {"version", false, "Print message with version and exit"};

    // parser
    ark::PandArg<std::string> inputExtension {"extension", "",
                                              "Parse the input as the given extension (options: js | ts | as | sts)"};
    ark::PandArg<bool> opModule {"module", false, "Parse the input as module (JS only option)"};
    ark::PandArg<bool> opParseOnly {"parse-only", false, "Parse the input only"};
    ark::PandArg<bool> opDumpAst {"dump-ast", false, "Dump the parsed AST"};
    ark::PandArg<bool> opDumpAstOnlySilent {"dump-ast-only-silent", false,
                                            "Dump parsed AST with all dumpers available but don't print to stdout"};
    ark::PandArg<bool> opDumpCheckedAst {"dump-dynamic-ast", false,
                                         "Dump AST with synthetic nodes for dynamic languages"};
    ark::PandArg<bool> opListFiles {"list-files", false, "Print names of files that are part of compilation"};

    // compiler
    ark::PandArg<bool> opDumpAssembly {"dump-assembly", false, "Dump pandasm"};
    ark::PandArg<bool> opDebugInfo {"debug-info", false, "Compile with debug info"};
    ark::PandArg<bool> opDumpDebugInfo {"dump-debug-info", false, "Dump debug info"};
    ark::PandArg<int> opOptLevel {"opt-level", 0, "Compiler optimization level (options: 0 | 1 | 2)", 0, MAX_OPT_LEVEL};
    ark::PandArg<bool> opEtsModule {"ets-module", false, "Compile the input as ets-module"};

    // ETS-warnings
    ark::PandArg<bool> opEtsEnableAll {"ets-warnings-all", false, "Show performance-related ets-warnings"};
    ark::PandArg<bool> opEtsWerror {"ets-werror", false, "Treat all enabled performance-related ets-warnings as error"};
    ark::PandArg<bool> opEtsSubsetWarnings {"ets-subset-warnings", false, "Show ETS-warnings that keep you in subset"};
    ark::PandArg<bool> opEtsNonsubsetWarnings {"ets-nonsubset-warnings", false,
                                               "Show ETS-warnings that do not keep you in subset"};
    ark::PandArg<bool> opEtsSuggestFinal {"ets-suggest-final", false,
                                          "Suggest final keyword warning - ETS non-subset warning"};
    ark::PandArg<bool> opEtsProhibitTopLevelStatements {"ets-prohibit-top-level-statements", false,
                                                        "Prohibit top-level statements - ETS subset Warning"};
    ark::PandArg<bool> opEtsBoostEqualityStatement {"ets-boost-equality-statement", false,
                                                    "Suggest boosting Equality Statements - ETS Subset Warning"};
    ark::PandArg<bool> opEtsRemoveAsync {
        "ets-remove-async", false, "Suggests replacing async functions with coroutines - ETS Non Subset Warnings"};
    ark::PandArg<bool> opEtsRemoveLambda {"ets-remove-lambda", false,
                                          "Suggestions to replace lambda with regular functions - ETS Subset Warning"};
    ark::PandArg<bool> opEtsImplicitBoxingUnboxing {
        "ets-implicit-boxing-unboxing", false,
        "Check if a program contains implicit boxing or unboxing - ETS Subset Warning"};

    ark::PandArg<bool> opDebuggerEvalMode {"debugger-eval-mode", false, "Compile given file in evaluation mode"};
    ark::PandArg<uint64_t> opDebuggerEvalLine {
        "debugger-eval-line", 0, "Debugger evaluation mode, line in the source file code where evaluate occurs."};
    ark::PandArg<std::string> opDebuggerEvalSource {"debugger-eval-source", "",
                                                    "Debugger evaluation mode, path to evaluation mode source file"};
    ark::PandArg<std::string> opDebuggerEvalPandaFiles {
        "debugger-eval-panda-files", "",
        "Debugger evaluation mode, paths to evaluation mode (.abc) files, must be accessible"};

    ark::PandArg<int> opThreadCount {"thread", DEFAULT_THREAD_COUNT, "Number of worker threads"};
    ark::PandArg<bool> opSizeStat {"dump-size-stat", false, "Dump size statistics"};
    ark::PandArg<std::string> outputFile {"output", "", "Compiler binary output (.abc)"};
    ark::PandArg<std::string> logLevel {"log-level", "error", "Log-level"};
    ark::PandArg<std::string> stdLib {"stdlib", "", "Path to standard library"};
    ark::PandArg<bool> genStdLib {"gen-stdlib", false, "Gen standard library"};
    ark::PandArg<std::string> plugins {"plugins", "", "Plugins"};
    ark::PandArg<std::string> skipPhases {"skip-phases", "", "Phases to skip"};
    ark::PandArg<std::string> verifierWarnings {
        "verifier-warnings", "CheckInfiniteLoopForAll",
        "Print errors and continue compilation if AST tree is incorrect. "
        "Possible values: "
        "NodeHasParentForAll,EveryChildHasValidParentForAll,VariableHasScopeForAll,NodeHasTypeForAll,"
        "IdentifierHasVariableForAll,ArithmeticOperationValidForAll,SequenceExpressionHasLastTypeForAll, "
        "CheckInfiniteLoopForAll,"
        "ForLoopCorrectlyInitializedForAll,VariableHasEnclosingScopeForAll,ModifierAccessValidForAll,"
        "ImportExportAccessValid,NodeHasSourceRangeForAll,EveryChildInParentRangeForAll,"
        "ReferenceTypeAnnotationIsNullForAll,VariableNameIdentifierNameSameForAll,CheckAbstractMethodForAll,"
        "GetterSetterValidationForAll,CheckScopeDeclarationForAll,CheckConstPropertiesForAll"};
    ark::PandArg<std::string> verifierErrors {
        "verifier-errors",
        "ForLoopCorrectlyInitializedForAll,SequenceExpressionHasLastTypeForAll,NodeHasTypeForAll,NodeHasParentForAll,"
        "EveryChildHasValidParentForAll,ModifierAccessValidForAll,ArithmeticOperationValidForAll,"
        "VariableHasScopeForAll,IdentifierHasVariableForAll,VariableHasEnclosingScopeForAll,"
        "ReferenceTypeAnnotationIsNullForAll,VariableNameIdentifierNameSameForAll,CheckAbstractMethodForAll,"
        "GetterSetterValidationForAll,CheckScopeDeclarationForAll,CheckConstPropertiesForAll",
        "Print errors and stop compilation if AST tree is incorrect. "
        "Possible values: "
        "NodeHasParentForAll,EveryChildHasValidParentForAll,VariableHasScopeForAll,NodeHasTypeForAll,"
        "IdentifierHasVariableForAll,ArithmeticOperationValidForAll,SequenceExpressionHasLastTypeForAll,"
        "CheckInfiniteLoopForAll,"
        "ForLoopCorrectlyInitializedForAll,VariableHasEnclosingScopeForAll,ModifierAccessValidForAll,"
        "ImportExportAccessValid,NodeHasSourceRangeForAll,EveryChildInParentRangeForAll,"
        "ReferenceTypeAnnotationIsNullForAll,VariableNameIdentifierNameSameForAll,CheckAbstractMethodForAll,"
        "GetterSetterValidationForAll,CheckScopeDeclarationForAll,CheckConstPropertiesForAll"};
    ark::PandArg<bool> verifierAllChecks {
        "verifier-all-checks", false,
        "Run verifier checks on every phase, monotonically expanding them on every phase"};
    ark::PandArg<bool> verifierFullProgram {"verifier-full-program", false,
                                            "Analyze full program, including program AST and it's dependencies"};
    ark::PandArg<std::string> dumpBeforePhases {"dump-before-phases", "",
                                                "Generate program dump before running phases in the list"};
    ark::PandArg<std::string> dumpEtsSrcBeforePhases {
        "dump-ets-src-before-phases", "", "Generate program dump as ets source code before running phases in the list"};
    ark::PandArg<std::string> dumpEtsSrcAfterPhases {
        "dump-ets-src-after-phases", "", "Generate program dump as ets source code after running phases in the list"};
    ark::PandArg<std::string> exitBeforePhase {"exit-before-phase", "",
                                               "Exit compilation before running the provided phase"};
    ark::PandArg<std::string> exitAfterPhase {"exit-after-phase", "",
                                              "Exit compilation after running the provided phase"};
    ark::PandArg<std::string> dumpAfterPhases {"dump-after-phases", "",
                                               "Generate program dump after running phases in the list"};
    ark::PandArg<bool> opListPhases {"list-phases", false, "Dump list of available phases"};

    // tail arguments
    ark::PandArg<std::string> inputFile {"input", "", "input file"};

    ark::PandArg<std::string> arktsConfig;
    // NOLINTEND(misc-non-private-member-variables-in-classes)

    explicit AllArgs(const char *argv0)
        : arktsConfig {"arktsconfig", ark::es2panda::JoinPaths(ark::es2panda::ParentPath(argv0), "arktsconfig.json"),
                       "Path to arkts configuration file"}
    {
    }

    bool ParseInputOutput(CompilationMode compilationMode, std::string &errorMsg, std::string &sourceFile,
                          std::string &parserInput, std::string &compilerOutput) const
    {
        auto isDebuggerEvalMode = opDebuggerEvalMode.GetValue();
        if (isDebuggerEvalMode && compilationMode != CompilationMode::SINGLE_FILE) {
            errorMsg = "Error: When compiling with --debugger-eval-mode single input file must be provided";
            return false;
        }

        sourceFile = inputFile.GetValue();
        if (compilationMode == CompilationMode::SINGLE_FILE) {
            sourceFile = os::GetAbsolutePath(inputFile.GetValue());
            std::ifstream inputStream(sourceFile.c_str());
            if (inputStream.fail()) {
                errorMsg = "Failed to open file: ";
                errorMsg.append(sourceFile);
                return false;
            }

            std::stringstream ss;
            if (isDebuggerEvalMode) {
                GenerateEvaluationWrapper(sourceFile, inputStream, ss);
            } else {
                ss << inputStream.rdbuf();
            }
            parserInput = ss.str();
        }

        if (!outputFile.GetValue().empty()) {
            if (compilationMode == CompilationMode::PROJECT) {
                errorMsg = "Error: When compiling in project mode --output key is not needed";
                return false;
            }
            compilerOutput = outputFile.GetValue();
        } else {
            compilerOutput = RemoveExtension(BaseName(sourceFile)).append(".abc");
        }

        return true;
    }

    void BindArgs(ark::PandArgParser &argparser)
    {
        argparser.Add(&opHelp);
        argparser.Add(&opVersion);
        argparser.Add(&opModule);
        argparser.Add(&opDumpAst);
        argparser.Add(&opDumpAstOnlySilent);
        argparser.Add(&opDumpCheckedAst);
        argparser.Add(&opParseOnly);
        argparser.Add(&opDumpAssembly);
        argparser.Add(&opDebugInfo);
        argparser.Add(&opDumpDebugInfo);

        argparser.Add(&opOptLevel);
        argparser.Add(&opEtsModule);
        argparser.Add(&opThreadCount);
        argparser.Add(&opSizeStat);
        argparser.Add(&opListFiles);

        argparser.Add(&inputExtension);
        argparser.Add(&outputFile);
        argparser.Add(&logLevel);
        argparser.Add(&stdLib);
        argparser.Add(&genStdLib);
        argparser.Add(&plugins);
        argparser.Add(&skipPhases);
        argparser.Add(&verifierAllChecks);
        argparser.Add(&verifierFullProgram);
        argparser.Add(&verifierWarnings);
        argparser.Add(&verifierErrors);
        argparser.Add(&dumpBeforePhases);
        argparser.Add(&dumpEtsSrcBeforePhases);
        argparser.Add(&exitBeforePhase);
        argparser.Add(&dumpAfterPhases);
        argparser.Add(&dumpEtsSrcAfterPhases);
        argparser.Add(&exitAfterPhase);
        argparser.Add(&opListPhases);
        argparser.Add(&arktsConfig);

        argparser.Add(&opEtsEnableAll);
        argparser.Add(&opEtsWerror);
        argparser.Add(&opEtsSubsetWarnings);
        argparser.Add(&opEtsNonsubsetWarnings);

        // ETS-subset warnings
        argparser.Add(&opEtsProhibitTopLevelStatements);
        argparser.Add(&opEtsBoostEqualityStatement);
        argparser.Add(&opEtsRemoveLambda);
        argparser.Add(&opEtsImplicitBoxingUnboxing);

        // ETS-non-subset warnings
        argparser.Add(&opEtsSuggestFinal);
        argparser.Add(&opEtsRemoveAsync);

        AddDebuggerEvaluationOptions(argparser);

        argparser.PushBackTail(&inputFile);
        argparser.EnableTail();
        argparser.EnableRemainder();
    }

    void InitCompilerOptions(es2panda::CompilerOptions &compilerOptions, CompilationMode compilationMode) const
    {
        compilerOptions.dumpAsm = opDumpAssembly.GetValue();
        compilerOptions.dumpAst = opDumpAst.GetValue();
        compilerOptions.opDumpAstOnlySilent = opDumpAstOnlySilent.GetValue();
        compilerOptions.dumpCheckedAst = opDumpCheckedAst.GetValue();
        compilerOptions.dumpDebugInfo = opDumpDebugInfo.GetValue();
        compilerOptions.isDebug = opDebugInfo.GetValue();
        compilerOptions.parseOnly = opParseOnly.GetValue();
        compilerOptions.stdLib = stdLib.GetValue();
        compilerOptions.isEtsModule = opEtsModule.GetValue();
        compilerOptions.plugins = SplitToStringVector(plugins.GetValue());
        compilerOptions.skipPhases = SplitToStringSet(skipPhases.GetValue());
        compilerOptions.verifierFullProgram = verifierFullProgram.GetValue();
        compilerOptions.verifierAllChecks = verifierAllChecks.GetValue();
        compilerOptions.verifierWarnings = SplitToStringSet(verifierWarnings.GetValue());
        compilerOptions.verifierErrors = SplitToStringSet(verifierErrors.GetValue());
        compilerOptions.dumpBeforePhases = SplitToStringSet(dumpBeforePhases.GetValue());
        compilerOptions.dumpEtsSrcBeforePhases = SplitToStringSet(dumpEtsSrcBeforePhases.GetValue());
        compilerOptions.exitBeforePhase = exitBeforePhase.GetValue();
        compilerOptions.dumpAfterPhases = SplitToStringSet(dumpAfterPhases.GetValue());
        compilerOptions.dumpEtsSrcAfterPhases = SplitToStringSet(dumpEtsSrcAfterPhases.GetValue());
        compilerOptions.exitAfterPhase = exitAfterPhase.GetValue();

        // ETS-Warnings
        compilerOptions.etsSubsetWarnings = opEtsSubsetWarnings.GetValue();
        compilerOptions.etsWerror = opEtsWerror.GetValue();
        compilerOptions.etsNonsubsetWarnings = opEtsNonsubsetWarnings.GetValue();
        compilerOptions.etsEnableAll = opEtsEnableAll.GetValue();

        if (compilerOptions.etsEnableAll || compilerOptions.etsSubsetWarnings) {
            // Adding subset warnings
            compilerOptions.etsProhibitTopLevelStatements = ETSWarningsGroupSetter(opEtsProhibitTopLevelStatements);
            compilerOptions.etsBoostEqualityStatement = ETSWarningsGroupSetter(opEtsBoostEqualityStatement);
            compilerOptions.etsRemoveLambda = ETSWarningsGroupSetter(opEtsRemoveLambda);
            compilerOptions.etsImplicitBoxingUnboxing = ETSWarningsGroupSetter(opEtsImplicitBoxingUnboxing);
        }

        if (compilerOptions.etsEnableAll || compilerOptions.etsNonsubsetWarnings) {
            // Adding non-subset warnings
            compilerOptions.etsSuggestFinal = ETSWarningsGroupSetter(opEtsSuggestFinal);
            compilerOptions.etsRemoveAsync = ETSWarningsGroupSetter(opEtsRemoveAsync);
        }

        if (!compilerOptions.etsEnableAll && !compilerOptions.etsSubsetWarnings &&
            !compilerOptions.etsNonsubsetWarnings) {
            // If no warnings groups enabled - check all if enabled
            compilerOptions.etsSuggestFinal = opEtsSuggestFinal.GetValue();
            compilerOptions.etsProhibitTopLevelStatements = opEtsProhibitTopLevelStatements.GetValue();
            compilerOptions.etsBoostEqualityStatement = opEtsBoostEqualityStatement.GetValue();
            compilerOptions.etsRemoveAsync = opEtsRemoveAsync.GetValue();
            compilerOptions.etsRemoveLambda = opEtsRemoveLambda.GetValue();
            compilerOptions.etsImplicitBoxingUnboxing = opEtsImplicitBoxingUnboxing.GetValue();
        }

        InitDebuggerEvaluationCompilerOptions(compilerOptions);

        // Pushing enabled warnings to warning collection
        PushingEnabledWarnings(compilerOptions);

        compilerOptions.compilationMode = compilationMode;
    }

private:
    static void PushingEnabledWarnings(es2panda::CompilerOptions &compilerOptions)
    {
        if (compilerOptions.etsSuggestFinal) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::SUGGEST_FINAL);
        }
        if (compilerOptions.etsProhibitTopLevelStatements) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::PROHIBIT_TOP_LEVEL_STATEMENTS);
        }
        if (compilerOptions.etsBoostEqualityStatement) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::BOOST_EQUALITY_STATEMENT);
        }
        if (compilerOptions.etsRemoveAsync) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::REMOVE_ASYNC_FUNCTIONS);
        }
        if (compilerOptions.etsRemoveLambda) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::REMOVE_LAMBDA);
        }
        if (compilerOptions.etsImplicitBoxingUnboxing) {
            compilerOptions.etsWarningCollection.push_back(ETSWarnings::IMPLICIT_BOXING_UNBOXING);
        }
        if (!compilerOptions.etsWarningCollection.empty()) {
            compilerOptions.etsHasWarnings = true;
        }
    }

    void AddDebuggerEvaluationOptions(ark::PandArgParser &argparser)
    {
        argparser.Add(&opDebuggerEvalMode);
        argparser.Add(&opDebuggerEvalLine);
        argparser.Add(&opDebuggerEvalSource);
        argparser.Add(&opDebuggerEvalPandaFiles);
    }

    void InitDebuggerEvaluationCompilerOptions(es2panda::CompilerOptions &compilerOptions) const
    {
        compilerOptions.debuggerEvalMode = opDebuggerEvalMode.GetValue();
        if (compilerOptions.debuggerEvalMode) {
            compilerOptions.debuggerEvalLine = opDebuggerEvalLine.GetValue();
            compilerOptions.debuggerEvalSource = opDebuggerEvalSource.GetValue();
            compilerOptions.debuggerEvalPandaFiles = SplitToStringVector(opDebuggerEvalPandaFiles.GetValue());
        }
    }
};

static std::string Usage(const ark::PandArgParser &argparser)
{
    std::stringstream ss;

    ss << argparser.GetErrorString() << std::endl;
    ss << "Usage: "
       << "es2panda"
       << " [OPTIONS] [input file] -- [arguments]" << std::endl;
    ss << std::endl;
    ss << "optional arguments:" << std::endl;
    ss << argparser.GetHelpString() << std::endl;

    ss << std::endl;
    ss << "--bco-optimizer: Argument directly to bytecode optimizer can be passed after this prefix" << std::endl;
    ss << "--bco-compiler: Argument directly to jit-compiler inside bytecode optimizer can be passed after this "
          "prefix"
       << std::endl;

    return ss.str();
}

static std::string GetVersion()
{
    std::stringstream ss;

    ss << std::endl;
    ss << "  Es2panda Version " << ES2PANDA_VERSION << std::endl;

// add check for PANDA_PRODUCT_BUILD after normal version tracking will be implemented
#ifdef ES2PANDA_DATE
    ss << std::endl;
    ss << "  Build date: ";
    ss << ES2PANDA_DATE;
#endif  // ES2PANDA_DATE
#ifdef ES2PANDA_HASH
    ss << std::endl;
    ss << "  Last commit hash: ";
    ss << ES2PANDA_HASH;
    ss << std::endl;
#endif  // ES2PANDA_HASH

    return ss.str();
}

bool Options::Parse(int argc, const char **argv)
{
    std::vector<std::string> es2pandaArgs;
    std::vector<std::string> bcoCompilerArgs;
    std::vector<std::string> bytecodeoptArgs;

    SplitArgs(argc, argv, es2pandaArgs, bcoCompilerArgs, bytecodeoptArgs);
    if (!ParseBCOCompilerOptions(bcoCompilerArgs, bytecodeoptArgs)) {
        return false;
    }

    AllArgs allArgs(argv[0]);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)

    allArgs.BindArgs(*argparser_);
    if (!argparser_->Parse(es2pandaArgs) || allArgs.opHelp.GetValue()) {
        errorMsg_ = Usage(*argparser_);
        return false;
    }

    if (allArgs.opVersion.GetValue()) {
        errorMsg_ = GetVersion();
        return false;
    }

    // Determine compilation mode
    auto compilationMode = DetermineCompilationMode(allArgs.genStdLib, allArgs.inputFile);
    if (!allArgs.ParseInputOutput(compilationMode, errorMsg_, sourceFile_, parserInput_, compilerOutput_)) {
        return false;
    }

    // Determine Extension
    DetermineExtension(allArgs.inputExtension, allArgs.arktsConfig, compilationMode);
    if (extension_ == es2panda::ScriptExtension::INVALID) {
        return false;
    }

    if (extension_ != es2panda::ScriptExtension::JS && allArgs.opModule.GetValue()) {
        errorMsg_ = "Error: --module is not supported for this extension.";
        return false;
    }

    // Add Option Flags
    AddOptionFlags(allArgs.opParseOnly, allArgs.opModule, allArgs.opSizeStat);

    if ((allArgs.dumpEtsSrcBeforePhases.GetValue().size() + allArgs.dumpEtsSrcAfterPhases.GetValue().size() > 0) &&
        extension_ != es2panda::ScriptExtension::ETS) {
        errorMsg_ = "--dump-ets-src-* option is valid only with ETS extension";
        return false;
    }

    DetermineLogLevel(allArgs.logLevel);
    if (logLevel_ == util::LogLevel::INVALID) {
        return false;
    }

    allArgs.InitCompilerOptions(compilerOptions_, compilationMode);

    if (!ProcessEtsSpecificOptions(allArgs.arktsConfig.GetValue(), compilationMode)) {
        return false;
    }

    optLevel_ = allArgs.opOptLevel.GetValue();
    threadCount_ = allArgs.opThreadCount.GetValue();
    listFiles_ = allArgs.opListFiles.GetValue();
    listPhases_ = allArgs.opListPhases.GetValue();

    return true;
}
}  // namespace ark::es2panda::util
