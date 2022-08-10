/*
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

#include "options.h"

#include <utils/pandargs.h>

#include <utility>
#include <sstream>

namespace panda::es2panda::aot {

template <class T>
T BaseName(T const &path, T const &delims = "/")
{
    return path.substr(path.find_last_of(delims) + 1);
}

template <class T>
T RemoveExtension(T const &filename)
{
    typename T::size_type const P(filename.find_last_of('.'));
    return P > 0 && P != T::npos ? filename.substr(0, P) : filename;
}

// Options

Options::Options() : argparser_(new panda::PandArgParser()) {}

Options::~Options()
{
    delete argparser_;
}

bool Options::Parse(int argc, const char **argv)
{
    panda::PandArg<bool> opHelp("help", false, "Print this message and exit");

    // parser
    panda::PandArg<std::string> inputExtension("extension", "js",
                                               "Parse the input as the given extension (options: js | ts | as)");
    panda::PandArg<bool> opModule("module", false, "Parse the input as module");
    panda::PandArg<bool> opCommonjs("commonjs", false, "Parse the input as commonjs");
    panda::PandArg<bool> opParseOnly("parse-only", false, "Parse the input only");
    panda::PandArg<bool> opDumpAst("dump-ast", false, "Dump the parsed AST");

    // compiler
    panda::PandArg<bool> opDumpAssembly("dump-assembly", false, "Dump pandasm");
    panda::PandArg<bool> opDebugInfo("debug-info", false, "Compile with debug info");
    panda::PandArg<bool> opDumpDebugInfo("dump-debug-info", false, "Dump debug info");
    panda::PandArg<int> opOptLevel("opt-level", 0, "Compiler optimization level (options: 0 | 1 | 2)");
    panda::PandArg<int> opThreadCount("thread", 0, "Number of worker theads");
    panda::PandArg<bool> opSizeStat("dump-size-stat", false, "Dump size statistics");
    panda::PandArg<bool> opDumpLiteralBuffer("dump-literal-buffer", false, "Dump literal buffer");
    panda::PandArg<std::string> outputFile("output", "", "Compiler binary output (.abc)");
    panda::PandArg<bool> debuggerEvaluateExpression("debugger-evaluate-expression", false,
                                                    "evaluate expression in debugger mode");
    panda::PandArg<std::string> base64Input("base64Input", "", "base64 input of js content");
    panda::PandArg<bool> base64Output("base64Output", false, "output panda file content as base64 to std out");

    // tail arguments
    panda::PandArg<std::string> inputFile("input", "", "input file");

    argparser_->Add(&opHelp);
    argparser_->Add(&opModule);
    argparser_->Add(&opCommonjs);
    argparser_->Add(&opDumpAst);
    argparser_->Add(&opParseOnly);
    argparser_->Add(&opDumpAssembly);
    argparser_->Add(&opDebugInfo);
    argparser_->Add(&opDumpDebugInfo);
    argparser_->Add(&debuggerEvaluateExpression);
    argparser_->Add(&base64Input);
    argparser_->Add(&base64Output);

    argparser_->Add(&opOptLevel);
    argparser_->Add(&opThreadCount);
    argparser_->Add(&opSizeStat);
    argparser_->Add(&opDumpLiteralBuffer);

    argparser_->Add(&inputExtension);
    argparser_->Add(&outputFile);

    argparser_->PushBackTail(&inputFile);
    argparser_->EnableTail();
    argparser_->EnableRemainder();

    if (!argparser_->Parse(argc, argv) || opHelp.GetValue() || (inputFile.GetValue().empty()
        && base64Input.GetValue().empty())) {
        std::stringstream ss;

        ss << argparser_->GetErrorString() << std::endl;
        ss << "Usage: "
           << "es2panda"
           << " [OPTIONS] [input file] -- [arguments]" << std::endl;
        ss << std::endl;
        ss << "optional arguments:" << std::endl;
        ss << argparser_->GetHelpString() << std::endl;

        errorMsg_ = ss.str();
        return false;
    }

    bool inputIsEmpty = inputFile.GetValue().empty();
    bool base64InputIsEmpty = base64Input.GetValue().empty();
    bool outputIsEmpty = outputFile.GetValue().empty();

    if (!inputIsEmpty && !base64InputIsEmpty) {
        errorMsg_ = "--input and --base64Input can not be used simultaneously";
        return false;
    }

    if (!outputIsEmpty && base64Output.GetValue()) {
        errorMsg_ = "--output and --base64Output can not be used simultaneously";
        return false;
    }

    if (!inputIsEmpty) {
        // in common mode: passed argument is js file path
        sourceFile_ = inputFile.GetValue();
        std::ifstream inputStream(sourceFile_.c_str());

        if (inputStream.fail()) {
            errorMsg_ = "Failed to open file: ";
            errorMsg_.append(sourceFile_);
            return false;
        }

        std::stringstream ss;
        ss << inputStream.rdbuf();
        parserInput_ = ss.str();

        sourceFile_ = BaseName(sourceFile_);
    } else {
        // input content is base64 string
        parserInput_ = ExtractContentFromBase64Input(base64Input.GetValue());
        if (parserInput_.empty()) {
            errorMsg_ = "The input string is not a valid base64 data";
            return false;
        }
    }

    if (base64Output.GetValue()) {
        compilerOutput_ = "";
    } else if (!outputIsEmpty) {
        compilerOutput_ = outputFile.GetValue();
    } else if (outputIsEmpty && !inputIsEmpty) {
        compilerOutput_ = RemoveExtension(sourceFile_).append(".abc");
    }

    std::string extension = inputExtension.GetValue();

    if (!extension.empty()) {
        if (extension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
        } else if (extension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (extension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else {
            errorMsg_ = "Invalid extension (available options: js, ts, as)";
            return false;
        }
    }

    optLevel_ = opOptLevel.GetValue();
    threadCount_ = opThreadCount.GetValue();

    if (opParseOnly.GetValue()) {
        options_ |= OptionFlags::PARSE_ONLY;
    }

    if (opModule.GetValue() && opCommonjs.GetValue()) {
        errorMsg_ = "[--module] and [--commonjs] can not be used simultaneously";
        return false;
    }

    if (opModule.GetValue()) {
        scriptKind_ = es2panda::parser::ScriptKind::MODULE;
    }

    if (opCommonjs.GetValue()) {
        scriptKind_ = es2panda::parser::ScriptKind::COMMONJS;
    }

    if (opSizeStat.GetValue()) {
        options_ |= OptionFlags::SIZE_STAT;
    }

    compilerOptions_.dumpAsm = opDumpAssembly.GetValue();
    compilerOptions_.dumpAst = opDumpAst.GetValue();
    compilerOptions_.dumpDebugInfo = opDumpDebugInfo.GetValue();
    compilerOptions_.isDebug = opDebugInfo.GetValue();
    compilerOptions_.parseOnly = opParseOnly.GetValue();
    compilerOptions_.dumpLiteralBuffer = opDumpLiteralBuffer.GetValue();
    compilerOptions_.isDebuggerEvaluateExpressionMode = debuggerEvaluateExpression.GetValue();

    return true;
}

std::string Options::ExtractContentFromBase64Input(const std::string &inputBase64String)
{
    std::string inputContent = util::Base64Decode(inputBase64String);
    if (inputContent == "") {
        return "";
    }
    bool validBase64Input = util::Base64Encode(inputContent) == inputBase64String;
    if (!validBase64Input) {
        return "";
    }
    return inputContent;
}

}  // namespace panda::es2panda::aot
