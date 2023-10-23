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

#include <utility>

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

static std::unordered_set<std::string> StringToStringSet(const std::string &str)
{
    std::unordered_set<std::string> res;
    std::string_view curr_str {str};
    auto ix = curr_str.find(',');
    while (ix != std::string::npos) {
        if (ix != 0) {
            res.insert(std::string(curr_str.substr(0, ix)));
        }
        curr_str = curr_str.substr(ix + 1);
        ix = curr_str.find(',');
    }

    if (!curr_str.empty()) {
        res.insert(std::string(curr_str));
    }
    return res;
}

// NOLINTNEXTLINE(readability-function-size)
bool Options::Parse(int argc, const char **argv)
{
    panda::PandArg<bool> op_help("help", false, "Print this message and exit");

    // parser
    panda::PandArg<std::string> input_extension("extension", "",
                                                "Parse the input as the given extension (options: js | ts | as | ets)");
    panda::PandArg<bool> op_module("module", false, "Parse the input as module (JS only option)");
    panda::PandArg<bool> op_parse_only("parse-only", false, "Parse the input only");
    panda::PandArg<bool> op_dump_ast("dump-ast", false, "Dump the parsed AST");
    panda::PandArg<bool> op_dump_checked_ast("dump-dynamic-ast", false,
                                             "Dump AST with synthetic nodes for dynamic languages");
    panda::PandArg<bool> op_list_files("list-files", false, "Print names of files that are part of compilation");

    // compiler
    panda::PandArg<bool> op_dump_assembly("dump-assembly", false, "Dump pandasm");
    panda::PandArg<bool> op_debug_info("debug-info", false, "Compile with debug info");
    panda::PandArg<bool> op_dump_debug_info("dump-debug-info", false, "Dump debug info");
    panda::PandArg<int> op_opt_level("opt-level", 0, "Compiler optimization level (options: 0 | 1 | 2)");
    panda::PandArg<bool> op_ets_module("ets-module", false, "Compile the input as ets-module");
    panda::PandArg<std::string> op_ts_decl_out("gen-ts-decl", "", "For given .ets file, generate .ts interop file");

    auto constexpr DEFAULT_THREAD_COUNT = 0;
    panda::PandArg<int> op_thread_count("thread", DEFAULT_THREAD_COUNT, "Number of worker threads");
    panda::PandArg<bool> op_size_stat("dump-size-stat", false, "Dump size statistics");
    panda::PandArg<std::string> output_file("output", "", "Compiler binary output (.abc)");
    panda::PandArg<std::string> log_level("log-level", "error", "Log-level");
    panda::PandArg<std::string> std_lib("stdlib", "", "Path to standard library");
    panda::PandArg<bool> gen_std_lib("gen-stdlib", false, "Gen standard library");
    panda::PandArg<std::string> skip_phases("skip-phases", "", "Phases to skip");
    panda::PandArg<std::string> dump_before_phases("dump-before-phases", "",
                                                   "Generate program dump before running phases in the list");
    panda::PandArg<std::string> dump_after_phases("dump-after-phases", "",
                                                  "Generate program dump after running phases in the list");
    panda::PandArg<std::string> arkts_config("arktsconfig", DEFAULT_ARKTSCONFIG, "Path to arkts configuration file");

    // tail arguments
    panda::PandArg<std::string> input_file("input", "", "input file");

    argparser_->Add(&op_help);
    argparser_->Add(&op_module);
    argparser_->Add(&op_dump_ast);
    argparser_->Add(&op_dump_checked_ast);
    argparser_->Add(&op_parse_only);
    argparser_->Add(&op_dump_assembly);
    argparser_->Add(&op_debug_info);
    argparser_->Add(&op_dump_debug_info);

    argparser_->Add(&op_opt_level);
    argparser_->Add(&op_ets_module);
    argparser_->Add(&op_thread_count);
    argparser_->Add(&op_size_stat);
    argparser_->Add(&op_list_files);

    argparser_->Add(&input_extension);
    argparser_->Add(&output_file);
    argparser_->Add(&log_level);
    argparser_->Add(&std_lib);
    argparser_->Add(&gen_std_lib);
    argparser_->Add(&skip_phases);
    argparser_->Add(&dump_before_phases);
    argparser_->Add(&dump_after_phases);
    argparser_->Add(&arkts_config);
    argparser_->Add(&op_ts_decl_out);

    argparser_->PushBackTail(&input_file);
    argparser_->EnableTail();
    argparser_->EnableRemainder();

    if (!argparser_->Parse(argc, argv) || op_help.GetValue()) {
        std::stringstream ss;

        ss << argparser_->GetErrorString() << std::endl;
        ss << "Usage: "
           << "es2panda"
           << " [OPTIONS] [input file] -- [arguments]" << std::endl;
        ss << std::endl;
        ss << "optional arguments:" << std::endl;
        ss << argparser_->GetHelpString() << std::endl;

        error_msg_ = ss.str();
        return false;
    }

    // Determine compilation mode
    auto compilation_mode = gen_std_lib.GetValue()          ? CompilationMode::GEN_STD_LIB
                            : input_file.GetValue().empty() ? CompilationMode::PROJECT
                                                            : CompilationMode::SINGLE_FILE;

    source_file_ = input_file.GetValue();
    std::ifstream input_stream;

    if (compilation_mode == CompilationMode::SINGLE_FILE) {
        input_stream.open(source_file_.c_str());

        if (input_stream.fail()) {
            error_msg_ = "Failed to open file: ";
            error_msg_.append(source_file_);
            return false;
        }

        std::stringstream ss;
        ss << input_stream.rdbuf();
        parser_input_ = ss.str();
        input_stream.close();
    }

    if (!output_file.GetValue().empty()) {
        if (compilation_mode == CompilationMode::PROJECT) {
            error_msg_ = "Error: When compiling in project mode --output key is not needed";
            return false;
        }
        compiler_output_ = output_file.GetValue();
    } else {
        compiler_output_ = RemoveExtension(BaseName(source_file_)).append(".abc");
    }

    if (const auto log_level_str = log_level.GetValue(); !log_level_str.empty()) {
        if (log_level_str == "debug") {
            log_level_ = util::LogLevel::DEBUG;
        } else if (log_level_str == "info") {
            log_level_ = util::LogLevel::INFO;
        } else if (log_level_str == "warning") {
            log_level_ = util::LogLevel::WARNING;
        } else if (log_level_str == "error") {
            log_level_ = util::LogLevel::ERROR;
        } else if (log_level_str == "fatal") {
            log_level_ = util::LogLevel::FATAL;
        } else {
            std::cerr << "Invalid log level: '" << log_level_str
                      << R"('. Possible values: ["debug", "info", "warning", "error", "fatal"])";
            return false;
        }
    }

    std::string extension = input_extension.GetValue();
    std::string source_file_extension = source_file_.substr(source_file_.find_last_of('.') + 1);

    if (!extension.empty()) {
        if (extension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
        } else if (extension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (extension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else if (extension == "ets") {
            extension_ = es2panda::ScriptExtension::ETS;

            input_stream.open(arkts_config.GetValue());
            if (input_stream.fail()) {
                error_msg_ = "Failed to open arktsconfig: ";
                error_msg_.append(arkts_config.GetValue());
                return false;
            }
            input_stream.close();
        } else {
            error_msg_ = "Invalid extension (available options: js, ts, as, ets)";
            return false;
        }

        if (!source_file_.empty() && extension != source_file_extension) {
            std::cerr << "Warning: Not matching extensions! Sourcefile: " << source_file_extension
                      << ", Manual(used): " << extension << std::endl;
        }
    } else {
        if (compilation_mode == CompilationMode::PROJECT) {
            extension_ = es2panda::ScriptExtension::ETS;
        } else if (source_file_extension == "js") {
            extension_ = es2panda::ScriptExtension::JS;
        } else if (source_file_extension == "ts") {
            extension_ = es2panda::ScriptExtension::TS;
        } else if (source_file_extension == "as") {
            extension_ = es2panda::ScriptExtension::AS;
        } else if (source_file_extension == "ets") {
            extension_ = es2panda::ScriptExtension::ETS;
        } else {
            error_msg_ =
                "Unknown extension of sourcefile, set the extension manually or change the file format (available "
                "options: js, ts, as, ets)";
            return false;
        }
    }

#ifndef PANDA_WITH_ECMASCRIPT
    if (extension_ == es2panda::ScriptExtension::JS) {
        error_msg_ = "js extension is not supported within current build";
        return false;
    }
#endif

    if (extension_ != es2panda::ScriptExtension::JS && op_module.GetValue()) {
        error_msg_ = "Error: --module is not supported for this extension.";
        return false;
    }

    if (extension_ != es2panda::ScriptExtension::ETS) {
        if (compilation_mode == CompilationMode::PROJECT) {
            error_msg_ = "Error: only --extension=ets is supported for project compilation mode.";
            return false;
        }
        if (!op_ts_decl_out.GetValue().empty()) {
            error_msg_ = "Error: only --extension=ets is supported for --gen-ts-decl option";
            return false;
        }
    }

    opt_level_ = op_opt_level.GetValue();
    thread_count_ = op_thread_count.GetValue();
    list_files_ = op_list_files.GetValue();

    if (op_parse_only.GetValue()) {
        options_ |= OptionFlags::PARSE_ONLY;
    }

    if (op_module.GetValue()) {
        options_ |= OptionFlags::PARSE_MODULE;
    }

    if (op_size_stat.GetValue()) {
        options_ |= OptionFlags::SIZE_STAT;
    }

    compiler_options_.arkts_config = std::make_shared<panda::es2panda::ArkTsConfig>(arkts_config.GetValue());
    if (extension_ == es2panda::ScriptExtension::ETS) {
        if (!compiler_options_.arkts_config->Parse()) {
            error_msg_ = "Invalid ArkTsConfig: ";
            error_msg_.append(arkts_config.GetValue());
            return false;
        }
    }

    compiler_options_.ts_decl_out = op_ts_decl_out.GetValue();
    compiler_options_.dump_asm = op_dump_assembly.GetValue();
    compiler_options_.dump_ast = op_dump_ast.GetValue();
    compiler_options_.dump_checked_ast = op_dump_checked_ast.GetValue();
    compiler_options_.dump_debug_info = op_dump_debug_info.GetValue();
    compiler_options_.is_debug = op_debug_info.GetValue();
    compiler_options_.parse_only = op_parse_only.GetValue();
    compiler_options_.std_lib = std_lib.GetValue();
    compiler_options_.compilation_mode = compilation_mode;
    compiler_options_.is_ets_module = op_ets_module.GetValue();
    compiler_options_.skip_phases = StringToStringSet(skip_phases.GetValue());
    compiler_options_.dump_before_phases = StringToStringSet(dump_before_phases.GetValue());
    compiler_options_.dump_after_phases = StringToStringSet(dump_after_phases.GetValue());

    return true;
}
}  // namespace panda::es2panda::util
