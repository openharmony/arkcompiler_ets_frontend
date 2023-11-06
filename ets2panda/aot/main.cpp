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

#include "bytecode_optimizer/bytecodeopt_options.h"
#include "bytecode_optimizer/optimize_bytecode.h"
#include "compiler/compiler_logger.h"
#include "mem/arena_allocator.h"
#include "mem/pool_manager.h"
#include "es2panda.h"
#include "util/arktsconfig.h"
#include "util/generateBin.h"
#include "util/options.h"

#include <iostream>
#include <memory>

namespace panda::es2panda::aot {
using mem::MemConfig;

class MemManager {
public:
    explicit MemManager()
    {
        constexpr auto COMPILER_SIZE = 256_MB;

        MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize(PoolType::MMAP);
    }

    NO_COPY_SEMANTIC(MemManager);
    NO_MOVE_SEMANTIC(MemManager);

    ~MemManager()
    {
        PoolManager::Finalize();
        MemConfig::Finalize();
    }
};

static int CompileFromSource(es2panda::Compiler &compiler, es2panda::SourceFile &input, util::Options *options)
{
    auto program = std::unique_ptr<pandasm::Program> {compiler.Compile(input, options->CompilerOptions())};

    if (program == nullptr) {
        const auto &err = compiler.GetError();

        // Intentional exit or --parse-only option usage.
        if (err.Type() == ErrorType::INVALID) {
            return 0;
        }

        std::cout << err.TypeString() << ": " << err.Message();
        std::cout << " [" << (err.File().empty() ? util::BaseName(options->SourceFile()) : util::BaseName(err.File()))
                  << ":" << err.Line() << ":" << err.Col() << "]" << std::endl;

        return err.ErrorCode();
    }

    return util::GenerateProgram(program.get(), options, [](std::string const &str) { std::cerr << str << std::endl; });
}

static int CompileFromConfig(es2panda::Compiler &compiler, util::Options *options)
{
    auto compilation_list = FindProjectSources(options->CompilerOptions().arkts_config);
    if (compilation_list.empty()) {
        std::cerr << "Error: No files to compile" << std::endl;
        return 1;
    }

    unsigned overall_res = 0;
    for (auto &[src, dst] : compilation_list) {
        std::ifstream input_stream(src);
        if (input_stream.fail()) {
            std::cerr << "Error: Failed to open file: " << src << std::endl;
            return 1;
        }

        std::stringstream ss;
        ss << input_stream.rdbuf();
        std::string parser_input = ss.str();
        input_stream.close();
        es2panda::SourceFile input(src, parser_input, options->ParseModule());
        options->SetCompilerOutput(dst);

        options->ListFiles() && std::cout << "> es2panda: compiling from '" << src << "' to '" << dst << "'"
                                          << std::endl;
        auto res = CompileFromSource(compiler, input, options);
        if (res != 0) {
            std::cout << "> es2panda: failed to compile from " << src << " to " << dst << std::endl;
            overall_res |= static_cast<unsigned>(res);
        }
    }

    return overall_res;
}

static int Run(int argc, const char **argv)
{
    auto options = std::make_unique<util::Options>();

    if (!options->Parse(argc, argv)) {
        std::cerr << options->ErrorMsg() << std::endl;
        return 1;
    }

    Logger::ComponentMask mask {};
    mask.set(Logger::Component::ES2PANDA);
    Logger::InitializeStdLogging(Logger::LevelFromString(options->LogLevel()), mask);
    es2panda::Compiler compiler(options->Extension(), options->ThreadCount());

    if (options->CompilerOptions().compilation_mode == CompilationMode::PROJECT) {
        return CompileFromConfig(compiler, options.get());
    }

    std::string_view source_file;
    std::string_view parser_input;
    if (options->CompilerOptions().compilation_mode == CompilationMode::GEN_STD_LIB) {
        source_file = "etsstdlib.ets";
        parser_input = "";
    } else {
        source_file = options->SourceFile();
        parser_input = options->ParserInput();
    }
    es2panda::SourceFile input(source_file, parser_input, options->ParseModule());
    return CompileFromSource(compiler, input, options.get());
}
}  // namespace panda::es2panda::aot

int main(int argc, const char **argv)
{
    panda::es2panda::aot::MemManager mm;
    return panda::es2panda::aot::Run(argc, argv);
}
