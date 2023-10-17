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
#include "options.h"
#include "es2panda.h"
#include "util/arktsconfig.h"

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

static int GenerateProgram(panda::pandasm::Program *prog, const Options *options)
{
    std::map<std::string, size_t> stat;
    std::map<std::string, size_t> *statp = options->OptLevel() != 0 ? &stat : nullptr;
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps maps {};
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps *mapsp = options->OptLevel() != 0 ? &maps : nullptr;

#ifdef PANDA_WITH_BYTECODE_OPTIMIZER
    if (options->OptLevel() != 0) {
        panda::Logger::ComponentMask component_mask;
        component_mask.set(panda::Logger::Component::ASSEMBLER);
        component_mask.set(panda::Logger::Component::COMPILER);
        component_mask.set(panda::Logger::Component::BYTECODE_OPTIMIZER);

        panda::Logger::InitializeStdLogging(Logger::LevelFromString(options->LogLevel()), component_mask);

        if (!panda::pandasm::AsmEmitter::Emit(options->CompilerOutput(), *prog, statp, mapsp, true)) {
            std::cerr << "Failed to emit binary data: " << panda::pandasm::AsmEmitter::GetLastError() << std::endl;
            return 1;
        }

        panda::bytecodeopt::OPTIONS.SetOptLevel(options->OptLevel());
        // Set default value instead of maximum set in panda::bytecodeopt::SetCompilerOptions()
        panda::compiler::CompilerLogger::Init({"all"});
        panda::compiler::OPTIONS.SetCompilerMaxBytecodeSize(panda::compiler::OPTIONS.GetCompilerMaxBytecodeSize());
        panda::bytecodeopt::OptimizeBytecode(prog, mapsp, options->CompilerOutput(), options->IsDynamic(), true);
    }
#endif

    if (options->CompilerOptions().dump_asm) {
        es2panda::Compiler::DumpAsm(prog);
    }

    if (!panda::pandasm::AsmEmitter::AssignProfileInfo(prog)) {
        std::cerr << "AssignProfileInfo failed" << std::endl;
        return 1;
    }

    if (!panda::pandasm::AsmEmitter::Emit(options->CompilerOutput(), *prog, statp, mapsp, true)) {
        std::cerr << "Failed to emit binary data: " << panda::pandasm::AsmEmitter::GetLastError() << std::endl;
        return 1;
    }

    if (options->SizeStat()) {
        size_t total_size = 0;
        std::cout << "Panda file size statistic:" << std::endl;
        constexpr std::array<std::string_view, 2> INFO_STATS = {"instructions_number", "codesize"};

        for (const auto &[name, size] : stat) {
            if (find(INFO_STATS.begin(), INFO_STATS.end(), name) != INFO_STATS.end()) {
                continue;
            }
            std::cout << name << " section: " << size << std::endl;
            total_size += size;
        }

        for (const auto &name : INFO_STATS) {
            std::cout << name << ": " << stat.at(std::string(name)) << std::endl;
        }

        std::cout << "total: " << total_size << std::endl;
    }

    return 0;
}

static int CompileFromSource(es2panda::Compiler &compiler, es2panda::SourceFile &input, Options *options)
{
    auto program = std::unique_ptr<pandasm::Program> {compiler.Compile(input, options->CompilerOptions())};

    if (program == nullptr) {
        const auto &err = compiler.GetError();

        // Intentional exit or --parse-only option usage.
        if (err.Type() == ErrorType::INVALID) {
            return 0;
        }

        std::cout << err.TypeString() << ": " << err.Message();
        std::cout << " [" << (err.File().empty() ? BaseName(options->SourceFile()) : BaseName(err.File())) << ":"
                  << err.Line() << ":" << err.Col() << "]" << std::endl;

        return err.ErrorCode();
    }

    return GenerateProgram(program.get(), options);
}

static int CompileFromConfig(es2panda::Compiler &compiler, Options *options)
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
    auto options = std::make_unique<Options>();

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
