/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "generateBin.h"
#include "bytecode_optimizer/bytecodeopt_options.h"
#include "bytecode_optimizer/optimize_bytecode.h"
#include "compiler/compiler_logger.h"
#include "compiler/compiler_options.h"

namespace panda::es2panda::util {

int GenerateProgram(panda::pandasm::Program *prog, const util::Options *options, const ReporterFun &reporter)
{
    std::map<std::string, size_t> stat;
    std::map<std::string, size_t> *statp = options->OptLevel() != 0 ? &stat : nullptr;
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps maps {};
    panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps *mapsp = options->OptLevel() != 0 ? &maps : nullptr;

#ifdef PANDA_WITH_BYTECODE_OPTIMIZER
    if (options->OptLevel() != 0) {
        panda::Logger::ComponentMask componentMask;
        componentMask.set(panda::Logger::Component::ASSEMBLER);
        componentMask.set(panda::Logger::Component::COMPILER);
        componentMask.set(panda::Logger::Component::BYTECODE_OPTIMIZER);

        panda::Logger::InitializeStdLogging(Logger::LevelFromString(options->LogLevel()), componentMask);

        if (!panda::pandasm::AsmEmitter::Emit(options->CompilerOutput(), *prog, statp, mapsp, true)) {
            reporter("Failed to emit binary data: " + panda::pandasm::AsmEmitter::GetLastError());
            return 1;
        }

        panda::bytecodeopt::g_options.SetOptLevel(options->OptLevel());
        // Set default value instead of maximum set in panda::bytecodeopt::SetCompilerOptions()
        panda::compiler::CompilerLogger::Init({"all"});
        panda::compiler::g_options.SetCompilerMaxBytecodeSize(panda::compiler::g_options.GetCompilerMaxBytecodeSize());
        panda::bytecodeopt::OptimizeBytecode(prog, mapsp, options->CompilerOutput(), options->IsDynamic(), true);
    }
#endif

    if (options->CompilerOptions().dumpAsm) {
        es2panda::Compiler::DumpAsm(prog);
    }

    if (!panda::pandasm::AsmEmitter::AssignProfileInfo(prog)) {
        reporter("AssignProfileInfo failed");
        return 1;
    }

    if (!panda::pandasm::AsmEmitter::Emit(options->CompilerOutput(), *prog, statp, mapsp, true)) {
        reporter("Failed to emit binary data: " + panda::pandasm::AsmEmitter::GetLastError());
        return 1;
    }

    if (options->SizeStat()) {
        size_t totalSize = 0;
        std::cout << "Panda file size statistic:" << std::endl;
        constexpr std::array<std::string_view, 2> INFO_STATS = {"instructions_number", "codesize"};

        for (const auto &[name, size] : stat) {
            if (find(INFO_STATS.begin(), INFO_STATS.end(), name) != INFO_STATS.end()) {
                continue;
            }
            std::cout << name << " section: " << size << std::endl;
            totalSize += size;
        }

        for (const auto &name : INFO_STATS) {
            std::cout << name << ": " << stat.at(std::string(name)) << std::endl;
        }

        std::cout << "total: " << totalSize << std::endl;
    }

    return 0;
}

}  // namespace panda::es2panda::util
