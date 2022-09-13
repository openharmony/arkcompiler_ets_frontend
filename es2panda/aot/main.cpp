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

#include <assembly-program.h>
#include <assembly-emitter.h>
#include <es2panda.h>
#include <mem/arena_allocator.h>
#include <mem/pool_manager.h>
#include <options.h>
#include <protobufSnapshotGenerator.h>
#include <util/dumper.h>
#include <util/moduleHelpers.h>
#include <util/programCache.h>

#include <iostream>

namespace panda::es2panda::aot {
using mem::MemConfig;
class MemManager {
public:
    explicit MemManager()
    {
        constexpr auto COMPILER_SIZE = 512_MB;

        MemConfig::Initialize(0, 0, COMPILER_SIZE, 0);
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

static void GenerateBase64Output(panda::pandasm::Program *prog,
                                 panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps *mapsp)
{
    auto pandaFile = panda::pandasm::AsmEmitter::Emit(*prog, mapsp);
    const uint8_t *buffer = pandaFile->GetBase();
    size_t size = pandaFile->GetPtr().GetSize();
    std::string content(reinterpret_cast<const char*>(buffer), size);
    std::string base64Output = util::Base64Encode(content);
    std::cout << base64Output << std::endl;
}

static void DumpPandaFileSizeStatistic(std::map<std::string, size_t> &stat)
{
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

static bool GenerateProgram(std::vector<panda::pandasm::Program *> &progs,
    std::unique_ptr<panda::es2panda::aot::Options> &options)
{
    int optLevel = options->OptLevel();
    bool dumpSize = options->SizeStat();
    const std::string output = options->CompilerOutput();
    const es2panda::CompilerOptions compilerOptions = options->CompilerOptions();
    if (compilerOptions.dumpAsm || compilerOptions.dumpLiteralBuffer) {
        for (auto *prog : progs) {
            if (compilerOptions.dumpAsm) {
                es2panda::Compiler::DumpAsm(prog);
            }

            if (compilerOptions.dumpLiteralBuffer) {
                panda::es2panda::util::Dumper::DumpLiterals(prog->literalarray_table);
            }
        }
    }

    if (progs.size() > 1) {
        if (!panda::pandasm::AsmEmitter::EmitPrograms(output, progs, true)) {
            std::cerr << "Failed to emit merged program " << std::endl;
            return false;
        }
    } else {
        auto *prog = progs[0];
        std::map<std::string, size_t> stat;
        std::map<std::string, size_t> *statp = optLevel != 0 ? &stat : nullptr;
        panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps maps {};
        panda::pandasm::AsmEmitter::PandaFileToPandaAsmMaps *mapsp = optLevel != 0 ? &maps : nullptr;

        if (output.empty()) {
            GenerateBase64Output(prog, mapsp);
            return true;
        }

        if (options->compilerProtoOutput().size() > 0) {
            panda::proto::ProtobufSnapshotGenerator::GenerateSnapshot(*prog, options->compilerProtoOutput());
            return true;
        }

        if (!panda::pandasm::AsmEmitter::Emit(output, *prog, statp, mapsp, true)) {
            return false;
        }

        if (dumpSize && optLevel != 0) {
            DumpPandaFileSizeStatistic(stat);
        }
    }

    return true;
}

int Run(int argc, const char **argv)
{
    auto options = std::make_unique<Options>();
    if (!options->Parse(argc, argv)) {
        std::cerr << options->ErrorMsg() << std::endl;
        return 1;
    }

    std::map<std::string, panda::es2panda::util::ProgramCache*> programsInfo;
    size_t expectedProgsCount = options->CompilerOptions().sourceFiles.size();
    panda::ArenaAllocator allocator(panda::SpaceType::SPACE_TYPE_COMPILER, nullptr, true);
    std::map<std::string, panda::es2panda::util::ProgramCache*> *cachePrograms = nullptr;

    if (!options->CacheFile().empty()) {
        cachePrograms = proto::ProtobufSnapshotGenerator::GetCacheContext(options->CacheFile(),
            options->CompilerOptions().isDebug, &allocator);
    }

    int ret = Compiler::CompileFiles(options->CompilerOptions(), cachePrograms, programsInfo, &allocator);
    if (options->ParseOnly()) {
        return ret;
    }

    if (!options->NpmModuleEntryList().empty()) {
        es2panda::util::ModuleHelpers::CompileNpmModuleEntryList(options->NpmModuleEntryList(), cachePrograms,
            programsInfo, &allocator);
        expectedProgsCount++;
    }

    if (!options->CacheFile().empty()) {
        proto::ProtobufSnapshotGenerator::UpdateCacheFile(programsInfo, options->CompilerOptions().isDebug,
            options->CacheFile());
    }

    std::vector<panda::pandasm::Program*> programs;
    programs.reserve(programsInfo.size());
    for (auto &it : programsInfo) {
        programs.emplace_back(it.second->program);
    }
    if (programs.size() != expectedProgsCount) {
        std::cerr << "the size of programs is expected to be " << expectedProgsCount
                  << ", but is " << programs.size() << std::endl;
        return 1;
    }

    if (!GenerateProgram(programs, options)) {
        std::cerr << "GenerateProgram Failed!" << std::endl;
        return 1;
    }

    return 0;
}
}  // namespace panda::es2panda::aot

int main(int argc, const char **argv)
{
    panda::es2panda::aot::MemManager mm;
    return panda::es2panda::aot::Run(argc, argv);
}
