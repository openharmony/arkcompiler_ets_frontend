/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "assemblyProgramProto.h"
#include "assembly-program.h"
#include "protobufSnapshotGenerator.h"

namespace panda::proto {
void ProtobufSnapshotGenerator::GenerateSnapshot(const panda::pandasm::Program &program, const std::string &outputName)
{
    protoPanda::Program protoProgram;

    Program::Serialize(program, protoProgram);

    std::fstream output(outputName, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!output) {
        std::cerr << "Failed to create: " << outputName << std::endl;
        return;
    }
    protoProgram.SerializeToOstream(&output);
    output.close();
}

void ProtobufSnapshotGenerator::GenerateProgram(const std::string &inputName, panda::pandasm::Program &prog,
                                                panda::ArenaAllocator *allocator)
{
    std::fstream input(inputName, std::ios::in | std::ios::binary);
    if (!input) {
        std::cerr << "Failed to open: " << inputName << std::endl;
        return;
    }
    protoPanda::Program proto_program;
    if (!proto_program.ParseFromIstream(&input)) {
        std::cerr << "Failed to parse: " << inputName << std::endl;
        return;
    }
    Program::Deserialize(proto_program, prog, allocator);
}

void ProtobufSnapshotGenerator::UpdateCacheFile(
    const std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> &compositeProgramMap,
    bool &isDebug, const std::string &cacheFilePath)
{
    protoPanda::CompositeProgram protoCompositeProgram;
    CompositeProgram::Serialize(compositeProgramMap, isDebug, protoCompositeProgram);
    std::fstream output(cacheFilePath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!output) {
        std::cerr << "Failed to create cache file: " << cacheFilePath << std::endl;
        return;
    }
    protoCompositeProgram.SerializeToOstream(&output);
    output.close();
}

std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> *ProtobufSnapshotGenerator::GetCacheContext(
    const std::string &cacheFilePath, bool isDebug, panda::ArenaAllocator *allocator)
{
    std::fstream input(cacheFilePath, std::ios::in | std::ios::binary);
    if (!input) {
        std::cerr << "Cache file: " << cacheFilePath << " doesn't exist" << std::endl;
        return nullptr;
    }
    protoPanda::CompositeProgram protoCompositeProgram;
    if (!protoCompositeProgram.ParseFromIstream(&input)) {
        std::cerr << "Failed to parse cache file: " << cacheFilePath << std::endl;
        return nullptr;
    }

    if (protoCompositeProgram.isdebug() != isDebug) {
        return nullptr;
    }

    auto compositeProgramMap = allocator->New<std::unordered_map<std::string, panda::es2panda::util::ProgramCache*>>();
    CompositeProgram::Deserialize(protoCompositeProgram, *compositeProgramMap, allocator);

    return compositeProgramMap;
}
} // panda::proto
