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

#include "protobufSnapshotGenerator.h"
#include "assembly-program.h"
#include "assemblyProgramProto.h"

namespace panda::proto {
void ProtobufSnapshotGenerator::GenerateSnapshot(const panda::pandasm::Program &program, const std::string &outputName)
{
    proto_panda::Program protoProgram;

    panda::proto::Program::Serialize(program, protoProgram);

    std::fstream output(outputName, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!output) {
        std::cout << ": Fail to create file" << std::endl;
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
        std::cerr << "Failed to open " << inputName << std::endl;
        return;
    }
    proto_panda::Program proto_program;
    if (!proto_program.ParseFromIstream(&input)) {
        std::cerr << "Failed to parse " << inputName << std::endl;
        return;
    }
    Program program;
    program.Deserialize(proto_program, prog, allocator);
}
} // panda::proto
