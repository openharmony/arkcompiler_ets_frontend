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

#include "compositeProgramProto.h"

namespace panda::proto {
void CompositeProgram::Serialize(const std::map<std::string, panda::es2panda::util::ProgramCache*> &compositeProgramMap,
                                 bool isDebug, protoPanda::CompositeProgram &protoCompositeProgram)
{
    for (const auto &[fileName, programCache] : compositeProgramMap) {
        auto *protoProgramcache = protoCompositeProgram.add_programcache();
        protoProgramcache->set_filename(fileName);
        protoProgramcache->set_hashcode(programCache->hashCode);
        auto *protoProgram = protoProgramcache->mutable_program();
        Program::Serialize(*(programCache->program), *protoProgram);
    }
    protoCompositeProgram.set_isdebug(isDebug);
}

void CompositeProgram::Deserialize(const protoPanda::CompositeProgram &protoCompositeProgram,
                                   std::map<std::string, panda::es2panda::util::ProgramCache*> &compositeProgramMap,
                                   panda::ArenaAllocator *allocator)
{
    for (const auto &protoProgramcache : protoCompositeProgram.programcache()) {
        auto &fileName = protoProgramcache.filename();
        auto hashCode = protoProgramcache.hashcode();
        auto &protoProgram = protoProgramcache.program();
        auto *program = allocator->New<panda::pandasm::Program>();
        Program::Deserialize(protoProgram, *program, allocator);
        auto *programCache = allocator->New<panda::es2panda::util::ProgramCache>(hashCode, program);
        compositeProgramMap.insert({fileName, programCache});
    }
}
} // namespace panda::proto
