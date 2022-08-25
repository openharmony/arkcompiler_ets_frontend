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

void CompositeProgram::Serialize(const panda::es2panda::util::CompositeProgram &compositeProgram,
                                 protoPanda::CompositeProgram &protoCompositeProgram)
{
    for (const auto &[fileName, hashProgram] : compositeProgramMap.compositeProgramInfo) {
        auto protoHashNameProgram = protoCompositeProgram.add_hashnameprogram();
        protoHashNameProgram->set_filename(fileName);
        protoHashNameProgram->set_hashcode(hashProgram->hashCode);
        auto *protoProgram = protoHashNameProgram->mutable_program();
        Program::Serialize(*(hashProgram->program), *protoProgram);
    }
}

void CompositeProgram::Deserialize(const protoPanda::CompositeProgram &protoCompositeProgram,
                                   panda::es2panda::util::CompositeProgramMap &compositeProgramMap,
                                   panda::ArenaAllocator *allocator)
{
    for (const auto &protoHashNameProgram : protoCompositeProgram.hashnameprogram()) {
        auto fileName = protoHashNameProgram.filename();
        auto hashCode = protoHashNameProgram.hashcode();
        auto protoProgram = protoHashNameProgram.program();
        auto *program = allocator->New<panda::pandasm::Program>();
        Program::Deserialize(protoProgram, *program, allocator);
        auto *hashProgram = allocator->New<panda::es2panda::util::HashProgram>(hashCode, program);
        compositeProgramMap.compositeProgramInfo.insert({fileName, hashProgram});
    }
}

} // namespace panda::proto
