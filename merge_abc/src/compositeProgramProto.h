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

#ifndef MERGE_ABC_BUILD_COMPOSITE_PROGRAM_H
#define MERGE_ABC_BUILD_COMPOSITE_PROGRAM_H

#include "assemblyProgramProto.h"
#include "compositeProgram.pb.h"
#include "programCache.h"

namespace panda::proto {
class CompositeProgram {
public:
    static void Serialize(
        const std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> &compositeProgramMap, bool isDebug,
        protoPanda::CompositeProgram &protoCompositeProgram);
    static void Deserialize(const protoPanda::CompositeProgram &protoCompositeProgram,
        std::unordered_map<std::string, panda::es2panda::util::ProgramCache*> &compositeProgramMap,
        panda::ArenaAllocator *allocator);
};
} // panda::proto
#endif
