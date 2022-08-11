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

#ifndef MERGE_ABC_ASSEMBLY_FUNCTION_H
#define MERGE_ABC_ASSEMBLY_FUNCTION_H

#include "assembly-program.h"
#include "assemblyLabelProto.h"
#include "assemblyTypeProto.h"
#include "assemblyInsProto.h"
#include "assemblyDebugProto.h"
#include "ideHelpersProto.h"
#include "assemblyFileLocationProto.h"
#include "metaProto.h"
#include "assemblyFunction.pb.h"
#include "arena_allocator.h"

namespace panda::proto {
class CatchBlock {
public:
    static void Serialize(const panda::pandasm::Function::CatchBlock &block, proto_panda::CatchBlock &protoBlock);
    static void Deserialize(const proto_panda::CatchBlock &protoBlock, panda::pandasm::Function::CatchBlock &block);
};

class Parameter {
public:
    static void Serialize(const panda::pandasm::Function::Parameter &param, proto_panda::Parameter &protoParam);
    static void Deserialize(const proto_panda::Parameter &protoParam, panda::pandasm::Function::Parameter &param,
                            panda::ArenaAllocator *allocator_);
};

class Function {
public:
    static void Serialize(const panda::pandasm::Function &function, proto_panda::Function &protoFunction);
    static void Deserialize(const proto_panda::Function &protoFunction, panda::pandasm::Function &function,
                            panda::ArenaAllocator *allocator_);
};
} // panda::proto
#endif
