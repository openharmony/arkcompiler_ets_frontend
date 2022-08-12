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
#include "assemblyLabel.h"
#include "assemblyType.h"
#include "assemblyIns.h"
#include "assemblyDebug.h"
#include "ideHelpers.h"
#include "assemblyFileLocation.h"
#include "meta.h"
#include "assemblyFunction.pb.h"

namespace panda::proto {
class CatchBlock {
public:
    static void Serialize(const panda::pandasm::Function::CatchBlock &block, proto_panda::CatchBlock &protoBlock);
};

class Parameter {
public:
    static void Serialize(const panda::pandasm::Function::Parameter &param, proto_panda::Parameter &protoParam);
};

class Function {
public:
    static void Serialize(const panda::pandasm::Function &function, proto_panda::Function &protoFunction);
};
} // panda::proto
#endif

