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

#include "assemblyType.h"

namespace panda::proto {
void Type::Serialize(const panda::pandasm::Type type, proto_panda::Type &protoType)
{   
    protoType.set_component_name(type.GetComponentName());
    protoType.set_rank(type.GetRank());
    protoType.set_name(type.GetName());
    protoType.set_type_id(static_cast<uint32_t>(type.GetId()));
}
} // panda::proto