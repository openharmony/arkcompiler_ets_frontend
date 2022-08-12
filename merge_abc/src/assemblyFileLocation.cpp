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

#include "assemblyFileLocation.h"

namespace panda::proto {
void FileLocation::Serialize(const panda::pandasm::FileLocation &location, proto_panda::FileLocation &protoLocation)
{
    protoLocation.set_whole_line(location.whole_line);
    protoLocation.set_bound_left(location.bound_left);
    protoLocation.set_bound_right(location.bound_right);
    protoLocation.set_is_defined(location.is_defined);
}
} // panda::proto
