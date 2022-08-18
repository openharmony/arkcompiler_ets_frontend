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

#include "assemblyFieldProto.h"

namespace panda::proto {
void Field::Serialize(const panda::pandasm::Field &field, proto_panda::Field &protoField)
{
    auto *protoType = protoField.mutable_type();
    Type::Serialize(field.type, *protoType);
    protoField.set_name(field.name);
    auto *protoFieldmeta = protoField.mutable_metadata();
    FieldMetadata::Serialize(*field.metadata, *protoFieldmeta);
    protoField.set_line_of_def(field.line_of_def);
    protoField.set_whole_line(field.whole_line);
    protoField.set_bound_left(field.bound_left);
    protoField.set_bound_right(field.bound_right);
    protoField.set_is_defined(field.is_defined);
}

void Field::Deserialize(const proto_panda::Field &protoField, panda::pandasm::Field &field,
                        std::unique_ptr<panda::ArenaAllocator> &&allocator)
{
    field.type = Type::Deserialize(protoField.type(), std::move(allocator));
    field.name = protoField.name();
    FieldMetadata::Deserialize(protoField.metadata(), field.metadata, std::move(allocator));
    field.line_of_def = protoField.line_of_def();
    field.whole_line = protoField.whole_line();
    field.bound_left = protoField.bound_left();
    field.bound_right = protoField.bound_right();
    field.is_defined = protoField.is_defined();
}
} // panda::proto