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

#ifndef MERGE_ABC_META_H
#define MERGE_ABC_META_H

#include "assembly-program.h"
#include "annotation.h"
#include "assemblyType.h"
#include "meta.pb.h"

namespace panda::proto {

class RecordMetadata {
public:
    static void Serialize(const panda::pandasm::RecordMetadata &meta, proto_panda::RecordMetadata &protoMeta);
};

class FunctionMetadata {
public:
    static void Serialize(const panda::pandasm::FunctionMetadata &meta,
                                    proto_panda::FunctionMetadata &protoMeta);
};

class FieldMetadata {
public:
    static void Serialize(const panda::pandasm::FieldMetadata &meta, proto_panda::FieldMetadata &protoMeta);
};

class ParamMetadata {
public:
    static void Serialize(const panda::pandasm::ParamMetadata &meta, proto_panda::ParamMetadata &protoMeta);
};

class ItemMetadata {
public:
    static void Serialize(const panda::pandasm::ItemMetadata &meta, proto_panda::ItemMetadata &protoMeta);
};

class AnnotationMetadata {
public:
    static void Serialize(const panda::pandasm::AnnotationMetadata &meta,
                                     proto_panda::AnnotationMetadata &protoMeta);
};

class Metadata {
public:
    static void Serialize(const panda::pandasm::Metadata &meta, proto_panda::Metadata &protoMeta);
};
} // panda::proto
#endif