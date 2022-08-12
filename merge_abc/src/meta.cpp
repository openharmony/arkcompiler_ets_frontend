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
#include "meta.h"

namespace panda::proto {

void RecordMetadata::Serialize(const panda::pandasm::RecordMetadata &meta, proto_panda::RecordMetadata &protoMeta)
{
    auto *protoItemmetadata = protoMeta.mutable_father();
    ItemMetadata::Serialize(static_cast<const panda::pandasm::ItemMetadata &>(meta), *protoItemmetadata);
}

void FunctionMetadata::Serialize(const panda::pandasm::FunctionMetadata &meta,
                                              proto_panda::FunctionMetadata &protoMeta)
{
    auto *protoItemmetadata = protoMeta.mutable_father();
    ItemMetadata::Serialize(static_cast<const panda::pandasm::ItemMetadata &>(meta), *protoItemmetadata);
}

void FieldMetadata::Serialize(const panda::pandasm::FieldMetadata &meta, proto_panda::FieldMetadata &protoMeta)
{
    auto *protoItemmetadata = protoMeta.mutable_father();
    ItemMetadata::Serialize(meta, *protoItemmetadata);
    auto *protoType = protoMeta.mutable_field_type();
    Type::Serialize(meta.GetFieldType(), *protoType);
    const auto val = meta.GetValue();
    if (val.has_value()) {
        auto *protoValue = protoMeta.mutable_value();
        ScalarValue::Serialize(val.value(), *protoValue);
    }
}

void ParamMetadata::Serialize(const panda::pandasm::ParamMetadata &meta, proto_panda::ParamMetadata &protoMeta)
{
    auto *protoAnnometadata = protoMeta.mutable_father();
    AnnotationMetadata::Serialize(static_cast<const panda::pandasm::AnnotationMetadata &>(meta), *protoAnnometadata);
}

void ItemMetadata::Serialize(const panda::pandasm::ItemMetadata &meta, proto_panda::ItemMetadata &protoMeta)
{
    auto *protoAnnometadata = protoMeta.mutable_father();
    AnnotationMetadata::Serialize(static_cast<const panda::pandasm::AnnotationMetadata &>(meta), *protoAnnometadata);
    protoMeta.set_access_flags(meta.GetAccessFlags());
}

void AnnotationMetadata::Serialize(const panda::pandasm::AnnotationMetadata &meta,
                                                  proto_panda::AnnotationMetadata &protoMeta)
{
    auto *protoMetadata = protoMeta.mutable_father();
    Metadata::Serialize(static_cast<const panda::pandasm::Metadata &>(meta), *protoMetadata);
    for (const auto &anno : meta.GetAnnotations()) {
        auto *proto_anno = protoMeta.add_annotations();
        AnnotationData::Serialize(anno, *proto_anno);
    }
}

void Metadata::Serialize(const panda::pandasm::Metadata &meta, proto_panda::Metadata &protoMeta)
{
    for (const auto &attr : meta.GetBoolAttributes()) {
        protoMeta.add_set_attributes(attr);
    }
    for (const auto &[name, attrs] : meta.GetAttributes()) {
        auto *protoKeyVal = protoMeta.add_attributes();
        protoKeyVal->set_key(name);
        for (const auto &attr : attrs) {
            protoKeyVal->add_value(attr);
        }
    }
}
} // panda::proto
