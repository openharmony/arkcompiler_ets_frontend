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

#include "annotationProto.h"

namespace panda::proto {
void AnnotationData::Serialize(const panda::pandasm::AnnotationData &anno, proto_panda::AnnotationData &protoAnno)
{
    protoAnno.set_record_name(anno.GetName());
    for (const auto &element : anno.GetElements()) {
        auto *protoElement = protoAnno.add_elements();
        AnnotationElement::Serialize(element, *protoElement);
    }
}

void AnnotationData::Deserialize(const proto_panda::AnnotationData &protoAnno, panda::pandasm::AnnotationData &anno,
                                 panda::ArenaAllocator *allocator)
{
    for (const auto &protoElement : protoAnno.elements()) {
        panda::pandasm::AnnotationElement element = AnnotationElement::Deserialize(protoElement, allocator);
        anno.AddElement(std::move(element));
    }
}

void AnnotationElement::Serialize(const panda::pandasm::AnnotationElement &element,
                                  proto_panda::AnnotationElement &protoElement)
{
    protoElement.set_name(element.GetName());
    bool is_array = element.GetValue()->IsArray();
    protoElement.set_is_array(is_array);
    if (is_array) {
        auto *protoArray = protoElement.mutable_array();
        ArrayValue::Serialize(*(element.GetValue()->GetAsArray()), *protoArray);
    } else {
        auto *protoScalar = protoElement.mutable_scalar();
        ScalarValue::Serialize(*(element.GetValue()->GetAsScalar()), *protoScalar);
    }
}

panda::pandasm::AnnotationElement &AnnotationElement::Deserialize(const proto_panda::AnnotationElement &protoElement,
                                                                  panda::ArenaAllocator *allocator)
{
    if (protoElement.is_array()) {
        panda::pandasm::ArrayValue array = ArrayValue::Deserialize(protoElement.array(), allocator);
        auto element = allocator->New<panda::pandasm::AnnotationElement>(protoElement.name(),
            std::make_unique<panda::pandasm::ArrayValue>(array));
        return *element;
    }
    panda::pandasm::ScalarValue scalar = ScalarValue::Deserialize(protoElement.scalar(), allocator);
    auto element = allocator->New<panda::pandasm::AnnotationElement>(protoElement.name(),
        std::make_unique<panda::pandasm::ScalarValue>(scalar));
    return *element;
}

void ScalarValue::Serialize(const panda::pandasm::ScalarValue &scalar, proto_panda::ScalarValue &protoScalar)
{
    const auto &value_type = scalar.GetType();
    protoScalar.mutable_father()->set_type(static_cast<uint32_t>(value_type));
    auto type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_UINT64;
    switch (value_type) {
        case panda::pandasm::Value::Type::U1:
        case panda::pandasm::Value::Type::U8:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<uint8_t>()));
            break;
        case panda::pandasm::Value::Type::U16:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<uint16_t>()));
            break;
        case panda::pandasm::Value::Type::STRING_NULLPTR:
        case panda::pandasm::Value::Type::U32:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<uint32_t>()));
            break;
        case panda::pandasm::Value::Type::U64:
            protoScalar.set_value_u64(scalar.GetValue<uint64_t>());
            break;
        case panda::pandasm::Value::Type::I8:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<int8_t>()));
            break;
        case panda::pandasm::Value::Type::I16:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<int16_t>()));
            break;
        case panda::pandasm::Value::Type::I32:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<int32_t>()));
            break;
        case panda::pandasm::Value::Type::I64:
            protoScalar.set_value_u64(static_cast<uint64_t>(scalar.GetValue<int64_t>()));
            break;
        case panda::pandasm::Value::Type::F32:
            type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_FLOAT;
            protoScalar.set_value_f(scalar.GetValue<float>());
            break;
        case panda::pandasm::Value::Type::F64:
            type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_DOUBLE;
            protoScalar.set_value_d(scalar.GetValue<double>());
            break;
        case panda::pandasm::Value::Type::STRING:
        case panda::pandasm::Value::Type::METHOD:
        case panda::pandasm::Value::Type::ENUM:
            type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_STRING;
            protoScalar.set_value_str(scalar.GetValue<std::string>());
            break;
        case panda::pandasm::Value::Type::RECORD: {
            type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_PANDASM_TYPE;
            auto *protoType = protoScalar.mutable_value_type();
            Type::Serialize(scalar.GetValue<panda::pandasm::Type>(), *protoType);
            break;
        }
        case panda::pandasm::Value::Type::ANNOTATION: {
            type = proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_ANNOTATION_DATA;
            auto *protoAnno = protoScalar.mutable_value_anno();
            AnnotationData::Serialize(scalar.GetValue<panda::pandasm::AnnotationData>(), *protoAnno);
            break;
        }
        default:
            UNREACHABLE();
    }
    protoScalar.set_type(type);
}

panda::pandasm::ScalarValue ScalarValue::Deserialize(const proto_panda::ScalarValue &protoScalar,
                                                     panda::ArenaAllocator *allocator)
{
    proto_panda::ScalarValue_VariantValueType scalarType = protoScalar.type();
    std::variant<uint64_t, float, double, std::string, panda::pandasm::Type, panda::pandasm::AnnotationData> value;
    switch (scalarType) {
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_UINT64: {
            value = static_cast<uint64_t>(protoScalar.value_u64());
            break;
        }
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_FLOAT: {
            value = static_cast<float>(protoScalar.value_f());
            break;
        }
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_DOUBLE: {
            value = static_cast<double>(protoScalar.value_d());
            break;
        }
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_STRING: {
            value = static_cast<std::string>(protoScalar.value_str());
            break;
        }
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_PANDASM_TYPE: {
            value = static_cast<panda::pandasm::Type>(Type::Deserialize(protoScalar.value_type(), allocator));
            break;
        }
        case proto_panda::ScalarValue_VariantValueType::ScalarValue_VariantValueType_ANNOTATION_DATA: {
            auto protoAnnotationData = protoScalar.value_anno();
            auto value = allocator->New<panda::pandasm::AnnotationData>(protoAnnotationData.record_name());
            AnnotationData::Deserialize(protoAnnotationData, *value, allocator);
            break;
        }
        default:
            UNREACHABLE();
    }
    auto scalar = ScalarValue::CreateScalarValue(static_cast<panda::pandasm::Value::Type>(
        protoScalar.father().type()), value);
    return scalar;
}

panda::pandasm::ScalarValue ScalarValue::CreateScalarValue(const panda::pandasm::Value::Type &type,
    std::variant<uint64_t, float, double, std::string, panda::pandasm::Type, panda::pandasm::AnnotationData> &value)
{
    switch (type) {
        case panda::pandasm::Value::Type::U1: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U1>(static_cast<uint8_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::U8: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U8>(static_cast<uint8_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::U16: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U16>(static_cast<uint16_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::STRING_NULLPTR: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::STRING_NULLPTR>(
                static_cast<uint32_t>(std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::U32: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U32>(static_cast<uint32_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::U64: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::U64>(static_cast<uint64_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::I8: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::I8>(static_cast<int8_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::I16: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::I16>(static_cast<int16_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::I32: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::I32>(static_cast<int32_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::I64: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::I64>(static_cast<int64_t>(
                std::get<uint64_t>(value)));
        }
        case panda::pandasm::Value::Type::F32: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::F32>(std::get<float>(value));
        }
        case panda::pandasm::Value::Type::F64: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::F64>(std::get<double>(value));
        }
        case panda::pandasm::Value::Type::STRING: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::STRING>(
                std::get<std::string>(value));
        }
        case panda::pandasm::Value::Type::METHOD: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::METHOD>(
                std::get<std::string>(value));
        }
        case panda::pandasm::Value::Type::ENUM: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::ENUM>(std::get<std::string>(value));
        }
        case panda::pandasm::Value::Type::RECORD: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::RECORD>(
                std::get<panda::pandasm::Type>(value));
        }
        case panda::pandasm::Value::Type::ANNOTATION: {
            return panda::pandasm::ScalarValue::Create<panda::pandasm::Value::Type::ANNOTATION>(
                std::get<panda::pandasm::AnnotationData>(value));
        }
        default:
            UNREACHABLE();
    }
}

void ArrayValue::Serialize(const panda::pandasm::ArrayValue &array, proto_panda::ArrayValue &protoArray)
{
    protoArray.mutable_father()->set_type(static_cast<uint32_t>(array.GetType()));
    protoArray.set_component_type(static_cast<uint32_t>(array.GetComponentType()));
    for (const auto &val : array.GetValues()) {
        auto *protoScalar = protoArray.add_values();
        ScalarValue::Serialize(val, *protoScalar);
    }
}

panda::pandasm::ArrayValue &ArrayValue::Deserialize(const proto_panda::ArrayValue &protoArray,
                                                    panda::ArenaAllocator *allocator)
{
    std::vector<panda::pandasm::ScalarValue> values;
    for (const auto &protoValue : protoArray.values()) {
        panda::pandasm::ScalarValue scalar = ScalarValue::Deserialize(protoValue, allocator);
        values.emplace_back(std::move(scalar));
    }
    auto array = allocator->New<panda::pandasm::ArrayValue>(
        static_cast<panda::pandasm::Value::Type>(protoArray.component_type()), values);
    return *array;
}
} // panda::proto
