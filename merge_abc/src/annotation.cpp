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

#include "annotation.h"

namespace panda::proto {
void AnnotationData::Serialize(const panda::pandasm::AnnotationData &anno, proto_panda::AnnotationData &protoAnno)
{
    protoAnno.set_record_name(anno.GetName());
    for (const auto &element : anno.GetElements()) {
        auto *protoElement = protoAnno.add_elements();
        AnnotationElement::Serialize(element, *protoElement);
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

void ArrayValue::Serialize(const panda::pandasm::ArrayValue &array, proto_panda::ArrayValue &protoArray)
{
    protoArray.mutable_father()->set_type(static_cast<uint32_t>(array.GetType()));
    protoArray.set_component_type(static_cast<uint32_t>(array.GetComponentType()));
    for (const auto &val : array.GetValues()) {
        auto *protoScalar = protoArray.add_values();
        ScalarValue::Serialize(val, *protoScalar);
    }
}

} // panda::proto