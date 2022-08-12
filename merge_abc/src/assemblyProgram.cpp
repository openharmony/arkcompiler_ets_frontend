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

#include "assemblyProgram.h"

namespace panda::proto {
void Program::Serialize(const panda::pandasm::Program &program, proto_panda::Program &protoProgram)
{
    protoProgram.set_lang(static_cast<uint32_t>(program.lang));

    for (const auto &[name, record] : program.record_table) {
        auto *recordMap = protoProgram.add_record_table();
        recordMap->set_key(name);
        auto *protoRecord = recordMap->mutable_value();
        Record::Serialize(record, *protoRecord);
    }

    for (const auto &[name, func] : program.function_table) {
        auto *functionMap = protoProgram.add_function_table();
        functionMap->set_key(name);
        auto *protoFunc = functionMap->mutable_value();
        Function::Serialize(func, *protoFunc);
    }
    // TODO: support function_synonyms
    for (const auto &[name, array] : program.literalarray_table) {
        auto *literalarrayMap = protoProgram.add_literalarray_table();
        literalarrayMap->set_key(name);
        auto *protoArray = literalarrayMap->mutable_value();
        LiteralArray::Serialize(array, *protoArray);
    }
    for (const auto &str : program.strings) {
        protoProgram.add_strings(str);
    }
    for (const auto &type : program.array_types) {
        auto *protoType = protoProgram.add_array_types();
        Type::Serialize(type, *protoType);
    }
}
} // panda::proto