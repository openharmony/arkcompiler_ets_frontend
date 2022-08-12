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

#include "assemblyFunction.h"

namespace panda::proto {
void CatchBlock::Serialize(const panda::pandasm::Function::CatchBlock &block, proto_panda::CatchBlock &protoBlock)
{
    protoBlock.set_whole_line(block.whole_line);
    protoBlock.set_exception_record(block.exception_record);
    protoBlock.set_try_begin_label(block.try_begin_label);
    protoBlock.set_try_end_label(block.try_end_label);
    protoBlock.set_catch_begin_label(block.catch_begin_label);
    protoBlock.set_catch_end_label(block.catch_end_label);
}

void Parameter::Serialize(const panda::pandasm::Function::Parameter &param, proto_panda::Parameter &protoParam)
{
    auto *type = protoParam.mutable_type();
    Type::Serialize(param.type, *type);
    auto *metadata = protoParam.mutable_metadata();
    ParamMetadata::Serialize(*(param.metadata), *metadata);
}

void Function::Serialize(const panda::pandasm::Function &function, proto_panda::Function &protoFunction)
{
    protoFunction.set_name(function.name);
    protoFunction.set_language(static_cast<uint32_t>(function.language));

    auto *protoFuncMeta = protoFunction.mutable_metadata();
    FunctionMetadata::Serialize(*function.metadata, *protoFuncMeta);


    for (const auto &[name, label] : function.label_table) {
        auto *labelMap = protoFunction.add_label_table();
        labelMap->set_key(name);
        auto *protoLabel = labelMap->mutable_value();
        Label::Serialize(label, *protoLabel);
    }

    for (const auto &insn : function.ins) {
        auto *protoIns = protoFunction.add_ins();
        Ins::Serialize(insn, *protoIns);
    }

    for (const auto &debug : function.local_variable_debug) {
        auto *protoDebug = protoFunction.add_local_variable_debug();
        LocalVariable::Serialize(debug, *protoDebug);
    }

    protoFunction.set_source_file(function.source_file);
    protoFunction.set_source_code(function.source_code);

    for (const auto &block : function.catch_blocks) {
        auto *protoBlock = protoFunction.add_catch_blocks();
        CatchBlock::Serialize(block, *protoBlock);
    }

    protoFunction.set_value_of_first_param(function.value_of_first_param);
    protoFunction.set_regs_num(function.regs_num);

    for (const auto &param : function.params) {
        auto *protoParam = protoFunction.add_params();
        Parameter::Serialize(param, *protoParam);
    }

    protoFunction.set_body_presence(function.body_presence);

    auto *protoReturnType = protoFunction.mutable_return_type();
    Type::Serialize(function.return_type, *protoReturnType);

    auto *protoBodyLocation = protoFunction.mutable_body_location();
    SourceLocation::Serialize(function.body_location, *protoBodyLocation);

    const auto &fileLocation = function.file_location;
    if (fileLocation.has_value()) {
        auto *protoFileLocation = protoFunction.mutable_file_location();
        FileLocation::Serialize(fileLocation.value(), *protoFileLocation);
    }
}
} // panda::proto