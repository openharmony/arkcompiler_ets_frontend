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

#include "assemblyDebug.h"

namespace panda::proto {
void DebuginfoIns::Serialize(const panda::pandasm::debuginfo::Ins &debug, proto_panda::DebuginfoIns &protoDebug)
{
    protoDebug.set_line_number(debug.line_number);
    protoDebug.set_column_number(debug.column_number);
    protoDebug.set_whole_line(debug.whole_line);
    protoDebug.set_bound_left(debug.bound_left);
    protoDebug.set_bound_right(debug.bound_right);
}

void LocalVariable::Serialize(const panda::pandasm::debuginfo::LocalVariable &debug,
                                              proto_panda::LocalVariable &protoDebug)
{
    protoDebug.set_name(debug.name);
    protoDebug.set_signature(debug.signature);
    protoDebug.set_signature_type(debug.signature_type);
    protoDebug.set_reg(debug.reg);
    protoDebug.set_start(debug.start);
    protoDebug.set_length(debug.length);
}
} // panda::proto