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

#include "assemblyIns.h"

namespace panda::proto {
void Ins::Serialize(const panda::pandasm::Ins &insn, proto_panda::Ins &protoInsn)
{
    protoInsn.set_opcode(static_cast<uint32_t>(insn.opcode));
    for (const auto &reg : insn.regs) {
        protoInsn.add_regs(static_cast<uint32_t>(reg));
    }
    for (const auto &str : insn.ids) {
        protoInsn.add_ids(str);
    }
    for (const auto imm : insn.imms) {
        auto *protoImm = protoInsn.add_imms();
        switch (static_cast<proto_panda::Ins_IType::TypeCase>(imm.index() + 1)) {  // 1: enum TypeCase start from 1
            case proto_panda::Ins_IType::kValueInt:
                protoImm->set_value_int(std::get<int64_t>(imm));
                break;
            case proto_panda::Ins_IType::kValueDouble:
                protoImm->set_value_double(std::get<double>(imm));
                break;
            default:
                UNREACHABLE();
        }
    }
    protoInsn.set_label(insn.label);
    protoInsn.set_set_label(insn.set_label);
    auto *protoDebug = protoInsn.mutable_ins_debug();
    DebuginfoIns::Serialize(insn.ins_debug, *protoDebug);
}
} // panda::proto