/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_ETSGEN_INL_H
#define ES2PANDA_COMPILER_CORE_ETSGEN_INL_H

#include "ETSGen.h"

#include "checker/ETSchecker.h"

namespace ark::es2panda::compiler {

template <typename T>
void ETSGen::MoveImmediateToRegister(const ir::AstNode *node, VReg reg, const checker::TypeFlag valueType,
                                     T const value)
{
    switch (valueType) {
        case checker::TypeFlag::ETS_BOOLEAN:
            [[fallthrough]];
        case checker::TypeFlag::BYTE: {
            Ra().Emit<Movi>(node, reg, static_cast<checker::ByteType::UType>(value));
            SetVRegType(reg, Checker()->GlobalByteType());
            break;
        }
        case checker::TypeFlag::CHAR: {
            Ra().Emit<Movi>(node, reg, static_cast<checker::CharType::UType>(value));
            SetVRegType(reg, Checker()->GlobalCharType());
            break;
        }
        case checker::TypeFlag::SHORT: {
            Ra().Emit<Movi>(node, reg, static_cast<checker::ShortType::UType>(value));
            SetVRegType(reg, Checker()->GlobalShortType());
            break;
        }
        case checker::TypeFlag::INT: {
            Ra().Emit<Movi>(node, reg, static_cast<checker::IntType::UType>(value));
            SetVRegType(reg, Checker()->GlobalIntType());
            break;
        }
        case checker::TypeFlag::LONG: {
            Ra().Emit<MoviWide>(node, reg, static_cast<checker::LongType::UType>(value));
            SetVRegType(reg, Checker()->GlobalLongType());
            break;
        }
        case checker::TypeFlag::FLOAT: {
            Ra().Emit<Fmovi>(node, reg, static_cast<checker::FloatType::UType>(value));
            SetVRegType(reg, Checker()->GlobalFloatType());
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            Ra().Emit<FmoviWide>(node, reg, static_cast<checker::DoubleType::UType>(value));
            SetVRegType(reg, Checker()->GlobalDoubleType());
            break;
        }
        default: {
            ES2PANDA_UNREACHABLE();
        }
    }
}

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_CORE_ETSGEN_INL_H
