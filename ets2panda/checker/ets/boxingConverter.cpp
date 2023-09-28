/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "boxingConverter.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/types.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/checker/ets/primitiveWrappers.h"

namespace panda::es2panda::checker {

void BoxingConverter::ETSTypeFromSource(Type *source)
{
    auto type_kind = checker::ETSChecker::TypeKind(source);

    auto wrap_map = Checker()->PrimitiveWrapper();

    switch (type_kind) {
        case checker::TypeFlag::ETS_BOOLEAN: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_BOOLEAN_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::BYTE: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_BYTE_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::SHORT: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_SHORT_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::CHAR: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_CHAR_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::INT: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_INT_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::LONG: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_LONG_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::FLOAT: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_FLOAT_CLASS);
            SetResult(res->second.first);
            break;
        }
        case checker::TypeFlag::DOUBLE: {
            auto res = wrap_map.find(compiler::Signatures::BUILTIN_DOUBLE_CLASS);
            SetResult(res->second.first);
            break;
        }
        default:
            UNREACHABLE();
    }
}

}  // namespace panda::es2panda::checker
