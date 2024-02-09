/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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
#include "checker/types/ets/types.h"
#include "checker/ETSchecker.h"
#include "util/helpers.h"
#include "checker/ets/primitiveWrappers.h"

namespace ark::es2panda::checker {

checker::ETSObjectType *BoxingConverter::ETSTypeFromSource(ETSChecker const *checker, Type const *source)
{
    auto getSignature = [](checker::TypeFlag typeKind) {
        switch (typeKind) {
            case checker::TypeFlag::ETS_BOOLEAN: {
                return compiler::Signatures::BUILTIN_BOOLEAN_CLASS;
            }
            case checker::TypeFlag::BYTE: {
                return compiler::Signatures::BUILTIN_BYTE_CLASS;
            }
            case checker::TypeFlag::SHORT: {
                return compiler::Signatures::BUILTIN_SHORT_CLASS;
            }
            case checker::TypeFlag::CHAR: {
                return compiler::Signatures::BUILTIN_CHAR_CLASS;
            }
            case checker::TypeFlag::INT: {
                return compiler::Signatures::BUILTIN_INT_CLASS;
            }
            case checker::TypeFlag::LONG: {
                return compiler::Signatures::BUILTIN_LONG_CLASS;
            }
            case checker::TypeFlag::FLOAT: {
                return compiler::Signatures::BUILTIN_FLOAT_CLASS;
            }
            case checker::TypeFlag::DOUBLE: {
                return compiler::Signatures::BUILTIN_DOUBLE_CLASS;
            }
            default:
                UNREACHABLE();
        }
    };

    auto wrapMap = checker->PrimitiveWrapper();
    return wrapMap.find(getSignature(checker::ETSChecker::TypeKind(source)))->second.first;
}

}  // namespace ark::es2panda::checker
