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

#include "unboxingConverter.h"
#include "checker/types/ets/types.h"
#include "checker/ETSchecker.h"
#include "util/helpers.h"

namespace panda::es2panda::checker {

checker::Type *UnboxingConverter::GlobalTypeFromSource(ETSObjectFlags type)
{
    switch (type) {
        case ETSObjectFlags::BUILTIN_BOOLEAN: {
            return Checker()->GlobalETSBooleanType();
        }
        case ETSObjectFlags::BUILTIN_BYTE: {
            return Checker()->GlobalByteType();
        }
        case ETSObjectFlags::BUILTIN_SHORT: {
            return Checker()->GlobalShortType();
        }
        case ETSObjectFlags::BUILTIN_CHAR: {
            return Checker()->GlobalCharType();
        }
        case ETSObjectFlags::BUILTIN_INT: {
            return Checker()->GlobalIntType();
        }
        case ETSObjectFlags::BUILTIN_LONG: {
            return Checker()->GlobalLongType();
        }
        case ETSObjectFlags::BUILTIN_FLOAT: {
            return Checker()->GlobalFloatType();
        }
        case ETSObjectFlags::BUILTIN_DOUBLE: {
            return Checker()->GlobalDoubleType();
        }
        default:
            return Source();
    }
}

}  // namespace panda::es2panda::checker
