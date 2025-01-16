/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_FUNCTION_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_FUNCTION_TYPE_H

#include "checker/types/ets/etsFunctionType.h"
#include "checker/ETSchecker.h"

namespace ark::es2panda::checker {

class ETSDynamicFunctionType : public ETSFunctionType {
public:
    explicit ETSDynamicFunctionType(ETSChecker *checker, util::StringView const &name, Signature *signature,
                                    Language const lang)
        : ETSFunctionType(checker, name, signature), lang_(lang)
    {
        AddTypeFlag(TypeFlag::ETS_DYNAMIC_FUNCTION_TYPE);
    }

    explicit ETSDynamicFunctionType(util::StringView const &name, ArenaAllocator *allocator, Language const lang)
        : ETSFunctionType(name, allocator), lang_(lang)
    {
        AddTypeFlag(TypeFlag::ETS_DYNAMIC_FUNCTION_TYPE);
    }

    ETSDynamicFunctionType() = delete;
    ~ETSDynamicFunctionType() override = default;
    NO_COPY_SEMANTIC(ETSDynamicFunctionType);
    NO_MOVE_SEMANTIC(ETSDynamicFunctionType);

    es2panda::Language Language() const
    {
        return lang_;
    }

private:
    es2panda::Language lang_;
};
}  // namespace ark::es2panda::checker

#endif /* ES2PANDA_COMPILER_CHECKER_TYPES_ETS_DYNAMIC_FUNCTION_TYPE_H */
