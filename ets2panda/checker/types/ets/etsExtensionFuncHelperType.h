/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_ETS_EXTENSION_FUNC_HELPER_TYPE_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_ETS_EXTENSION_FUNC_HELPER_TYPE_H

#include "checker/types/type.h"

namespace ark::es2panda::checker {
class ETSExtensionFuncHelperType : public Type {
public:
    ETSExtensionFuncHelperType(ETSFunctionType *classMethodType, ETSFunctionType *extensionFunctionType)
        : Type(TypeFlag::ETS_EXTENSION_FUNC_HELPER),
          classMethodType_(classMethodType),
          extensionFunctionType_(extensionFunctionType)
    {
    }

    ETSFunctionType *ClassMethodType()
    {
        return classMethodType_;
    }

    ETSFunctionType *ExtensionMethodType()
    {
        return extensionFunctionType_;
    }

    void ToString(std::stringstream &ss, bool precise) const override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;

private:
    ETSFunctionType *classMethodType_ {};
    ETSFunctionType *extensionFunctionType_ {};
};
}  // namespace ark::es2panda::checker

#endif
