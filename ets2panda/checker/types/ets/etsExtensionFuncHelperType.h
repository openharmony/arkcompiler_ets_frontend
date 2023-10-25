/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

namespace panda::es2panda::checker {
class ETSExtensionFuncHelperType : public Type {
public:
    ETSExtensionFuncHelperType(ETSFunctionType *class_method_type, ETSFunctionType *extension_function_type)
        : Type(TypeFlag::ETS_EXTENSION_FUNC_HELPER),
          class_method_type_(class_method_type),
          extension_function_type_(extension_function_type)
    {
    }

    ETSFunctionType *ClassMethodType()
    {
        return class_method_type_;
    }

    ETSFunctionType *ExtensionMethodType()
    {
        return extension_function_type_;
    }

    void ToString(std::stringstream &ss) const override;
    void AssignmentTarget(TypeRelation *relation, Type *source) override;

private:
    ETSFunctionType *class_method_type_ {};
    ETSFunctionType *extension_function_type_ {};
};
}  // namespace panda::es2panda::checker

#endif
