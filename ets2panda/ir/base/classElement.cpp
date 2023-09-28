/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "classElement.h"

#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"

namespace panda::es2panda::ir {

Identifier *ClassElement::Id()
{
    return key_->AsIdentifier();
}

const Identifier *ClassElement::Id() const
{
    return key_->AsIdentifier();
}

bool ClassElement::IsPrivateElement() const
{
    if (IsClassStaticBlock()) {
        return false;
    }

    return key_->IsIdentifier() && key_->AsIdentifier()->IsPrivateIdent();
}
}  // namespace panda::es2panda::ir
