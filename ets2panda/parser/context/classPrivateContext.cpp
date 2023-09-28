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

#include "classPrivateContext.h"

#include "plugins/ecmascript/es2panda/ir/expression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/base/classElement.h"
#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"

namespace panda::es2panda::parser {
bool ClassPrivateContext::AddElement(const ir::ClassElement *elem)
{
    bool new_prop_is_static = elem->IsStatic();
    util::StringView new_prop_name = elem->Id()->Name();
    ir::MethodDefinitionKind new_prop_method_kind = ir::MethodDefinitionKind::METHOD;

    if (elem->IsMethodDefinition()) {
        new_prop_method_kind = elem->AsMethodDefinition()->Kind();
    }

    for (const auto *prop : elements_) {
        const ir::Identifier *ident = prop->Id();
        ir::MethodDefinitionKind method_kind = ir::MethodDefinitionKind::METHOD;
        bool is_static = prop->IsStatic();

        if (prop->IsMethodDefinition()) {
            method_kind = prop->AsMethodDefinition()->Kind();
        }

        if (ident == nullptr || !ident->IsPrivateIdent() || ident->Name() != new_prop_name ||
            is_static != new_prop_is_static) {
            continue;
        }

        if ((new_prop_method_kind == ir::MethodDefinitionKind::GET && method_kind == ir::MethodDefinitionKind::SET) ||
            (new_prop_method_kind == ir::MethodDefinitionKind::SET && method_kind == ir::MethodDefinitionKind::GET)) {
            continue;
        }

        return false;
    }

    elements_.push_back(elem);

    return true;
}

bool ClassPrivateContext::FindElement(const ir::Identifier *elem) const
{
    for (const auto *it : elements_) {
        if (it->Id()->Name().Compare(elem->Name()) == 0) {
            return true;
        }
    }

    if (prev_ != nullptr) {
        return prev_->FindElement(elem);
    }

    return false;
}
}  // namespace panda::es2panda::parser
