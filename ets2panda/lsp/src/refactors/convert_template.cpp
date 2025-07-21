/**
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

#include <string_view>
#include "refactors/convert_template.h"
#include "refactor_provider.h"
#include "internal_api.h"

namespace ark::es2panda::lsp {

ConvertTemplateRefactor::ConvertTemplateRefactor()
{
    AddKind(std::string(TO_NAMED_TEMPLATE_ACTION.kind));
}

ApplicableRefactorInfo ConvertTemplateRefactor::GetAvailableActions(const RefactorContext &refContext) const
{
    es2panda_Context *context = refContext.context;
    size_t position = refContext.span.pos;

    ApplicableRefactorInfo res;

    if (!IsKind(refContext.kind)) {
        return res;
    }
    auto node = GetTouchingToken(context, position, false);
    if (node == nullptr) {
        return res;
    }

    if (node != nullptr && node->Parent() != nullptr &&
        (node->Parent()->IsExpression() && node->Parent()->IsBinaryExpression())) {
        res.name = refactor_name::CONVERT_TEMPLATE_REFACTOR_NAME;
        res.description = refactor_description::CONVERT_TEMPLATE_REFACTOR_DESC;
        res.action.kind = std::string(TO_NAMED_TEMPLATE_ACTION.kind);
        res.action.name = std::string(TO_NAMED_TEMPLATE_ACTION.name);
        res.action.description = std::string(TO_NAMED_TEMPLATE_ACTION.description);
    }

    return res;
}

std::unique_ptr<RefactorEditInfo> ConvertTemplateRefactor::GetEditsForAction(const RefactorContext &context,
                                                                             const std::string &actionName) const
{
    (void)context;
    (void)actionName;
    return std::make_unique<RefactorEditInfo>();
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoRefactorRegister<ConvertTemplateRefactor> g_convertTemplateRefactorRegister("ConvertTemplateRefactor");

}  // namespace ark::es2panda::lsp
