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
#include "refactors/convert_function.h"
#include "refactor_provider.h"
#include "compiler/lowering/util.h"
#include "internal_api.h"

namespace ark::es2panda::lsp {

ConvertFunctionRefactor::ConvertFunctionRefactor()
{
    AddKind(std::string(TO_ANONYMOUS_FUNCTION_ACTION.kind));
    AddKind(std::string(TO_NAMED_FUNCTION_ACTION.kind));
    AddKind(std::string(TO_ARROW_FUNCTION_ACTION.kind));
}

ApplicableRefactorInfo ConvertFunctionRefactor::GetAvailableActions(const RefactorContext &refContext) const
{
    es2panda_Context *context = refContext.context;
    size_t position = refContext.span.pos;

    ApplicableRefactorInfo res;

    if (!IsKind(refContext.kind)) {
        return res;
    }

    auto node = GetTouchingToken(context, position, false);
    if (node == nullptr || !node->IsIdentifier()) {
        return res;
    }

    auto nodeDecl = compiler::DeclarationFromIdentifier(node->AsIdentifier());
    if (nodeDecl != nullptr && nodeDecl->IsClassProperty() && nodeDecl->AsClassProperty()->Value() != nullptr &&
        nodeDecl->AsClassProperty()->Value()->IsArrowFunctionExpression()) {
        res.name = refactor_name::CONVERT_FUNCTION_REFACTOR_NAME;
        res.description = refactor_description::CONVERT_FUNCTION_REFACTOR_DESC;
        res.action.kind = std::string(TO_NAMED_FUNCTION_ACTION.kind);
        res.action.name = std::string(TO_NAMED_FUNCTION_ACTION.name);
        res.action.description = std::string(TO_NAMED_FUNCTION_ACTION.description);
    }

    return res;
}

std::unique_ptr<RefactorEditInfo> ConvertFunctionRefactor::GetEditsForAction(const RefactorContext &context,
                                                                             const std::string &actionName) const
{
    (void)context;
    (void)actionName;
    return std::make_unique<RefactorEditInfo>();
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoRefactorRegister<ConvertFunctionRefactor> g_convertFunctionRefactorRegister("ConvertFunctionRefactor");

}  // namespace ark::es2panda::lsp
