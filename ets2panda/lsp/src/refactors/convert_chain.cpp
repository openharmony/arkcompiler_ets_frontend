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
#include "refactors/convert_chain.h"
#include "refactor_provider.h"
#include "internal_api.h"

namespace ark::es2panda::lsp {

ark::es2panda::ir::AstNode *FindType(ark::es2panda::ir::AstNode *node);

ConvertChainRefactor::ConvertChainRefactor()
{
    AddKind(std::string(TO_NAMED_CHAIN_ACTION.kind));
}

ark::es2panda::ir::AstNode *FindType(ark::es2panda::ir::AstNode *node)
{
    if ((node != nullptr) && (node->Parent() != nullptr)) {
        if (node->Parent()->IsExpression()) {
            return node;
        }
        auto cb = [](ir::AstNode *ancestorNode) { return ancestorNode->IsConditionalExpression(); };
        node = FindAncestor(node, cb);
        return node;
    }
    return node;
}

ApplicableRefactorInfo ConvertChainRefactor::GetAvailableActions(const RefactorContext &refContext) const
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

    auto nodedec1 = FindType(node);
    if (nodedec1 != nullptr && (nodedec1->IsConditionalExpression() || nodedec1->IsExpression())) {
        res.name = refactor_name::CONVERT_CHAIN_REFACTOR_NAME;
        res.description = refactor_description::CONVERT_CHAIN_REFACTOR_DESC;
        res.action.kind = std::string(TO_NAMED_CHAIN_ACTION.kind);
        res.action.name = std::string(TO_NAMED_CHAIN_ACTION.name);
        res.action.description = std::string(TO_NAMED_CHAIN_ACTION.description);
    }
    return res;
}

std::unique_ptr<RefactorEditInfo> ConvertChainRefactor::GetEditsForAction(const RefactorContext &context,
                                                                          const std::string &actionName) const
{
    (void)context;
    (void)actionName;
    return std::make_unique<RefactorEditInfo>();
}
// NOLINTNEXTLINE(fuchsia-statically-constructed-objects, cert-err58-cpp)
AutoRefactorRegister<ConvertChainRefactor> g_convertChainRefactorRegister("ConvertChainRefactor");

}  // namespace ark::es2panda::lsp