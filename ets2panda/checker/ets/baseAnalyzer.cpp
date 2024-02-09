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

#include "baseAnalyzer.h"
#include "ir/astNode.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"

namespace ark::es2panda::checker {
void BaseAnalyzer::ClearPendingExits()
{
    pendingExits_.clear();
}

PendingExitsVector &BaseAnalyzer::PendingExits()
{
    return pendingExits_;
}

void BaseAnalyzer::SetPendingExits(const PendingExitsVector &pendingExits)
{
    pendingExits_ = pendingExits;
}

PendingExitsVector &BaseAnalyzer::OldPendingExits()
{
    return oldPendingExits_;
}

void BaseAnalyzer::SetOldPendingExits(const PendingExitsVector &oldPendingExits)
{
    oldPendingExits_ = oldPendingExits;
}

const ir::AstNode *BaseAnalyzer::GetJumpTarget(const ir::AstNode *node) const
{
    if (node->IsBreakStatement()) {
        return node->AsBreakStatement()->Target();
    }

    ASSERT(node->IsContinueStatement());
    return node->AsContinueStatement()->Target();
}

LivenessStatus BaseAnalyzer::ResolveJump(const ir::AstNode *node, ir::AstNodeType jumpKind)
{
    bool resolved = false;
    PendingExitsVector exits = pendingExits_;
    pendingExits_ = oldPendingExits_;

    for (auto &it : exits) {
        if (it.Node()->Type() == jumpKind && node == GetJumpTarget(it.Node())) {
            it.ResolveJump();
            resolved = true;
        } else {
            pendingExits_.push_back(it);
        }
    }

    return From(resolved);
}

LivenessStatus BaseAnalyzer::ResolveContinues(const ir::AstNode *node)
{
    oldPendingExits_.clear();
    return ResolveJump(node, ir::AstNodeType::CONTINUE_STATEMENT);
}

LivenessStatus BaseAnalyzer::ResolveBreaks(const ir::AstNode *node)
{
    return ResolveJump(node, ir::AstNodeType::BREAK_STATEMENT);
}

}  // namespace ark::es2panda::checker
