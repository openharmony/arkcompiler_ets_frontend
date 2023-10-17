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

#include "baseAnalyzer.h"
#include "ir/astNode.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"

namespace panda::es2panda::checker {
void BaseAnalyzer::ClearPendingExits()
{
    pending_exits_.clear();
}

PendingExitsVector &BaseAnalyzer::PendingExits()
{
    return pending_exits_;
}

void BaseAnalyzer::SetPendingExits(const PendingExitsVector &pending_exits)
{
    pending_exits_ = pending_exits;
}

PendingExitsVector &BaseAnalyzer::OldPendingExits()
{
    return old_pending_exits_;
}

void BaseAnalyzer::SetOldPendingExits(const PendingExitsVector &old_pending_exits)
{
    old_pending_exits_ = old_pending_exits;
}

const ir::AstNode *BaseAnalyzer::GetJumpTarget(const ir::AstNode *node) const
{
    if (node->IsBreakStatement()) {
        return node->AsBreakStatement()->Target();
    }

    ASSERT(node->IsContinueStatement());
    return node->AsContinueStatement()->Target();
}

LivenessStatus BaseAnalyzer::ResolveJump(const ir::AstNode *node, ir::AstNodeType jump_kind)
{
    bool resolved = false;
    PendingExitsVector exits = pending_exits_;
    pending_exits_ = old_pending_exits_;

    for (auto &it : exits) {
        if (it.Node()->Type() == jump_kind && node == GetJumpTarget(it.Node())) {
            it.ResolveJump();
            resolved = true;
        } else {
            pending_exits_.push_back(it);
        }
    }

    return From(resolved);
}

LivenessStatus BaseAnalyzer::ResolveContinues(const ir::AstNode *node)
{
    old_pending_exits_.clear();
    return ResolveJump(node, ir::AstNodeType::CONTINUE_STATEMENT);
}

LivenessStatus BaseAnalyzer::ResolveBreaks(const ir::AstNode *node)
{
    return ResolveJump(node, ir::AstNodeType::BREAK_STATEMENT);
}

}  // namespace panda::es2panda::checker
