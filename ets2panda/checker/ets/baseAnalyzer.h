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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_BASE_ANALYZER_H
#define ES2PANDA_COMPILER_CHECKER_ETS_BASE_ANALYZER_H

#include "utils/arena_containers.h"
#include "plugins/ecmascript/es2panda/util/enumbitops.h"

namespace panda::es2panda::ir {
class AstNode;
enum class AstNodeType;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class ETSChecker;

enum class LivenessStatus { DEAD, ALIVE };

DEFINE_BITOPS(LivenessStatus)

class PendingExit {
public:
    using JumpResolver = std::function<void()>;

    explicit PendingExit(
        const ir::AstNode *node, JumpResolver jump_resolver = [] {})
        : node_(node), jump_resolver_(std::move(jump_resolver))
    {
    }
    ~PendingExit() = default;

    DEFAULT_COPY_SEMANTIC(PendingExit);
    DEFAULT_NOEXCEPT_MOVE_SEMANTIC(PendingExit);

    void ResolveJump() const
    {
        jump_resolver_();
    }

    const ir::AstNode *Node() const
    {
        return node_;
    }

private:
    const ir::AstNode *node_;
    JumpResolver jump_resolver_;
};

using PendingExitsVector = std::vector<PendingExit>;

class BaseAnalyzer {
public:
    explicit BaseAnalyzer() = default;

    virtual void MarkDead() = 0;

    void RecordExit(const PendingExit &pe)
    {
        pending_exits_.push_back(pe);
        MarkDead();
    }

    LivenessStatus From(bool value)
    {
        return value ? LivenessStatus::ALIVE : LivenessStatus::DEAD;
    }

    LivenessStatus ResolveJump(const ir::AstNode *node, ir::AstNodeType jump_kind);
    LivenessStatus ResolveContinues(const ir::AstNode *node);
    LivenessStatus ResolveBreaks(const ir::AstNode *node);
    const ir::AstNode *GetJumpTarget(const ir::AstNode *node) const;

protected:
    void ClearPendingExits();
    PendingExitsVector &PendingExits();
    void SetPendingExits(const PendingExitsVector &pending_exits);
    PendingExitsVector &OldPendingExits();
    void SetOldPendingExits(const PendingExitsVector &old_pending_exits);

private:
    PendingExitsVector pending_exits_;
    PendingExitsVector old_pending_exits_;
};
}  // namespace panda::es2panda::checker
#endif
