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

#ifndef ES2PANDA_CHECKER_CHECKER_CONTEXT_H
#define ES2PANDA_CHECKER_CHECKER_CONTEXT_H

#include <macros.h>
#include "varbinder/variable.h"
#include "util/enumbitops.h"

#include <vector>

namespace ark::es2panda::checker {

class ETSObjectType;
class Signature;

enum class CheckerStatus : uint32_t {
    NO_OPTS = 0U,
    FORCE_TUPLE = 1U << 0U,
    IN_CONST_CONTEXT = 1U << 1U,
    KEEP_LITERAL_TYPE = 1U << 2U,
    IN_PARAMETER = 1U << 3U,
    IN_CLASS = 1U << 4U,
    IN_INTERFACE = 1U << 5U,
    IN_ABSTRACT = 1U << 6U,
    IN_STATIC_CONTEXT = 1U << 7U,
    IN_CONSTRUCTOR = 1U << 8U,
    IN_STATIC_BLOCK = 1U << 9U,
    INNER_CLASS = 1U << 10U,
    IN_ENUM = 1U << 11U,
    BUILTINS_INITIALIZED = 1U << 12U,
    IN_LAMBDA = 1U << 13U,
    IGNORE_VISIBILITY = 1U << 14U,
    IN_INSTANCE_EXTENSION_METHOD = 1U << 15U,
};

DEFINE_BITOPS(CheckerStatus)

using CapturedVarsMap = ArenaUnorderedMap<varbinder::Variable *, lexer::SourcePosition>;

class CheckerContext {
public:
    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus newStatus)
        : CheckerContext(allocator, newStatus, nullptr)
    {
    }

    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus newStatus, ETSObjectType *containingClass)
        : CheckerContext(allocator, newStatus, containingClass, nullptr)
    {
    }

    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus newStatus, ETSObjectType *containingClass,
                            Signature *containingSignature)
        : status_(newStatus),
          capturedVars_(allocator->Adapter()),
          containingClass_(containingClass),
          containingSignature_(containingSignature)
    {
    }

    const CapturedVarsMap &CapturedVars() const
    {
        return capturedVars_;
    }

    CapturedVarsMap &CapturedVars()
    {
        return capturedVars_;
    }

    const CheckerStatus &Status() const
    {
        return status_;
    }

    ETSObjectType *ContainingClass() const
    {
        return containingClass_;
    }

    Signature *ContainingSignature() const
    {
        return containingSignature_;
    }

    CheckerStatus &Status()
    {
        return status_;
    }

    void SetContainingSignature(Signature *containingSignature)
    {
        containingSignature_ = containingSignature;
    }

    void SetContainingClass(ETSObjectType *containingClass)
    {
        containingClass_ = containingClass;
    }

    void AddCapturedVar(varbinder::Variable *var, const lexer::SourcePosition &pos)
    {
        capturedVars_.emplace(var, pos);
    }

    DEFAULT_COPY_SEMANTIC(CheckerContext);
    DEFAULT_MOVE_SEMANTIC(CheckerContext);
    ~CheckerContext() = default;

private:
    CheckerStatus status_;
    CapturedVarsMap capturedVars_;
    ETSObjectType *containingClass_ {nullptr};
    Signature *containingSignature_ {nullptr};
};
}  // namespace ark::es2panda::checker

#endif
