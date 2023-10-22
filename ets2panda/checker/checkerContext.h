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
#include "binder/variable.h"
#include "util/enumbitops.h"

#include <vector>

namespace panda::es2panda::checker {

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

using CapturedVarsMap = ArenaUnorderedMap<binder::Variable *, lexer::SourcePosition>;

class CheckerContext {
public:
    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus new_status)
        : CheckerContext(allocator, new_status, nullptr)
    {
    }

    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus new_status, ETSObjectType *containing_class)
        : CheckerContext(allocator, new_status, containing_class, nullptr)
    {
    }

    explicit CheckerContext(ArenaAllocator *allocator, CheckerStatus new_status, ETSObjectType *containing_class,
                            Signature *containing_signature)
        : status_(new_status),
          captured_vars_(allocator->Adapter()),
          containing_class_(containing_class),
          containing_signature_(containing_signature)
    {
    }

    const CapturedVarsMap &CapturedVars() const
    {
        return captured_vars_;
    }

    CapturedVarsMap &CapturedVars()
    {
        return captured_vars_;
    }

    const CheckerStatus &Status() const
    {
        return status_;
    }

    ETSObjectType *ContainingClass() const
    {
        return containing_class_;
    }

    Signature *ContainingSignature() const
    {
        return containing_signature_;
    }

    CheckerStatus &Status()
    {
        return status_;
    }

    void SetContainingSignature(Signature *containing_signature)
    {
        containing_signature_ = containing_signature;
    }

    void SetContainingClass(ETSObjectType *containing_class)
    {
        containing_class_ = containing_class;
    }

    void AddCapturedVar(binder::Variable *var, const lexer::SourcePosition &pos)
    {
        captured_vars_.emplace(var, pos);
    }

    DEFAULT_COPY_SEMANTIC(CheckerContext);
    DEFAULT_MOVE_SEMANTIC(CheckerContext);
    ~CheckerContext() = default;

private:
    CheckerStatus status_;
    CapturedVarsMap captured_vars_;
    ETSObjectType *containing_class_ {nullptr};
    Signature *containing_signature_ {nullptr};
};
}  // namespace panda::es2panda::checker

#endif
