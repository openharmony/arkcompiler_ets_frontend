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

#ifndef ES2PANDA_IR_ANNOTATION_ALLOWED_H
#define ES2PANDA_IR_ANNOTATION_ALLOWED_H

#include "ir/astNode.h"
#include "ir/statement.h"
#include "ir/statements/annotationUsage.h"

namespace ark::es2panda::ir {

template <typename T>
class AnnotationAllowed : public T {
public:
    AnnotationAllowed() = delete;
    ~AnnotationAllowed() override = default;

    NO_COPY_OPERATOR(AnnotationAllowed);
    NO_MOVE_SEMANTIC(AnnotationAllowed);

    [[nodiscard]] ArenaVector<ir::AnnotationUsage *> &Annotations() noexcept
    {
        return annotations_;
    }

    [[nodiscard]] const ArenaVector<ir::AnnotationUsage *> &Annotations() const noexcept
    {
        return annotations_;
    }

    void SetAnnotations(ArenaVector<ir::AnnotationUsage *> &&annotations)
    {
        annotations_ = std::move(annotations);
        for (ir::AnnotationUsage *anno : annotations_) {
            anno->SetParent(this);
        }
    }

protected:
    explicit AnnotationAllowed(Expression const &other, ArenaAllocator *allocator)
        : T(other), annotations_(allocator->Adapter())
    {
    }
    explicit AnnotationAllowed(AstNodeType const type, ArenaVector<AnnotationUsage *> &&annotations)
        : T(type), annotations_(std::move(annotations))
    {
    }
    explicit AnnotationAllowed(AstNodeType const type, ModifierFlags const flags,
                               ArenaVector<AnnotationUsage *> &&annotations)
        : T(type, flags), annotations_(std::move(annotations))
    {
    }
    explicit AnnotationAllowed(AstNodeType const type, ArenaAllocator *const allocator)
        : T(type), annotations_(allocator->Adapter())
    {
    }
    explicit AnnotationAllowed(AstNodeType const type, ModifierFlags const flags, ArenaAllocator *const allocator)
        : T(type, flags), annotations_(allocator->Adapter())
    {
    }
    explicit AnnotationAllowed(AstNodeType const type, Expression *const key, Expression *const value,
                               ModifierFlags const modifiers, ArenaAllocator *const allocator, bool const isComputed)
        : T(type, key, value, modifiers, allocator, isComputed), annotations_(allocator->Adapter())
    {
    }

    explicit AnnotationAllowed(ArenaAllocator *const allocator, ArenaVector<Statement *> &&statementList)
        : T(allocator, std::move(statementList)), annotations_(allocator->Adapter())
    {
    }

    void AddAnnotations(AnnotationUsage *const annotations)
    {
        annotations_.emplace_back(annotations);
    }

    AnnotationAllowed(AnnotationAllowed const &other)
        : T(static_cast<T const &>(other)), annotations_(other.annotations_.get_allocator())
    {
    }

private:
    ArenaVector<AnnotationUsage *> annotations_;
};
}  // namespace ark::es2panda::ir

#endif
