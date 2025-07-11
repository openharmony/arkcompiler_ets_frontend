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

#ifndef ES2PANDA_IR_JSDOC_ALLOWED_H
#define ES2PANDA_IR_JSDOC_ALLOWED_H

#include "ir/astNode.h"
#include "ir/statement.h"

namespace ark::es2panda::ir {

struct JsDocRecord {
    util::StringView name;     // NOLINT(misc-non-private-member-variables-in-classes)
    util::StringView param;    // NOLINT(misc-non-private-member-variables-in-classes)
    util::StringView comment;  // NOLINT(misc-non-private-member-variables-in-classes)

    JsDocRecord(util::StringView initName, util::StringView initParam, util::StringView initComment)
        : name(initName), param(initParam), comment(initComment)
    {
    }
};

using JsDocInfo = ArenaUnorderedMap<util::StringView, JsDocRecord>;

template <typename T>
class JsDocAllowed : public T {
public:
    JsDocAllowed() = delete;
    ~JsDocAllowed() override = default;

    NO_COPY_OPERATOR(JsDocAllowed);
    NO_MOVE_SEMANTIC(JsDocAllowed);

    [[nodiscard]] ArenaVector<JsDocInfo> &JsDocInformation() noexcept
    {
        return jsDocInformation_;
    }

    [[nodiscard]] const ArenaVector<JsDocInfo> &JsDocInformation() const noexcept
    {
        return jsDocInformation_;
    }

    void SetJsDocInformation(ArenaVector<JsDocInfo> &&jsDocInformation)
    {
        jsDocInformation_ = std::move(jsDocInformation);
    }

protected:
    explicit JsDocAllowed(Expression const &other, ArenaAllocator *allocator)
        : T(other, allocator), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(ArenaAllocator *const allocator, AstNodeType const type,
                          ArenaVector<AnnotationUsage *> &&annotations)
        : T(type, std::move(annotations)), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(AstNodeType const type, ModifierFlags const flags,
                          ArenaVector<AnnotationUsage *> &&annotations, ArenaVector<JsDocInfo> &&jsDocInformation)
        : T(type, flags, std::move(annotations)), jsDocInformation_(std::move(jsDocInformation))
    {
    }

    explicit JsDocAllowed(AstNodeType const type, ArenaAllocator *const allocator)
        : T(type, allocator), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(AstNodeType const type, ModifierFlags const flags, ArenaAllocator *const allocator)
        : T(type, flags, allocator), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(AstNodeType const type, Expression *const key, Expression *const value,
                          ModifierFlags const modifiers, ArenaAllocator *const allocator, bool const isComputed)
        : T(type, key, value, modifiers, allocator, isComputed), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(AstNodeType const type, TypeNode *typeAnnotation,
                          [[maybe_unused]] ArenaAllocator *const allocator)
        : T(type, typeAnnotation), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(ArenaAllocator *const allocator, AstNodeType const type)
        : T(type), jsDocInformation_(allocator->Adapter())
    {
    }

    explicit JsDocAllowed(ArenaAllocator *allocator, ArenaVector<Statement *> &&statements)
        : T(allocator, std::move(statements)), jsDocInformation_(allocator->Adapter())
    {
    }

    JsDocAllowed(const JsDocAllowed &other)
        : T(static_cast<const T &>(other)), jsDocInformation_(other.jsDocInformation_)
    {
    }

    JsDocAllowed(JsDocAllowed const &other, ArenaAllocator *const allocator)
        : T(static_cast<T const &>(other)), jsDocInformation_(allocator->Adapter())
    {
    }

    void CopyTo(AstNode *other) const override
    {
        auto otherImpl = static_cast<JsDocAllowed<T> *>(other);
        otherImpl->jsDocInformation_ = jsDocInformation_;
        T::CopyTo(other);
    }

private:
    friend class SizeOfNodeTest;
    ArenaVector<JsDocInfo> jsDocInformation_;
};
}  // namespace ark::es2panda::ir

#endif
