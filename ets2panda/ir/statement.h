/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_IR_STATEMENT_H
#define ES2PANDA_IR_STATEMENT_H

#include "ir/astNode.h"

namespace ark::es2panda::ir {
class ClassElement;

class Statement : public AstNode {
public:
    Statement() = delete;
    ~Statement() override = default;

    NO_COPY_OPERATOR(Statement);
    NO_MOVE_SEMANTIC(Statement);

    [[nodiscard]] bool IsStatement() const noexcept override
    {
        return true;
    }

    virtual void SetReturnType([[maybe_unused]] checker::ETSChecker *checker, [[maybe_unused]] checker::Type *type) {}

protected:
    explicit Statement(AstNodeType type) : AstNode(type) {}
    explicit Statement(AstNodeType type, ModifierFlags flags) : AstNode(type, flags) {}
    Statement(Statement const &other) : AstNode(static_cast<AstNode const &>(other)) {}
};

}  // namespace ark::es2panda::ir

#endif
