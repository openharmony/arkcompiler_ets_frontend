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

#include "astNode.h"

namespace panda::es2panda::ir {

template <typename R, typename T>
static R GetTopStatementImpl(T *self)
{
    auto iter = self;

    while (iter->Parent()) {
        iter = iter->Parent();
    }

    return reinterpret_cast<R>(iter);
}

ir::BlockStatement *AstNode::GetTopStatement()
{
    return GetTopStatementImpl<ir::BlockStatement *>(this);
}

const ir::BlockStatement *AstNode::GetTopStatement() const
{
    return GetTopStatementImpl<const ir::BlockStatement *>(this);
}

void AstNode::TransformChildrenRecursively(const NodeTransformer &cb)
{
    TransformChildren([=](AstNode *child) {
        child->TransformChildrenRecursively(cb);
        return cb(child);
    });
}

void AstNode::IterateRecursively(const NodeTraverser &cb) const
{
    Iterate([=](AstNode *child) {
        cb(child);
        child->IterateRecursively(cb);
    });
}

void AnyChildHelper(bool *found, const NodePredicate &cb, AstNode *ast)
{
    if (*found) {
        return;
    }

    if (cb(ast)) {
        *found = true;
        return;
    }

    ast->Iterate([=](AstNode *child) { AnyChildHelper(found, cb, child); });
}

bool AstNode::IsAnyChild(const NodePredicate &cb) const
{
    bool found = false;
    Iterate([&found, cb](AstNode *child) { AnyChildHelper(&found, cb, child); });
    return found;
}

}  // namespace panda::es2panda::ir
