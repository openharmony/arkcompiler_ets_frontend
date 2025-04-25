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

#ifndef TODO_COMMENTS_H
#define TODO_COMMENTS_H

#include <cstddef>
#include <string>
#include <utility>
#include <vector>
#include "cancellation_token.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {
struct TodoCommentDescriptor {
private:
    std::string text_;
    int priority_;

public:
    TodoCommentDescriptor(std::string text, int priority) : text_(std::move(text)), priority_(priority) {}

    std::string GetText() const
    {
        return text_;
    }

    int GetPriority() const
    {
        return priority_;
    }
};

struct TodoComment {
private:
    TodoCommentDescriptor commentDescriptor_;
    std::string message_;
    size_t position_;

public:
    TodoComment(TodoCommentDescriptor descriptor, std::string message, size_t position)
        : commentDescriptor_(std::move(descriptor)), message_(std::move(message)), position_(position)
    {
    }

    TodoCommentDescriptor GetCommentDescriptor() const
    {
        return commentDescriptor_;
    }

    std::string GetMessage() const
    {
        return message_;
    }

    int GetPosition() const
    {
        return position_;
    }
};

struct TodoMatchContext {
    es2panda_Context *context;
    const std::vector<ark::es2panda::lsp::TodoCommentDescriptor> &descriptors;
    size_t lineStart;
    const std::string *line;
    std::string_view fileContents;
    std::vector<ark::es2panda::lsp::TodoComment> &result;
};

std::vector<ark::es2panda::lsp::TodoComment> GetTodoCommentsImpl(
    es2panda_Context *context, std::vector<ark::es2panda::lsp::TodoCommentDescriptor> &descriptors,
    CancellationToken *cancellationToken);

}  // namespace ark::es2panda::lsp

#endif