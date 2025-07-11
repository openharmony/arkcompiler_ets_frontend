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

#include <gtest/gtest.h>

#include "lsp_api_test.h"
#include "lsp/include/internal_api.h"
#include "lsp/include/todo_comments.h"

namespace {
// NOLINTBEGIN
using ark::es2panda::lsp::Initializer;

class TodoCommentsTest : public LSPAPITests {};

TEST_F(TodoCommentsTest, GetTodoCommentsSimpleTodo)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "simple-todo.sts";
    const char *const kFileContent = "// TODO: Fix this";
    const char *const kExpectedMessage = "TODO: Fix this";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsSimpleTodoWithName)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "simple-todo-name.sts";
    const char *const kFileContent = "// TODO(name): Fix this";
    const char *const kExpectedMessage = "TODO(name): Fix this";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsSimpleHack)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kHackTag = "HACK";
    const char *const kFileName = "simple-hack.sts";
    const char *const kFileContent = "// HACK: Needs work";
    const char *const kExpectedMessage = "HACK: Needs work";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kHackTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kHackTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsBlockCommentTodo)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "block-comment.sts";
    const char *const kFileContent = "/* TODO: Fix this */";
    const char *const kExpectedMessage = "TODO: Fix this ";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsMultiLineBlockComment)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "multiline-block-comment.sts";
    const char *const kFileContent = "/*\n * TODO: Multi-line fix\n */";
    const char *const kExpectedMessage = "TODO: Multi-line fix";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsIgnoresNonComments)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "non-comment.sts";
    const char *const kFileContent = "let s = \"TODO: not a comment\"";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;

    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_TRUE(comments.empty());

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsMultiLineCodeMultiComments)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 2;
    const char *const kTodoTag = "TODO";
    const char *const kHackTag = "HACK";
    const char *const kFileName = "multiline-multicomment.sts";
    const char *const kFileContent =
        R"(export function A(a:number): number {return a;}
 // TODO: this is a todo comment
 
 // HACK: fix me
 export function B(a:number, b:number): number {return a + b;})";
    const char *const kExpectedTodoMessage = "TODO: this is a todo comment";
    const char *const kExpectedHackMessage = "HACK: fix me";
    const int kExpectedTodoPosition = 52;
    const int kExpectedHackPosition = 87;

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;

    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority),
        ark::es2panda::lsp::TodoCommentDescriptor(kHackTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedTodoMessage);
    EXPECT_EQ(comments[0].GetPosition(), kExpectedTodoPosition);
    EXPECT_EQ(comments[1].GetCommentDescriptor().GetText(), kHackTag);
    EXPECT_EQ(comments[1].GetMessage(), kExpectedHackMessage);
    EXPECT_EQ(comments[1].GetPosition(), kExpectedHackPosition);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsMultiLineCodeSameComments)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 2;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "multiline-duplicate.sts";
    const char *const kFileContent =
        R"(export function A(a:number): number {return a;}
 // TODO: this is a duplicate todo comment
 
 // TODO: this is a duplicate todo comment
 export function B(a:number, b:number): number {return a + b;})";
    const char *const kExpectedMessage = "TODO: this is a duplicate todo comment";
    const int kExpectedFirstPosition = 52;
    const int kExpectedSecondPosition = 97;

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;

    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[1].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);
    EXPECT_EQ(comments[1].GetMessage(), kExpectedMessage);
    EXPECT_EQ(comments[0].GetPosition(), kExpectedFirstPosition);
    EXPECT_EQ(comments[1].GetPosition(), kExpectedSecondPosition);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsNotTodoComment)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const char *const kTodoTag = "TODO";
    const char *const kFileName = "non-comment.sts";
    const char *const kFileContent = "// TODOX not a todo comment";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;

    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_TRUE(comments.empty());

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsBlockCommentFixMe)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kTodoTag = "FIXME";
    const char *const kFileName = "block-comment-fixme.sts";
    const char *const kFileContent = "/* FIXME: Fix this */";
    const char *const kExpectedMessage = "FIXME: Fix this ";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsSimpleFix)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 1;
    const char *const kHackTag = "FIX";
    const char *const kFileName = "simple-comment-fix.sts";
    const char *const kFileContent = "// FIX: Needs to be fixed";
    const char *const kExpectedMessage = "FIX: Needs to be fixed";

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kHackTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kHackTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);

    initializer.DestroyContext(ctx);
}

TEST_F(TodoCommentsTest, GetTodoCommentsNoteMultiLineCodeSameComments)
{
    const time_t kDesignatedThrottleTime = 123;
    const int kDescriptorPriority = 1;
    const int kExpectedSize = 2;
    const char *const kTodoTag = "NOTE";
    const char *const kFileName = "multiline-duplicate-note.sts";
    const char *const kFileContent =
        R"(export function A(b:number): number {return c;}
 // NOTE: this is a duplicate note comment

 // Comment line
 
 // NOTE: this is a duplicate note comment
 export function B(a:number, b:number): number {return a + b;})";
    const char *const kExpectedMessage = "NOTE: this is a duplicate note comment";
    const int kExpectedFirstPosition = 52;
    const int kExpectedSecondPosition = 115;

    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;

    auto cancellationToken = ark::es2panda::lsp::CancellationToken(kDesignatedThrottleTime, nullptr);

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(kFileName, ES2PANDA_STATE_CHECKED, kFileContent);

    std::vector<ark::es2panda::lsp::TodoCommentDescriptor> descriptors = {
        ark::es2panda::lsp::TodoCommentDescriptor(kTodoTag, kDescriptorPriority)};

    auto comments = ark::es2panda::lsp::GetTodoCommentsImpl(ctx, descriptors, &cancellationToken);

    ASSERT_EQ(comments.size(), kExpectedSize);
    EXPECT_EQ(comments[0].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[1].GetCommentDescriptor().GetText(), kTodoTag);
    EXPECT_EQ(comments[0].GetMessage(), kExpectedMessage);
    EXPECT_EQ(comments[1].GetMessage(), kExpectedMessage);
    EXPECT_EQ(comments[0].GetPosition(), kExpectedFirstPosition);
    EXPECT_EQ(comments[1].GetPosition(), kExpectedSecondPosition);

    initializer.DestroyContext(ctx);
}
// NOLINTEND
}  // namespace