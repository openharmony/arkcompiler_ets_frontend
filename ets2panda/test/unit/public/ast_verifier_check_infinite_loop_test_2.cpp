/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ast_verifier_test.h"
#include "ir/astNode.h"
#include "public/es2panda_lib.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

namespace {
struct TestData {
    char const *program;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class InfiniteLoopTests : public ASTVerifierTest, public testing::WithParamInterface<TestData> {};

// clang-format off
INSTANTIATE_TEST_SUITE_P(,
    InfiniteLoopTests,
    testing::Values(
        TestData {
            R"(
                function main () {
                    do {
                    } while (2 > 1)
                }
            )",
        },
        TestData {
            R"(
                function main () {
                    for (;;) {}
                }
            )",
        },
        TestData {
            R"(
                function main () {
                    for (; 2 > 1;) {}
                }
            )",
        }));
// clang-format on

TEST_P(InfiniteLoopTests, InfiniteLoop)
{
    ASTVerifier verifier {Allocator()};
    TestData data = GetParam();

    char const *text = data.program;

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    InvariantNameSet checks;
    checks.insert("CheckInfiniteLoopForAll");
    const auto &messages = verifier.Verify(ast, checks);

    // Expecting warning
    ASSERT_EQ(messages.size(), 1);
    ASSERT_EQ(messages[0].Cause(), "INFINITE LOOP");

    impl_->DestroyContext(ctx);
}
}  // namespace
