/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

using ark::es2panda::compiler::ast_verifier::CheckInfiniteLoop;

namespace {
struct TestData {
    char const *program;
};

// NOLINTNEXTLINE(fuchsia-multiple-inheritance)
class NormalLoopTests : public ASTVerifierTest, public testing::WithParamInterface<TestData> {};

// clang-format off
INSTANTIATE_TEST_SUITE_P(,
    NormalLoopTests,
    testing::Values(
        TestData {
            R"(
                function main() {
                    let counter = 0;
                    while (counter < 10) {
                        counter = counter + 1;
                    }
                }
            )",
        },
        TestData {
            R"(
                function main() {
                    let counter = 0;
                    do {
                        counter = counter + 1
                    } while (counter < 10)
                }
            )",
        },
        TestData {
            R"(
                function main() {
                    for (let i = 0; i < 10; ++i) {}
                }
            )",
        }));
// clang-format on

TEST_P(NormalLoopTests, NormalLoop)
{
    TestData data = GetParam();
    char const *text = data.program;

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        EXPECT_TRUE(Verify<CheckInfiniteLoop>());
    }
}
}  // namespace
