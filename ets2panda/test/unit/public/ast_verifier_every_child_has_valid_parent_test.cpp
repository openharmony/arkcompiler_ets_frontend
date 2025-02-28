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
#include "checker/ETSchecker.h"
#include "ir/expressions/identifier.h"
#include "ir/astNode.h"
#include "parser/ETSparser.h"

#include <gtest/gtest.h>

using ark::es2panda::compiler::ast_verifier::EveryChildHasValidParent;

namespace {
TEST_F(ASTVerifierTest, ReturnTypeInLambda)
{
    char const *text = R"(
        function main(): void {
            let x: () => void = ()=> {}
        }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        EXPECT_TRUE(Verify<EveryChildHasValidParent>());
    }
}

TEST_F(ASTVerifierTest, TSThisType)
{
    char const *text = R"(
        class A {
            foo(a?: Number): this { return this; }
        }

        function main () {}
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        EXPECT_TRUE(Verify<EveryChildHasValidParent>());
    }
}

TEST_F(ASTVerifierTest, TupleFieldInInterface)
{
    char const *text = R"(
        interface I {
            field: [String, String]
        }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        EXPECT_TRUE(Verify<EveryChildHasValidParent>());
    }
}

}  // namespace
