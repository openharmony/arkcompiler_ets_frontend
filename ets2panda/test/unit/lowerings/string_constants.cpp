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

#include "lowering_test.h"
#include "compiler/lowering/ets/stringConstantsLowering.h"

namespace ark::es2panda {

TEST_F(LoweringTest, TestStringConstansConcat)
{
    char const *text = R"(
        function main() {
            let v = "a" + ("bb" + "1") + (("ccc" + "123") + "dddd");
        }
    )";
    char const *expect = "abb1ccc123dddd";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        const auto *const ast = GetAst();

        ASSERT_FALSE(ast->IsAnyChild([](ir::AstNode *const node) { return node->IsBinaryExpression(); }));
        ASSERT_TRUE(ast->IsAnyChild([expect](ir::AstNode *const node) {
            return node->IsStringLiteral() && node->AsStringLiteral()->Str().Is(expect);
        }));
    }
}

}  // namespace ark::es2panda
