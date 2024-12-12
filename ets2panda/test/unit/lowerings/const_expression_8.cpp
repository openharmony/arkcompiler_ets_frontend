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

#include "lowering_test.h"
#include "compiler/lowering/ets/constantExpressionLowering.h"

namespace ark::es2panda {

TEST_F(LoweringTest, TestConstantExpressionConcatNumeric)
{
    char const *text = R"(
        @interface MyAnno {
            a : long
        }
        @MyAnno({a = ((((1 + -1 + 10) * 123 / 5) ^ (~10.2) << 1) >> 2.6 >>> 33 & 141 | 12) % 53})
        function main() {}
    )";

    int64_t const expectA = 35;
    ir::AstNode *const ast = SetupContext(text, ES2PANDA_STATE_CHECKED)->Ast();

    ASSERT_FALSE(ast->IsAnyChild([](ir::AstNode *const node) {
        return node->IsBinaryExpression() || node->IsUnaryExpression() || node->IsConditionalExpression();
    }));

    ASSERT_TRUE(ast->IsAnyChild([](ir::AstNode *const node) {
        return node->IsNumberLiteral() && node->AsNumberLiteral()->Number().GetLong() == expectA;
    }));
}

}  // namespace ark::es2panda