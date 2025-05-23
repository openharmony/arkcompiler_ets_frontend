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

#include "lowering_test.h"

namespace ark::es2panda {

TEST_F(LoweringTest, TestConvertPrimitiveCastMethodCall)
{
    char const *text = R"(
        let d: double = 3.14
        let b: byte = d.toByte()
        let s: short = d.toShort()
        let i: int = d.toInt()
        let l: long = d.toLong()
        let f: float= d.toFloat()
    )";

    static std::array<std::string_view, 7U> castMethods {{
        "toChar",
        "toByte",
        "toShort",
        "toInt",
        "toLong",
        "toFloat",
        "toDouble",
    }};

    CONTEXT(ES2PANDA_STATE_LOWERED, text)
    {
        const auto *const ast = GetAst();
        ASSERT_FALSE(ast->IsAnyChild([](ir::AstNode *const node) {
            if (!node->IsCallExpression()) {
                return false;
            }
            auto call = node->AsCallExpression();
            if (!call->Callee()->IsMemberExpression()) {
                return false;
            }
            auto me = node->AsCallExpression()->Callee()->AsMemberExpression();
            auto prop = me->Property();
            if (!prop->IsIdentifier()) {
                return false;
            }
            auto m = prop->AsIdentifier()->Name().Utf8();
            return std::find(castMethods.begin(), castMethods.end(), m) != castMethods.end();
        }));
    }
}

}  // namespace ark::es2panda
