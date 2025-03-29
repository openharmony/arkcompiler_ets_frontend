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
#include "compiler/lowering/ets/topLevelStmts/topLevelStmts.h"

namespace ark::es2panda {

TEST_F(LoweringTest, TestTopLevelStmtsSyntheticModuleGlobalClass)
{
    char const *text = R"(
        function foo() { } // foo is a member of *module* class
    )";

    CONTEXT(ES2PANDA_STATE_LOWERED, text)
    {
        const auto *const ast = GetAst();
        auto *classDef = ast->FindChild(
            [](ir::AstNode *child) { return child->IsClassDefinition() && child->AsClassDefinition()->IsGlobal(); });
        ASSERT(classDef != nullptr);
        bool foundModuleAnnotation = false;
        for (auto *anno : classDef->AsClassDefinition()->Annotations()) {
            if (anno->Expr()->AsIdentifier()->Name() == "Module") {
                foundModuleAnnotation = true;
            }
        }
        ASSERT_TRUE(foundModuleAnnotation);
    }
}

TEST_F(LoweringTest, TestTopLevelStmtsSyntheticModuleClass)
{
    char const *text = R"(
        namespace X {
            export function bar() { } // bar is a member of another *module* class
        }
    )";

    CONTEXT(ES2PANDA_STATE_LOWERED, text)
    {
        const auto *const ast = GetAst();
        auto *classDef = ast->FindChild([](ir::AstNode *child) {
            return child->IsClassDefinition() &&
                   ((child->AsClassDefinition()->Modifiers() & ir::ClassDefinitionModifiers::CLASS_DECL) != 0U);
        });
        ASSERT(classDef != nullptr);
        bool foundModuleAnnotation = false;
        for (auto *anno : classDef->AsClassDefinition()->Annotations()) {
            if (anno->Expr()->AsIdentifier()->Name() == "Module") {
                foundModuleAnnotation = true;
            }
        }
        ASSERT_TRUE(foundModuleAnnotation);
    }
}

}  // namespace ark::es2panda
