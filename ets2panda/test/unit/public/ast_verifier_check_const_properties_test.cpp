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
#include "ir/base/classProperty.h"
#include <gtest/gtest.h>
#include "checker/ETSchecker.h"

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

namespace {

TEST_F(ASTVerifierTest, CheckConstProperties)
{
    ark::es2panda::checker::ETSChecker checker;
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Test
        {
            readonly value = "readonly";
        }

        function main(): void {
            const test = new Test();
            console.log(test.value);
        }
    )";

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_LOWERED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_LOWERED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->IterateRecursively([](ark::es2panda::ir::AstNode *node) {
        if (node->IsClassProperty()) {
            auto property = node->AsClassProperty();
            if (property->IsReadonly()) {
                property->AddModifier(ark::es2panda::ir::ModifierFlags::CONST);
            }
        }
    });

    InvariantNameSet checks;
    checks.insert("CheckConstPropertiesForAll");
    const auto &messages = verifier.Verify(ast, checks);

    ASSERT_EQ(messages.size(), 1);
    auto invariant = messages[0].Invariant();
    auto cause = messages[0].Cause();
    ASSERT_EQ(invariant, "CheckConstPropertiesForAll");
    ASSERT_EQ(cause, "Class property cannot be const");

    impl_->DestroyContext(ctx);
}

}  // namespace