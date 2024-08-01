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
#include "checker/ETSchecker.h"

using ark::es2panda::compiler::ast_verifier::ASTVerifier;
using ark::es2panda::compiler::ast_verifier::InvariantNameSet;
using ark::es2panda::ir::AstNode;

constexpr char const *PRIVATE_PROTECTED_PUBLIC_TEST =
    R"(
        class Base {
            public a: int = 1;
            protected b: int = 2;
            private c: int = 3;
            public publicMethod() {
                this.a = 4;
                this.protectedMethod();
                this.privateMethod();
            }
            protected protectedMethod() {
                this.b = 5;
                this.publicMethod();
                this.privateMethod();
            }
            private privateMethod() {
                this.c = 6;
                this.publicMethod();
                this.protectedMethod();
            }
        }
        class Derived extends Base {
            foo () {
                this.a = 7;
                this.b = 8;
                this.publicMethod();
                this.protectedMethod();
            }
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
            base.publicMethod();
            let derived1: Derived = new Derived();
            let b = derived1.a;
            derived1.publicMethod();
            derived1.foo();
            let derived2: Base = new Derived();
            let c = derived2.a;
            derived2.publicMethod();
        }
    )";

TEST_F(ASTVerifierTest, PrivateProtectedPublicAccessTestCorrect)
{
    ASTVerifier verifier {Allocator()};

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, PRIVATE_PROTECTED_PUBLIC_TEST, "dummy.sts");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));
    InvariantNameSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto &messages = verifier.Verify(ast, checks);

    ASSERT_EQ(messages.size(), 0);
    impl_->DestroyContext(ctx);
}
