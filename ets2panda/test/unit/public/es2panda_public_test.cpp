/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "macros.h"
#include "public/es2panda_lib.h"
#include "test/utils/panda_executable_path_getter.h"
#include "test/utils/ast_verifier_test.h"

using Es2PandaLibTest = test::utils::AstVerifierTest;

TEST_F(Es2PandaLibTest, NoError)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function main() {}", "no-error.sts", ES2PANDA_STATE_ASM_GENERATED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_ASM_GENERATED);

    impl_->DestroyContext(ctx);
}

TEST_F(Es2PandaLibTest, TypeError)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, "function main() { let x: int = \"\" }",
                                                           "type-error.sts", ES2PANDA_STATE_ASM_GENERATED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_ERROR);

    ASSERT_EQ(std::string(impl_->ContextErrorMessage(ctx)),
              "TypeError: Type '\"\"' cannot be assigned to type 'int'[type-error.sts:1,32]");
    impl_->DestroyContext(ctx);
}

TEST_F(Es2PandaLibTest, ListIdentifiers)
{
    char const *text = R"XXX(
class C {
    n: string = "oh"
}

function main() {
    let c = new C
    console.log(c.n + 1) // type error, but not syntax error
}
)XXX";

    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, text, "list-ids.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    struct Arg {
        es2panda_Impl const *impl = nullptr;
        es2panda_Context *ctx = nullptr;
        std::vector<std::string> ids;
    } arg;
    arg.impl = impl_;
    arg.ctx = ctx;

    auto func = [](es2panda_AstNode *ast, void *argp) {
        auto *a = reinterpret_cast<Arg *>(argp);
        if (a->impl->IsIdentifier(ast)) {
            a->ids.emplace_back(a->impl->IdentifierName(a->ctx, ast));
        }
    };

    impl_->AstNodeForEach(impl_->ProgramAst(ctx, impl_->ContextProgram(ctx)), func, &arg);

    std::vector<std::string> expected {"C", "n", "string",  "constructor", "constructor", "main",
                                       "c", "C", "console", "log",         "c",           "n"};
    ASSERT_EQ(arg.ids, expected);

    impl_->DestroyContext(ctx);
}
