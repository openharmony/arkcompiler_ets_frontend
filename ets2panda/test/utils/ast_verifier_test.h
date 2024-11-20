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

#ifndef ES2PANDA_TEST_UTILS_AST_VERIFIER_TEST_H
#define ES2PANDA_TEST_UTILS_AST_VERIFIER_TEST_H

#include "ast_verifier/ASTVerifier.h"
#include "panda_executable_path_getter.h"

#include <gtest/gtest.h>

namespace ir_alias = ark::es2panda::ir;
namespace verifier_alias = ark::es2panda::compiler::ast_verifier;

namespace test::utils {

class AstVerifierTest : public testing::Test {
public:
    AstVerifierTest();

    ~AstVerifierTest() override;

    ark::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

    es2panda_Context *CreateContextAndProceedToState(const es2panda_Impl *impl, es2panda_Config *config,
                                                     char const *source, char const *fileName,
                                                     es2panda_ContextState state);

    verifier_alias::Messages VerifyCheck(verifier_alias::ASTVerifier &verifier, const ir_alias::AstNode *ast,
                                         const std::string &check, verifier_alias::InvariantNameSet &checks);

    verifier_alias::Messages VerifyCheck(verifier_alias::ASTVerifier &verifier, const ir_alias::AstNode *ast,
                                         const std::string &check);

    template <typename Ast>
    Ast *GetAstFromContext(const es2panda_Impl *impl, es2panda_Context *ctx)
    {
        auto ast = reinterpret_cast<Ast *>(impl->ProgramAst(impl->ContextProgram(ctx)));
        return ast;
    }
    NO_COPY_SEMANTIC(AstVerifierTest);
    NO_MOVE_SEMANTIC(AstVerifierTest);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    ark::ArenaAllocator *allocator_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

}  // namespace test::utils

#endif  // ES2PANDA_TEST_UTILS_AST_VERIFIER_TEST_H
