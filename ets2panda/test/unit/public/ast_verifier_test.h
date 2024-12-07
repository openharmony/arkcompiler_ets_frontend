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

#ifndef TEST_UNIT_PUBLIC_AST_VERIFIER_TEST_H
#define TEST_UNIT_PUBLIC_AST_VERIFIER_TEST_H

#include "ast_verifier/ASTVerifier.h"
#include "test/utils/panda_executable_path_getter.h"
#include "test/utils/ast_verifier_test.h"

#include <gtest/gtest.h>

class ASTVerifierTest : public test::utils::AstVerifierTest {
public:
    ASTVerifierTest() = default;
    ~ASTVerifierTest() override = default;

    NO_COPY_SEMANTIC(ASTVerifierTest);
    NO_MOVE_SEMANTIC(ASTVerifierTest);

protected:
    template <typename Type>
    Type *Tree(Type *node)
    {
        return node;
    }

    template <typename Type, typename... Args>
    Type *Node(Args &&...args)
    {
        return allocator_->New<Type>(std::forward<Args>(args)...);
    }

    template <typename Type, typename... Args>
    ark::ArenaVector<Type *> Nodes(Args &&...args)
    {
        auto v = ark::ArenaVector<Type *> {allocator_->Adapter()};
        v.insert(v.end(), {std::forward<Args>(args)...});
        return v;
    }
};

#endif  // TEST_UNIT_PUBLIC_AST_VERIFIER_TEST_H
