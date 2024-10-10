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

#include <gtest/gtest.h>

class ASTVerifierTest : public testing::Test {
public:
    ASTVerifierTest()
    {
        impl_ = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
        auto es2pandaPath = test::utils::PandaExecutablePathGetter {}.Get();
        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        char const *argv[] = {es2pandaPath.c_str()};
        cfg_ = impl_->CreateConfig(1, argv);
        allocator_ = new ark::ArenaAllocator(ark::SpaceType::SPACE_TYPE_COMPILER);
    }
    ~ASTVerifierTest() override
    {
        delete allocator_;
        impl_->DestroyConfig(cfg_);
    }

    ark::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

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

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    ark::ArenaAllocator *allocator_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

#endif  // TEST_UNIT_PUBLIC_AST_VERIFIER_TEST_H
