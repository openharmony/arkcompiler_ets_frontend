/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <algorithm>
#include "macros.h"

#include "test/unit/node_creator.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "varbinder/tsBinding.h"
#include "varbinder/ETSBinder.h"

namespace panda::es2panda {

class ScopesInitPhaseTest : public testing::Test {
public:
    ~ScopesInitPhaseTest() override = default;

    ScopesInitPhaseTest()
        : allocator_(std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER)), node_gen_(allocator_.get())
    {
    }

    static void SetUpTestCase()
    {
        constexpr auto COMPILER_SIZE = operator""_MB(256ULL);
        mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize();
    }

    ArenaAllocator *Allocator()
    {
        return allocator_.get();
    }

    gtests::NodeGenerator &NodeGen()
    {
        return node_gen_;
    }

    /*
     * Shortcut to convert single elemnt block expression body to it's name
     * Example: { let x; } => x
     */
    static ir::Identifier *BodyToFirstName(ir::Statement *body)
    {
        return body->AsBlockStatement()
            ->Statements()
            .front()
            ->AsVariableDeclaration()
            ->Declarators()
            .front()
            ->Id()
            ->AsIdentifier();
    }

    NO_COPY_SEMANTIC(ScopesInitPhaseTest);
    NO_MOVE_SEMANTIC(ScopesInitPhaseTest);

private:
    std::unique_ptr<ArenaAllocator> allocator_;
    gtests::NodeGenerator node_gen_;
};

TEST_F(ScopesInitPhaseTest, TestForUpdateLoop)
{
    /*
     * for (int x = 0; x < 10; x++ ) { let x; }
     */
    auto varbinder = varbinder::VarBinder(Allocator());
    auto for_node = NodeGen().CreateForUpdate();
    compiler::ScopesInitPhaseETS::RunExternalNode(for_node, &varbinder);

    auto block_scope = for_node->Body()->AsBlockStatement()->Scope();
    auto loop_scope = for_node->Scope();
    auto par_scope = loop_scope->Parent();
    ASSERT_EQ(block_scope->Parent(), loop_scope);

    const auto &scope_bindings = block_scope->Bindings();
    const auto &par_bindings = par_scope->Bindings();

    ASSERT_EQ(scope_bindings.size(), 1);
    ASSERT_EQ(par_bindings.size(), 1);

    auto par_name = for_node->Init()->AsVariableDeclaration()->Declarators()[0]->Id()->AsIdentifier();
    auto name = BodyToFirstName(for_node->Body());
    ASSERT_EQ(scope_bindings.begin()->first, name->Name());
    ASSERT_EQ(par_bindings.begin()->first, par_name->Name());
    ASSERT_EQ(scope_bindings.begin()->second, name->Variable());
    ASSERT_EQ(par_bindings.begin()->second, par_name->Variable());
    ASSERT_NE(par_name->Variable(), name->Variable());
}

TEST_F(ScopesInitPhaseTest, CreateWhile)
{
    /*
     * while (x < 10) { let x; }
     */
    auto varbinder = varbinder::VarBinder(Allocator());
    auto while_node = NodeGen().CreateWhile();

    compiler::ScopesInitPhaseETS::RunExternalNode(while_node, &varbinder);

    auto while_scope = while_node->Scope();
    auto body_scope = while_node->Body()->AsBlockStatement()->Scope();
    ASSERT_EQ(body_scope->Parent(), while_scope);

    const auto &body_bindings = body_scope->Bindings();
    auto name = BodyToFirstName(while_node->Body());
    ASSERT_EQ(body_bindings.size(), 1);
    ASSERT_EQ(body_bindings.begin()->first, name->Name());
    ASSERT_EQ(body_bindings.begin()->second, name->Variable());
}

}  // namespace panda::es2panda