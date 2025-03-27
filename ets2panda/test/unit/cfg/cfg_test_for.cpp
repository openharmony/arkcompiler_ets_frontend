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

#include "cfg_test.h"

namespace ark::es2panda::compiler {

TEST_F(CFGTest, for_statement_01)
{
    char const *text = R"(
      function main() {
        for (let i = 0; i < 1; i++) {
          let b = i;
        }
        let a: number = 42;
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_FOUR);

        auto bb1 = GetBBByID(basicBlocks, ID_01);
        ASSERT_NE(bb1, nullptr);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_NE(bb3, nullptr);

        auto bb4 = GetBBByID(basicBlocks, ID_04);
        ASSERT_NE(bb4, nullptr);

        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb1->GetPredecessors().size(), 0);
        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb3->GetSuccessors().size(), 0);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_ONE);

        auto bb4Successors = bb4->GetSuccessors();
        ASSERT_EQ(bb4Successors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Successors[0], bb2);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Predecessors[0], bb2);
    }
}

TEST_F(CFGTest, for_statement_with_break)
{
    char const *text = R"(
      function main() {
        for (let i = 0; i < 1; i++) {
          let b = i;
          if (i == 0)
            break;
          b++;
        }
        let a: number = 42;
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_FIVE);

        auto bb1 = GetBBByID(basicBlocks, ID_01);
        ASSERT_NE(bb1, nullptr);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_NE(bb3, nullptr);

        auto bb4 = GetBBByID(basicBlocks, ID_04);
        ASSERT_NE(bb4, nullptr);

        auto bb7 = GetBBByID(basicBlocks, ID_07);
        ASSERT_NE(bb7, nullptr);

        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb1->GetPredecessors().size(), 0);

        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_TWO);

        ASSERT_EQ(bb3->GetSuccessors().size(), 0);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_TWO);

        ASSERT_EQ(bb4->GetSuccessors().size(), EXPECTED_TWO);
        auto bb4Successors = bb4->GetSuccessors();
        ASSERT_EQ(bb4Successors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb4Successors[0], bb3);
        ASSERT_EQ(bb4Successors[1], bb7);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Predecessors[0], bb2);

        ASSERT_EQ(bb7->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb7->GetPredecessors().size(), EXPECTED_TWO);  // NOTE: Should be 1, needs to be fixed
    }
}

TEST_F(CFGTest, for_statement_with_continue)
{
    char const *text = R"(
      function main() {
        for (let i = 0; i < 1; i++) {
          let b = i;
          if (i == 0)
            continue;
          b++;
        }
        let a: number = 42;
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_FIVE);

        auto bb1 = GetBBByID(basicBlocks, ID_01);
        ASSERT_NE(bb1, nullptr);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_NE(bb3, nullptr);

        auto bb4 = GetBBByID(basicBlocks, ID_04);
        ASSERT_NE(bb4, nullptr);

        auto bb7 = GetBBByID(basicBlocks, ID_07);
        ASSERT_NE(bb7, nullptr);

        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb1->GetPredecessors().size(), 0);

        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_THREE);

        ASSERT_EQ(bb3->GetSuccessors().size(), 0);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_ONE);

        auto bb4Successors = bb4->GetSuccessors();
        ASSERT_EQ(bb4Successors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb4Successors[0], bb2);
        ASSERT_EQ(bb4Successors[1], bb7);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Predecessors[0], bb2);

        ASSERT_EQ(bb7->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb7->GetPredecessors().size(), EXPECTED_TWO);  // NOTE: Should be 1, needs to be fixed
    }
}

TEST_F(CFGTest, for_statement_infinite_loop)
{
    char const *text = R"(
    function main () {
      for (;;) {}
    }
  )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_ONE);

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_NE(bb3, nullptr);
        ASSERT_EQ(bb3->GetSuccessors()[0], bb3);
    }
}

}  // namespace ark::es2panda::compiler
