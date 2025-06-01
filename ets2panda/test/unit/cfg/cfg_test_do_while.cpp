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

TEST_F(CFGTest, do_while_statement_01)
{
    char const *text = R"(
      function main() {
        let i: number = 0;
        do {
          i++;
        } while (i < 10);
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
        ASSERT_EQ(bb1->GetPredecessors().size(), EXPECTED_ZERO);
        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb3->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_ONE);

        ASSERT_EQ(bb4->GetSuccessors().size(), EXPECTED_ZERO);
        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Predecessors[0], bb3);
    }
}

TEST_F(CFGTest, do_while_statement_with_break)
{
    char const *text = R"(
      function main() {
        let i: number = 1;
        do {
          if (i % 2 == 0) {
            break;
          }
          i++;
        } while (i < 10);
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
        ASSERT_EQ(bb1->GetPredecessors().size(), EXPECTED_ZERO);

        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_TWO);

        ASSERT_EQ(bb3->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_ONE);

        ASSERT_EQ(bb4->GetSuccessors().size(), EXPECTED_ZERO);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb4Predecessors[0], bb3);
        ASSERT_EQ(bb4Predecessors[1], bb2);

        ASSERT_EQ(bb7->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb7->GetPredecessors().size(), EXPECTED_TWO);  // NOTE: Should be 1, needs to be fixed
    }
}

TEST_F(CFGTest, do_while_statement_with_continue)
{
    char const *text = R"(
      function main() {
        let i: number = 1;
        do {
          i++;
          if (i % 2 == 0) {
            continue;
          }
          let b = i * 3;
        } while (i < 10);
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
        ASSERT_EQ(bb1->GetPredecessors().size(), EXPECTED_ZERO);

        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_TWO);

        ASSERT_EQ(bb3->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_TWO);

        ASSERT_EQ(bb4->GetSuccessors().size(), EXPECTED_ZERO);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb4Predecessors[0], bb3);

        auto bb7Successors = bb7->GetSuccessors();
        ASSERT_EQ(bb7Successors.size(), EXPECTED_ONE);
        ASSERT_EQ(bb7Successors[0], bb3);
        auto bb7Predecessors = bb7->GetPredecessors();
        ASSERT_EQ(bb7Predecessors.size(), EXPECTED_TWO);  // NOTE: Should be 1, needs to be fixed
    }
}

}  // namespace ark::es2panda::compiler
