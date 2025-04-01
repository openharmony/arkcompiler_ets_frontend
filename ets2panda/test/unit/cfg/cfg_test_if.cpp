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

TEST_F(CFGTest, if_statement_01)
{
    // Test if the empty BB will be omitted from the final CFG
    char const *text = R"(
      function main() {
        let cond = true;
        if (cond == true) { }
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();

        ASSERT_TRUE(cfg != nullptr);
        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_TWO);
    }
}

TEST_F(CFGTest, if_statement_02)
{
    char const *text = R"(
      function main() {
        let cond = true;
        if (cond == true) { let i = 1; }
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();

        ASSERT_TRUE(cfg != nullptr);
        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_THREE);

        auto bb1 = GetBBByID(basicBlocks, ID_01);
        ASSERT_NE(bb1, nullptr);
        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_TWO);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);
        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb1, bb2->GetPredecessors().at(0));

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_NE(bb3, nullptr);
        auto bb3Predecessors = bb3->GetPredecessors();
        ASSERT_EQ(bb3Predecessors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb3Predecessors[0], bb2);
        ASSERT_EQ(bb3Predecessors[1], bb1);
    }
}

TEST_F(CFGTest, if_statement_03)
{
    char const *text = R"(
      function main() {
        let i: number = 1;
        if (i < 1) {
          i++;
        } else {
          i--;
        }
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

        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_TWO);
        ASSERT_EQ(bb1->GetPredecessors().size(), 0);
        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb3->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb3->GetPredecessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb4->GetSuccessors().size(), 0);
        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb4Predecessors[0], bb2);
        ASSERT_EQ(bb4Predecessors[1], bb3);
    }
}

TEST_F(CFGTest, if_statement_04)
{
    char const *text = R"(
        function main() {
          let cond = true;
          if (cond == true) {
            let i = 1;
          } else {
          }
        }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_THREE);

        auto bb1 = GetBBByID(basicBlocks, ID_01);
        ASSERT_NE(bb1, nullptr);
        ASSERT_EQ(bb1->GetSuccessors().size(), EXPECTED_TWO);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);
        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb2->GetPredecessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb1, bb2->GetPredecessors().at(0));

        auto bb3 = GetBBByID(basicBlocks, ID_03);
        ASSERT_EQ(bb3, nullptr);

        auto bb4 = GetBBByID(basicBlocks, ID_04);
        ASSERT_NE(bb4, nullptr);

        auto bb4Predecessors = bb4->GetPredecessors();
        ASSERT_EQ(bb4Predecessors.size(), EXPECTED_TWO);
        ASSERT_EQ(bb4Predecessors[0], bb2);
        ASSERT_EQ(bb4Predecessors[1], bb1);
    }
}

TEST_F(CFGTest, if_statement_with_emptystatement)
{
    // Test if the empty BB will be omitted from the final CFG
    char const *text = R"(
      function main() {
        ;
        let cond = true;
        if (cond == true) {
          ;
        }
        ;
      }
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_TWO);
    }
}

}  // namespace ark::es2panda::compiler
