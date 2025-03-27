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

TEST_F(CFGTest, switch_statement_01)
{
    char const *text = R"(
      function getDayName(day: int): string {
        let dayName: string;

        switch (day) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            dayName = "Weekday";
            break;
            case 6:
            dayName = "Weekend";
            break;
            case 7:
            dayName = "Weekend";
            break;
            default:
            dayName = "Invalid day!";
        }

        return dayName;
      }

      let str: string = getDayName(1);
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_FIFTEEN);

        auto bb2 = GetBBByID(basicBlocks, ID_02);
        ASSERT_NE(bb2, nullptr);

        ASSERT_EQ(bb2->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb2->GetPredecessors().size(), 0);

        auto bb13 = GetBBByID(basicBlocks, ID_13);
        ASSERT_NE(bb13, nullptr);

        ASSERT_EQ(bb13->GetSuccessors().size(), EXPECTED_ONE);
        ASSERT_EQ(bb13->GetPredecessors().size(), EXPECTED_FIVE);
    }
}

}  // namespace ark::es2panda::compiler
