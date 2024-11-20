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

TEST_F(CFGTest, for_of_statement_01)
{
    char const *text = R"(
      let str: string = "";
      for (let c of "asdfgh") {
        str += c;
      }
      str;
    )";

    CONTEXT(ES2PANDA_STATE_CHECKED, text)
    {
        CFG *cfg = GetCfg();
        ASSERT_TRUE(cfg != nullptr);

        const ArenaSet<compiler::CFG::BasicBlock *> basicBlocks = cfg->GetBasicBlocks();
        ASSERT_EQ(basicBlocks.size(), EXPECTED_FOUR);
    }
}

}  // namespace ark::es2panda::compiler
