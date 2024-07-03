/*
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

#ifndef ES2PANDA_EVALUATE_SCOPED_DEBUG_INFO_PLUGIN_INL_H
#define ES2PANDA_EVALUATE_SCOPED_DEBUG_INFO_PLUGIN_INL_H

#include "evaluate/scopedDebugInfoPlugin.h"

namespace ark::es2panda::evaluate {

template <bool IS_PROLOGUE>
void ScopedDebugInfoPlugin::RegisterPrologueEpilogue(ir::BlockStatement *block, ir::Statement *stmt)
{
    ASSERT(block);
    ASSERT(stmt);

    auto iter = prologueEpilogueMap_.find(block);
    if (iter == prologueEpilogueMap_.end()) {
        ArenaVector<ir::Statement *> vec(1, stmt, Allocator()->Adapter());
        if constexpr (IS_PROLOGUE) {
            prologueEpilogueMap_.emplace(block,
                                         std::make_pair(vec, ArenaVector<ir::Statement *>(Allocator()->Adapter())));
        } else {
            prologueEpilogueMap_.emplace(block,
                                         std::make_pair(ArenaVector<ir::Statement *>(Allocator()->Adapter()), vec));
        }
    } else {
        if constexpr (IS_PROLOGUE) {
            iter->second.first.push_back(stmt);
        } else {
            iter->second.second.push_back(stmt);
        }
    }
}

}  // namespace ark::es2panda::evaluate

#endif  // ES2PANDA_EVALUATE_SCOPED_DEBUG_INFO_PLUGIN_INL_H
