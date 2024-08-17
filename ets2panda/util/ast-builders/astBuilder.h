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

#ifndef ES2PANDA_UTIL_INCLUDE_AST_BUILDER
#define ES2PANDA_UTIL_INCLUDE_AST_BUILDER

#include "mem/arena_allocator.h"
#include "util/helpers.h"

namespace ark::es2panda::ir {

class AstBuilder {
public:
    explicit AstBuilder(ark::ArenaAllocator *allocator) : allocator_(allocator) {}

    ark::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

    template <typename T, typename... Args>
    T *AllocNode(Args &&...args)
    {
        return util::NodeAllocator::ForceSetParent<T>(allocator_, std::forward<Args>(args)...);
    }

private:
    ark::ArenaAllocator *allocator_;
};

}  // namespace ark::es2panda::ir
#endif  // ES2PANDA_UTIL_INCLUDE_AST_BUILDER