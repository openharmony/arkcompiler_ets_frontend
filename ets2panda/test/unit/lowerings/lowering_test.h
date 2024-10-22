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

#ifndef ES2PANDA_TEST_LOWERINGS_LOWERING_TEST_H
#define ES2PANDA_TEST_LOWERINGS_LOWERING_TEST_H

#include <gtest/gtest.h>
#include "test/unit/node_creator.h"
#include "test/utils/panda_executable_path_getter.h"
#include "parser/program/program.h"

namespace ark::es2panda {

class LoweringTest : public testing::Test {
public:
    LoweringTest()
    {
        impl_ = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
        auto es2pandaPath = test::utils::PandaExecutablePathGetter {}.Get();
        std::array argv = {es2pandaPath.c_str()};
        cfg_ = impl_->CreateConfig(argv.size(), argv.data());
        allocator_ = new ark::ArenaAllocator(ark::SpaceType::SPACE_TYPE_COMPILER);
    }

    ~LoweringTest() override
    {
        if (ctx_ != nullptr) {
            impl_->DestroyContext(ctx_);
        }
        delete allocator_;
        impl_->DestroyConfig(cfg_);
    }

    ark::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

    parser::Program *SetupContext(const char *text, es2panda_ContextState state)
    {
        ASSERT(ctx_ == nullptr);
        ctx_ = impl_->CreateContextFromString(cfg_, text, "dummy.sts");
        impl_->ProceedToState(ctx_, state);
        ASSERT(impl_->ContextState(ctx_) == state);

        return reinterpret_cast<parser::Program *>(impl_->ContextProgram(ctx_));
    }

    NO_COPY_SEMANTIC(LoweringTest);
    NO_MOVE_SEMANTIC(LoweringTest);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_ {};
    es2panda_Config *cfg_ {};
    ark::ArenaAllocator *allocator_ {};

    es2panda_Context *ctx_ {};
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

}  // namespace ark::es2panda

#endif  // ES2PANDA_TEST_LOWERINGS_LOWERING_TEST_H
