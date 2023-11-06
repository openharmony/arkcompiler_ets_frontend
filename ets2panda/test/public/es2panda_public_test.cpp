/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "macros.h"
#include "public/es2panda_lib.h"

class Es2PandaLibTest : public testing::Test {
public:
    Es2PandaLibTest()
    {
        impl_ = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        char const *argv[] = {"test"};
        cfg_ = impl_->CreateConfig(1, argv);
    }

    ~Es2PandaLibTest() override
    {
        impl_->DestroyConfig(cfg_);
    }

    NO_COPY_SEMANTIC(Es2PandaLibTest);
    NO_MOVE_SEMANTIC(Es2PandaLibTest);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

TEST_F(Es2PandaLibTest, NoError)
{
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, "function main() {}", "no-error.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_ASM_GENERATED);  // don't produce any object files
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_ASM_GENERATED);
    impl_->DestroyContext(ctx);
}

TEST_F(Es2PandaLibTest, TypeError)
{
    es2panda_Context *ctx =
        impl_->CreateContextFromString(cfg_, "function main() { let x: int = \"\" }", "no-error.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_ASM_GENERATED);  // don't produce any object files
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_ERROR);
    ASSERT_EQ(std::string(impl_->ContextErrorMessage(ctx)),
              "TypeError: Initializers type is not assignable to the target type[no-error.ets:1,32]");
    impl_->DestroyContext(ctx);
}
