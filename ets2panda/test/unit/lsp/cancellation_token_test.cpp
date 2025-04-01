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

#include "lsp/include/cancellation_token.h"
#include <gtest/gtest.h>
#include "lsp_api_test.h"

const int DEFAULT_THROTTLE = 20;
const int NO_THROTTLE = 0;

class LspCancellationTokenTests : public LSPAPITests {};

TEST_F(LspCancellationTokenTests, CancellationTokenHostNull)
{
    ark::es2panda::lsp::CancellationToken cancellationToken(DEFAULT_THROTTLE, nullptr);
    ASSERT_EQ(false, cancellationToken.IsCancellationRequested());
}

TEST_F(LspCancellationTokenTests, CancellationTokenHostNotNull)
{
    class LanguageHost : public ark::es2panda::lsp::HostCancellationToken {
    public:
        bool IsCancellationRequested() override
        {
            return true;
        }
    };

    LanguageHost host;
    ark::es2panda::lsp::CancellationToken cancellationToken(DEFAULT_THROTTLE, &host);

    ASSERT_EQ(true, cancellationToken.IsCancellationRequested());
}

TEST_F(LspCancellationTokenTests, CancellationTokenThrottledCancellationCheck)
{
    class LanguageHost : public ark::es2panda::lsp::HostCancellationToken {
    public:
        bool IsCancellationRequested() override
        {
            return true;
        }
    };

    LanguageHost host;
    ark::es2panda::lsp::CancellationToken cancellationToken(DEFAULT_THROTTLE, &host);

    ASSERT_EQ(true, cancellationToken.IsCancellationRequested());
    ASSERT_EQ(false, cancellationToken.ThrottledCancellationCheck());
}

TEST_F(LspCancellationTokenTests, CancellationTokenThrottledCancellationCheck2)
{
    class LanguageHost : public ark::es2panda::lsp::HostCancellationToken {
    public:
        bool IsCancellationRequested() override
        {
            return true;
        }
    };

    LanguageHost host;
    ark::es2panda::lsp::CancellationToken cancellationToken(NO_THROTTLE, &host);

    ASSERT_EQ(true, cancellationToken.IsCancellationRequested());
    ASSERT_EQ(true, cancellationToken.ThrottledCancellationCheck());
}
