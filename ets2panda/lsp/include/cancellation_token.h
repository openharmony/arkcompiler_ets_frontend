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

#ifndef ES2PANDA_LSP_CANCELLATION_TOKEN_H
#define ES2PANDA_LSP_CANCELLATION_TOKEN_H

#include <ctime>
namespace ark::es2panda::lsp {
// This class needs to be implemented by the server, we need a way to know
// if the $/cancelRequest notification has been sent over by the client.
// the CancellationToken Class only there to give API's to ability to
// check if they should stop or not.
class HostCancellationToken {
public:
    virtual bool IsCancellationRequested() = 0;
};

class CancellationToken {
public:
    bool IsCancellationRequested();
    bool ThrottledCancellationCheck();
    CancellationToken(time_t designatedThrottleTime, HostCancellationToken *hostCancellationToken);
    CancellationToken() : lastCancellationTime_(0), throttleTime_(0), host_(nullptr) {}

private:
    time_t lastCancellationTime_;
    time_t throttleTime_;
    HostCancellationToken *host_;
};
}  // namespace ark::es2panda::lsp

#endif
