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

#include "cancellation_token.h"

namespace ark::es2panda::lsp {
bool CancellationToken::ThrottledCancellationCheck()
{
    if (this->host_ == nullptr) {
        return false;
    }

    time_t time = std::time(nullptr);
    time_t duration = time - this->lastCancellationTime_;
    if (duration >= this->throttleTime_) {
        this->lastCancellationTime_ = time;
        return this->host_->IsCancellationRequested();
    }
    return false;
}
bool CancellationToken::IsCancellationRequested()
{
    if (this->host_ == nullptr) {
        return false;
    }

    this->lastCancellationTime_ = std::time(nullptr);
    return this->host_->IsCancellationRequested();
}

CancellationToken::CancellationToken(time_t designatedThrottleTime, HostCancellationToken *hostCancellationToken)
{
    this->lastCancellationTime_ = 0;
    this->throttleTime_ = designatedThrottleTime;
    this->host_ = hostCancellationToken;
}
}  // namespace ark::es2panda::lsp
