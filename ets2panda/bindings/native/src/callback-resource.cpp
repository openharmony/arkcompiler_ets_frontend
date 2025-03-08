/*
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

#include "common-interop.h"
#include "callback-resource.h"
#include <deque>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>

// NOLINTBEGIN

static bool needReleaseFront = false;
static std::deque<CallbackEventKind> callbackEventsQueue;
static std::deque<CallbackBuffer> callbackCallSubqueue;
static std::deque<InteropInt32> callbackResourceSubqueue;

void EnqueueCallback(const CallbackBuffer *event)
{
    callbackEventsQueue.push_back(EVENT_CALL_CALLBACK);
    callbackCallSubqueue.push_back(*event);
}

void HoldManagedCallbackResource(InteropInt32 resourceId)
{
    callbackEventsQueue.push_back(EVENT_HOLD_MANAGED_RESOURCE);
    callbackResourceSubqueue.push_back(resourceId);
}

void ReleaseManagedCallbackResource(InteropInt32 resourceId)
{
    callbackEventsQueue.push_back(EVENT_RELEASE_MANAGED_RESOURCE);
    callbackResourceSubqueue.push_back(resourceId);
}

KInt impl_CheckCallbackEvent(KByte *result, [[maybe_unused]] KInt size)
{
    if (needReleaseFront) {
        switch (callbackEventsQueue.front()) {
            case EVENT_CALL_CALLBACK:
                callbackCallSubqueue.front().resourceHolder.release();
                callbackCallSubqueue.pop_front();
                break;
            case EVENT_HOLD_MANAGED_RESOURCE:
            case EVENT_RELEASE_MANAGED_RESOURCE:
                callbackResourceSubqueue.pop_front();
                break;
            default:
                throw std::runtime_error("Unknown event kind");
        }
        callbackEventsQueue.pop_front();
        needReleaseFront = false;
    }
    if (callbackEventsQueue.empty()) {
        return 0;
    }
    const CallbackEventKind frontEventKind = callbackEventsQueue.front();
    std::copy_n(&frontEventKind, 4U, result);
    switch (frontEventKind) {
        case EVENT_CALL_CALLBACK:
            std::copy_n(callbackCallSubqueue.front().buffer, sizeof(CallbackBuffer::buffer), result + 4U);
            break;
        case EVENT_HOLD_MANAGED_RESOURCE:
        case EVENT_RELEASE_MANAGED_RESOURCE: {
            const InteropInt32 resourceId = callbackResourceSubqueue.front();
            std::copy_n(&resourceId, 4U, result + 4U);
            break;
        }
        default:
            throw std::runtime_error("Unknown event kind");
    }
    needReleaseFront = true;
    return 1;
}
TS_INTEROP_2(CheckCallbackEvent, KInt, KByte *, KInt)

void impl_ReleaseCallbackResource(InteropInt32 resourceId)
{
    ReleaseManagedCallbackResource(resourceId);
}
TS_INTEROP_V1(ReleaseCallbackResource, KInt)

void impl_HoldCallbackResource(InteropInt32 resourceId)
{
    HoldManagedCallbackResource(resourceId);
}
TS_INTEROP_V1(HoldCallbackResource, KInt)

// NOLINTEND
