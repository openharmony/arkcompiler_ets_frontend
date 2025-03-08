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

#ifndef INTEROP_CALLBACK_RESOURCE_H
#define INTEROP_CALLBACK_RESOURCE_H

#include <vector>
#include "interop-types.h"

// NOLINTBEGIN

class CallbackResourceHolder {
private:
    std::vector<InteropCallbackResource> heldResources;

public:
    void holdCallbackResource(const InteropCallbackResource *resource)
    {
        resource->hold(resource->resourceId);
        this->heldResources.push_back(*resource);
    }
    void release()
    {
        for (auto resource : this->heldResources) {
            resource.release(resource.resourceId);
        }
        this->heldResources.clear();
    }
};

struct CallbackBuffer {
    InteropInt32 kind;
    uint8_t buffer[60 * 4];
    CallbackResourceHolder resourceHolder;
};

enum CallbackEventKind {
    EVENT_CALL_CALLBACK = 0,
    EVENT_HOLD_MANAGED_RESOURCE = 1,
    EVENT_RELEASE_MANAGED_RESOURCE = 2,
};

// CC-OFFNXT(G.NAM.01) false positive
void EnqueueCallback(const CallbackBuffer *event);
// CC-OFFNXT(G.NAM.01) false positive
void HoldManagedCallbackResource(InteropInt32 resourceId);
// CC-OFFNXT(G.NAM.01) false positive
void ReleaseManagedCallbackResource(InteropInt32 resourceId);

// NOLINTEND

#endif
