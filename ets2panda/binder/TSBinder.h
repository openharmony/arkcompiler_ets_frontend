/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_BINDER_TS_BINDER_H
#define ES2PANDA_BINDER_TS_BINDER_H

#include "binder/TypedBinder.h"

namespace panda::es2panda::binder {
class TSBinder : public TypedBinder {
public:
    explicit TSBinder(ArenaAllocator *allocator) : TypedBinder(allocator) {}

    NO_COPY_SEMANTIC(TSBinder);
    NO_MOVE_SEMANTIC(TSBinder);
    ~TSBinder() = default;

    ScriptExtension Extension() const override
    {
        return ScriptExtension::TS;
    }

    ResolveBindingOptions BindingOptions() const override
    {
        return ResolveBindingOptions::ALL;
    }

protected:
};
}  // namespace panda::es2panda::binder

#endif
