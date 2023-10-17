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

#ifndef ES2PANDA_BINDER_JS_BINDER_H
#define ES2PANDA_BINDER_JS_BINDER_H

#include "binder/binder.h"

namespace panda::es2panda::binder {
class JSBinder : public Binder {
public:
    explicit JSBinder(ArenaAllocator *allocator) : Binder(allocator) {}

    NO_COPY_SEMANTIC(JSBinder);
    NO_MOVE_SEMANTIC(JSBinder);
    ~JSBinder() = default;

private:
};
}  // namespace panda::es2panda::binder

#endif
