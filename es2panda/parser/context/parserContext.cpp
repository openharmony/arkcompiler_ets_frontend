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

#include "parserContext.h"

namespace panda::es2panda::parser {
const ParserContext *ParserContext::FindLabel(const util::StringView &label) const
{
    const auto *iter = this;
    do {
        if (iter->label_.Empty()) {
            return nullptr;
        }

        if (iter->label_ == label) {
            return iter;
        }

        iter = iter->prev_;
    } while (iter);

    return nullptr;
}
}  // namespace panda::es2panda::parser
