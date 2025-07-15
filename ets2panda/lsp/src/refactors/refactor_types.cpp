
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

#include "refactors/refactor_types.h"

namespace ark::es2panda::lsp {

Refactor::Refactor(const Refactor &other)
{
    kinds_.insert(kinds_.end(), other.kinds_.begin(), other.kinds_.end());
}

Refactor &Refactor::operator=(const Refactor &other)
{
    kinds_.insert(kinds_.end(), other.kinds_.begin(), other.kinds_.end());
    return *this;
}

Refactor &Refactor::operator=(Refactor &&other)
{
    kinds_.insert(kinds_.end(), other.kinds_.begin(), other.kinds_.end());
    return *this;
}

Refactor::Refactor(Refactor &&other)
{
    kinds_.insert(kinds_.end(), other.kinds_.begin(), other.kinds_.end());
}

bool Refactor::IsKind(const std::string &kind) const
{
    for (const std::string &rKind : kinds_) {
        if (rKind.substr(0, kind.length()) == kind) {
            return true;
        }
    }
    return false;
}

void Refactor::AddKind(const std::string &kind)
{
    kinds_.push_back(kind);
}

}  // namespace ark::es2panda::lsp