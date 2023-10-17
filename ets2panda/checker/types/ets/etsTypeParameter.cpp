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

#include "etsTypeParameter.h"

namespace panda::es2panda::checker {
void ETSTypeParameter::ToString([[maybe_unused]] std::stringstream &ss) const
{
    UNREACHABLE();
}

void ETSTypeParameter::Identical([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *other)
{
    UNREACHABLE();
}

void ETSTypeParameter::AssignmentTarget([[maybe_unused]] TypeRelation *relation, [[maybe_unused]] Type *source)
{
    UNREACHABLE();
}
}  // namespace panda::es2panda::checker
