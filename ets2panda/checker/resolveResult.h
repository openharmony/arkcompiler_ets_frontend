/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_RESOLVE_RESULT_H
#define ES2PANDA_CHECKER_RESOLVE_RESULT_H

namespace ark::es2panda::checker {
enum class OverrideErrorCode {
    NO_ERROR,
    OVERRIDDEN_FINAL,
    INCOMPATIBLE_RETURN,
    OVERRIDDEN_WEAKER,
};

enum class ResolvedKind {
    PROPERTY,
    INSTANCE_EXTENSION_FUNCTION,
};

class ResolveResult {
public:
    explicit ResolveResult(varbinder::Variable *v, ResolvedKind kind) : variable_(v), kind_(kind) {}

    varbinder::Variable *Variable()
    {
        return variable_;
    }

    ResolvedKind Kind()
    {
        return kind_;
    }

private:
    varbinder::Variable *variable_ {};
    ResolvedKind kind_ {};
};

}  // namespace ark::es2panda::checker

#endif /* ES2PANDA_CHECKER_RESOLVE_RESULT_H */
