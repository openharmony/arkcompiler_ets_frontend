/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_UTIL_ERROR_RECOVERY_H
#define ES2PANDA_UTIL_ERROR_RECOVERY_H

#include "lexer/lexer.h"

namespace ark::es2panda::util {

class ErrorRecursionGuard {
public:
    explicit ErrorRecursionGuard(lexer::Lexer *lexer);
    NO_COPY_SEMANTIC(ErrorRecursionGuard);
    NO_MOVE_SEMANTIC(ErrorRecursionGuard);

    ~ErrorRecursionGuard();

private:
    lexer::Lexer *lexer_;
    lexer::LexerPosition savedPos_;
};

}  // namespace ark::es2panda::util

#endif  // ES2PANDA_UTIL_ERROR_RECOVERY_H