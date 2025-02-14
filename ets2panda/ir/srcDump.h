/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd. All rights reserved.
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

#ifndef ES2PANDA_IR_SRCDUMP_H
#define ES2PANDA_IR_SRCDUMP_H

#include <ir/astNode.h>
#include <lexer/token/sourceLocation.h>
#include "generated/tokenType.h"
#include <util/ustring.h>

#include <sstream>
#include <variant>

namespace ark::es2panda::ir {

class SrcDumper {
public:
    explicit SrcDumper(const ir::AstNode *node);

    void Add(const std::string &str);
    void Add(int32_t i);
    void Add(int64_t l);
    void Add(float f);
    void Add(double d);

    std::string Str() const
    {
        return ss_.str();
    }

    void IncrIndent();
    void DecrIndent();
    void Endl(size_t num = 1);

private:
    std::stringstream ss_;
    std::string indent_;
};
}  // namespace ark::es2panda::ir

#endif  // ES2PANDA_IR_SRCDUMP_H
