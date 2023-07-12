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

#include "statement.h"

namespace panda::es2panda::ir {
void Statement::UpdateForMultipleTransformedStatements(const NodeUpdater &cb,
                                                       ArenaVector<Statement *> &originStatements)
{
    for (auto iter = originStatements.begin(); iter != originStatements.end();) {
        auto newStatements = cb(*iter);
        if (std::holds_alternative<ir::AstNode *>(newStatements)) {
            auto statement = std::get<ir::AstNode *>(newStatements);
            if (statement == *iter) {
                iter++;
            } else if (statement == nullptr) {
                iter = originStatements.erase(iter);
            } else {
                *iter = statement->AsStatement();
                iter++;
            }
        } else {
            auto statements = std::get<std::vector<ir::AstNode *>>(newStatements);
            for (auto *it : statements) {
                iter = originStatements.insert(iter, it->AsStatement());
                iter++;
            }
            iter = originStatements.erase(iter);
        }
    }
}
}  // namespace panda::es2panda::ir
