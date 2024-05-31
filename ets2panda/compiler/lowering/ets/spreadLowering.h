/*
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

#ifndef ES2PANDA_COMPILER_LOWERING_SPREAD_LOWERING_H
#define ES2PANDA_COMPILER_LOWERING_SPREAD_LOWERING_H

#include "compiler/lowering/phase.h"

namespace ark::es2panda::compiler {

class SpreadConstructionPhase : public Phase {
public:
    std::string_view Name() const override
    {
        return "SpreadConstructionPhase";
    }

    bool Perform(public_lib::Context *ctx, parser::Program *program) override;
    bool Postcondition(public_lib::Context *ctx, const parser::Program *program) override;

protected:
    std::string CreateETSCode(ir::ArrayExpression *array, std::vector<ir::AstNode *> &node, public_lib::Context *ctx);
    std::string CreateLengthString(ir::ArrayExpression *array);
};

}  // namespace ark::es2panda::compiler

#endif
