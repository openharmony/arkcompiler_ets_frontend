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

#ifndef ES2PANDA_IR_EXPRESSION_DIRECT_EVAL_H
#define ES2PANDA_IR_EXPRESSION_DIRECT_EVAL_H

#include "ir/expressions/callExpression.h"

namespace panda::es2panda::ir {
class DirectEvalExpression : public CallExpression {
public:
    explicit DirectEvalExpression(Expression *callee, ArenaVector<Expression *> &&arguments,
                                  TSTypeParameterInstantiation *type_params, bool optional, uint32_t parser_status)
        : CallExpression(callee, std::move(arguments), type_params, optional), parser_status_(parser_status)
    {
        type_ = AstNodeType::DIRECT_EVAL;
    }

    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;

private:
    uint32_t parser_status_ {};
};
}  // namespace panda::es2panda::ir

#endif
