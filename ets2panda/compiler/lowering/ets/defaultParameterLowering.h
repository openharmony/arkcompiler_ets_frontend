/**
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_LOWERING_DEFAULT_PARAM_LOWERING_H
#define ES2PANDA_COMPILER_LOWERING_DEFAULT_PARAM_LOWERING_H

#include "compiler/lowering/phase.h"

namespace ark::es2panda::compiler {

class DefaultParameterLowering : public Phase {
    std::pair<bool, std::size_t> HasDefaultParam(const ir::ScriptFunction *function, parser::Program *program);
    void ThrowSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos,
                          parser::Program *program) const
    {
        lexer::LineIndex index(program->SourceCode());
        lexer::SourceLocation loc = index.GetLocation(pos);

        throw Error {ErrorType::SYNTAX, program->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col};
    }
    ir::TSTypeParameterDeclaration *CreateParameterDeclaraion(ir::MethodDefinition *method, public_lib::Context *ctx);
    ir::FunctionSignature CreateFunctionSignature(ir::MethodDefinition *method, ArenaVector<ir::Expression *> funcParam,
                                                  public_lib::Context *ctx);
    ir::TSTypeParameterInstantiation *CreateTypeParameterInstantiation(ir::MethodDefinition *method,
                                                                       public_lib::Context *ctx);
    ir::BlockStatement *CreateFunctionBody(ir::MethodDefinition *method, public_lib::Context *ctx,
                                           ArenaVector<ir::Expression *> funcCallArgs);
    ir::FunctionExpression *CreateFunctionExpression(ir::MethodDefinition *method, public_lib::Context *ctx,
                                                     ArenaVector<ir::Expression *> funcDefinitionArgs,
                                                     ArenaVector<ir::Expression *> funcCallArgs);
    void CreateOverloadFunction(ir::MethodDefinition *method, ArenaVector<ir::Expression *> funcCallArgs,
                                ArenaVector<ir::Expression *> funcDefinitionArgs, public_lib::Context *ctx);
    void RemoveInitializers(ArenaVector<ir::Expression *> params);
    void ProcessGlobalFunctionDefinition(ir::MethodDefinition *method, public_lib::Context *ctx);

public:
    std::string_view Name() const override
    {
        return "DefaultParameterLowering";
    }
    bool Perform(public_lib::Context *ctx, parser::Program *program) override;
};

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_LOWERING_DEFAULT_PARAM_LOWERING_H
