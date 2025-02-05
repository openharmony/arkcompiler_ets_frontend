/**
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

class DefaultParameterLowering : public PhaseForDeclarations {
    static ir::TSTypeParameterDeclaration *CreateParameterDeclaraion(ir::MethodDefinition *method,
                                                                     public_lib::Context *ctx);
    static ir::FunctionSignature CreateFunctionSignature(ir::MethodDefinition *method,
                                                         ArenaVector<ir::Expression *> &&funcParam,
                                                         public_lib::Context *ctx);
    static ir::TSTypeParameterInstantiation *CreateTypeParameterInstantiation(ir::MethodDefinition *method,
                                                                              public_lib::Context *ctx);
    static ir::BlockStatement *CreateFunctionBody(ir::MethodDefinition *method, public_lib::Context *ctx,
                                                  ArenaVector<ir::Expression *> &&funcCallArgs);
    static ir::FunctionExpression *CreateFunctionExpression(ir::MethodDefinition *method, public_lib::Context *ctx,
                                                            ArenaVector<ir::Expression *> &&funcDefinitionArgs,
                                                            ArenaVector<ir::Expression *> &&funcCallArgs);
    static void CreateOverloadFunction(ir::MethodDefinition *method, ArenaVector<ir::Expression *> &&funcCallArgs,
                                       ArenaVector<ir::Expression *> &&funcDefinitionArgs, public_lib::Context *ctx);
    static void RemoveInitializers(ArenaVector<ir::Expression *> params);

public:
    std::string_view Name() const override
    {
        return "DefaultParameterLowering";
    }
    bool PerformForModule(public_lib::Context *ctx, parser::Program *program) override;

    static std::pair<bool, std::size_t> HasDefaultParam(const ir::ScriptFunction *function, parser::Program *program,
                                                        util::DiagnosticEngine &diagnosticEngine);
    static void ProcessGlobalFunctionDefinition(ir::MethodDefinition *method, public_lib::Context *ctx);
};

}  // namespace ark::es2panda::compiler

#endif  // ES2PANDA_COMPILER_LOWERING_DEFAULT_PARAM_LOWERING_H
