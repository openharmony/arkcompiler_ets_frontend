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

#include "bigintLowering.h"

#include "checker/ETSchecker.h"
#include "macros.h"

namespace ark::es2panda::compiler {

std::string_view BigIntLowering::Name() const
{
    return "BigIntLowering";
}

bool BigIntLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    program->Ast()->TransformChildrenRecursively([ctx](ir::AstNode *const ast) -> ir::AstNode * {
        if (ast != nullptr && ast->IsClassProperty()) {
            auto property = ast->AsClassProperty();
            if (property != nullptr && property->Value() != nullptr && property->Value()->IsBigIntLiteral()) {
                auto literal = property->Value()->AsBigIntLiteral();
                auto value = literal->Str();

                // This will change the bigint literal node into the new class instance expression.
                std::stringstream src;
                src << "new BigInt(" << value << ")";
                auto newValue = ctx->parser->AsETSParser()->CreateExpression(src.str());
                newValue->SetParent(property);
                property->SetValue(newValue);
            }
        }

        return ast;
    });

    return true;
}

}  // namespace ark::es2panda::compiler
