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

namespace ark::es2panda::compiler {

std::string_view BigIntLowering::Name() const
{
    return "BigIntLowering";
}

void CreateBigInt(parser::ETSParser *parser, ir::ClassProperty *property)
{
    if (property != nullptr && property->Value() != nullptr && property->Value()->IsBigIntLiteral()) {
        auto literal = property->Value()->AsBigIntLiteral();
        auto value = literal->Str();

        // This will change the bigint literal node into the new class instance expression.
        std::string src {"new BigInt("};
        src += value.Utf8();
        src += ")";
        auto newValue = parser->AsETSParser()->CreateExpression(src);
        newValue->SetParent(property);
        property->SetValue(newValue);
    }
}

bool BigIntLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    auto *const parser = ctx->parser->AsETSParser();

    program->Ast()->TransformChildrenRecursively(
        [parser](ir::AstNode *ast) -> ir::AstNode * {
            if (ast->IsClassProperty()) {
                CreateBigInt(parser, ast->AsClassProperty());
            }

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
