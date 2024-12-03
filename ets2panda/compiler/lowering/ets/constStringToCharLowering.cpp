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

#include "constStringToCharLowering.h"

#include "checker/ETSchecker.h"

namespace ark::es2panda::compiler {

std::string_view ConstStringToCharLowering::Name() const
{
    return "ConstStringToCharLowering";
}

ir::AstNode *TryConvertToCharLiteral(checker::ETSChecker *checker, ir::AstNode *ast)
{
    if (!ast->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::UNBOX_TO_CHAR) || !ast->IsExpression() ||
        ast->AsExpression()->TsType() == nullptr || !ast->AsExpression()->TsType()->IsETSStringType()) {
        return nullptr;
    }

    auto type = ast->AsExpression()->TsType()->AsETSStringType();
    if (!type->IsConstantType() || !type->GetValue().IsConvertibleToChar()) {
        return nullptr;
    }

    auto parent = ast->Parent();
    util::StringView::Iterator it(type->GetValue());
    auto value = static_cast<char16_t>(it.PeekCp());

    auto newValue = checker->Allocator()->New<ir::CharLiteral>(value);
    newValue->SetParent(parent);
    newValue->SetRange(ast->Range());
    if (ast->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_CHAR)) {
        newValue->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_CHAR);
    }

    newValue->Check(checker);
    return newValue;
}

bool ConstStringToCharLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    auto *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [checker](ir::AstNode *ast) -> ir::AstNode * {
            if (auto newValue = TryConvertToCharLiteral(checker, ast); newValue != nullptr) {
                return newValue;
            }

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
