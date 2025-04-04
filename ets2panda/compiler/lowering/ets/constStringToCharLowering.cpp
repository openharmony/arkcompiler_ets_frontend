/**
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

ir::AstNode *TryConvertToCharLiteral(public_lib::Context *const ctx, ir::AstNode *ast)
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

    auto newValue = ctx->Allocator()->New<ir::CharLiteral>(value);
    newValue->SetParent(parent);
    newValue->SetRange(ast->Range());
    if (ast->HasBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_CHAR)) {
        newValue->AddBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOX_TO_CHAR);
    }

    newValue->Check(ctx->checker->AsETSChecker());
    return newValue;
}

bool ConstStringToCharLowering::PerformForModule(public_lib::Context *const ctx, parser::Program *const program)
{
    if (program->GetFlag(parser::ProgramFlags::AST_CONST_STRING_TO_CHAR_LOWERED)) {
        return true;
    }

    (void)ctx;
    program->Ast()->TransformChildrenRecursively(
        [ctx](checker::AstNodePtr ast) -> checker::AstNodePtr {
            if (auto newValue = TryConvertToCharLiteral(ctx, ast); newValue != nullptr) {
                return newValue;
            }

            return ast;
        },
        Name());

    program->SetFlag(parser::ProgramFlags::AST_CONST_STRING_TO_CHAR_LOWERED);
    return true;
}

}  // namespace ark::es2panda::compiler
