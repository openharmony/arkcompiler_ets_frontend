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

#include "boxedTypeLowering.h"

#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "generated/signatures.h"

namespace ark::es2panda::compiler {

std::string_view BoxedTypeLowering::Name() const
{
    return "BoxedTypeLowering";
}

void BoxNumberLiteralArguments(ir::CallExpression *callExpr, PhaseManager *phaseManager, checker::ETSChecker *checker,
                               parser::ETSParser *parser)
{
    const static std::unordered_map<ir::BoxingUnboxingFlags, util::StringView> BOXTO({
        {ir::BoxingUnboxingFlags::BOX_TO_BOOLEAN, compiler::Signatures::BUILTIN_BOOLEAN_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_BYTE, compiler::Signatures::BUILTIN_BYTE_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_SHORT, compiler::Signatures::BUILTIN_SHORT_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_CHAR, compiler::Signatures::BUILTIN_CHAR_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_INT, compiler::Signatures::BUILTIN_INT_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_LONG, compiler::Signatures::BUILTIN_LONG_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_FLOAT, compiler::Signatures::BUILTIN_FLOAT_CLASS},
        {ir::BoxingUnboxingFlags::BOX_TO_DOUBLE, compiler::Signatures::BUILTIN_DOUBLE_CLASS},
    });

    for (size_t i = 0; i < callExpr->Arguments().size(); ++i) {
        auto arg = callExpr->Arguments()[i];
        if (arg->IsNumberLiteral()) {
            const auto boxingFlag = arg->GetBoxingUnboxingFlags() & ir::BoxingUnboxingFlags::BOXING_FLAG;
            auto it = BOXTO.find(static_cast<ir::BoxingUnboxingFlags>(boxingFlag));
            if (it == BOXTO.end()) {
                continue;
            }

            auto res = parser->CreateFormattedExpression("@@I1.valueOf(@@E2)", it->second, arg);
            res->SetParent(callExpr);
            res->SetRange(arg->Range());
            arg->RemoveBoxingUnboxingFlags(ir::BoxingUnboxingFlags::BOXING_FLAG);
            callExpr->Arguments()[i] = res;

            Recheck(phaseManager, checker->VarBinder()->AsETSBinder(), checker, res);
        }
    }
}

bool BoxedTypeLowering::Perform(public_lib::Context *const ctx, parser::Program *const program)
{
    for (const auto &[_, extPrograms] : program->ExternalSources()) {
        (void)_;
        for (auto *const extProg : extPrograms) {
            if (extProg->GetFlag(parser::ProgramFlags::AST_BOXED_TYPE_LOWERED)) {
                continue;
            }
            Perform(ctx, extProg);
            extProg->SetFlag(parser::ProgramFlags::AST_BOXED_TYPE_LOWERED);
        }
    }

    auto checker = ctx->checker->AsETSChecker();
    auto parser = ctx->parser->AsETSParser();
    auto phaseManager = ctx->phaseManager;
    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [phaseManager, checker, parser](checker::AstNodePtr ast) -> checker::AstNodePtr {
            if (!ast->IsCallExpression()) {
                return ast;
            }

            auto callExpr = ast->AsCallExpression();
            if (callExpr->Signature() == nullptr ||
                // Skip lambda expressions because lambda parameters are treated a special way as ETSObjectType.
                callExpr->Callee()->TsType()->IsETSObjectType()) {
                return ast;
            }

            BoxNumberLiteralArguments(callExpr, phaseManager, checker, parser);

            return ast;
        },
        Name());

    return true;
}

}  // namespace ark::es2panda::compiler
