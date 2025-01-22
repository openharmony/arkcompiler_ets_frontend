/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

//
// desc: Object index access syntax is translated to the call of special setter (in case of assignment):
//       "obj[i] = val; => obj.S_set(i, val);"
//   	 or getter (in all the other cases):
//   	 "...obj[i]... => ...obj.S_get(i)..."
//      methods.
//

#include "objectIndexAccess.h"

#include "checker/ETSchecker.h"
#include "compiler/lowering/util.h"
#include "parser/ETSparser.h"
#include "util/options.h"

namespace ark::es2panda::compiler {
ir::Expression *ObjectIndexLowering::ProcessIndexSetAccess(parser::ETSParser *parser, checker::ETSChecker *checker,
                                                           ir::AssignmentExpression *assignmentExpression) const
{
    //  Note! We assume that parser and checker phase nave been already passed correctly, thus the class has
    //  required accessible index method[s] and all the types are properly resolved.
    static std::string const CALL_EXPRESSION =
        std::string {"@@E1."} + std::string {compiler::Signatures::SET_INDEX_METHOD} + "(@@E2, @@E3)";

    // Parse ArkTS code string and create and process corresponding AST node(s)
    auto *const memberExpression = assignmentExpression->Left()->AsMemberExpression();
    auto *const loweringResult = parser->CreateFormattedExpression(
        CALL_EXPRESSION, memberExpression->Object(), memberExpression->Property(), assignmentExpression->Right());
    loweringResult->SetParent(assignmentExpression->Parent());
    loweringResult->SetRange(assignmentExpression->Range());

    CheckLoweredNode(checker->VarBinder()->AsETSBinder(), checker, loweringResult);
    return loweringResult;
}

ir::Expression *ObjectIndexLowering::ProcessIndexGetAccess(parser::ETSParser *parser, checker::ETSChecker *checker,
                                                           ir::MemberExpression *memberExpression) const
{
    //  Note! We assume that parser and checker phase nave been already passed correctly, thus the class has
    //  required accessible index method[s] and all the types are properly resolved.
    static std::string const CALL_EXPRESSION =
        std::string {"@@E1."} + std::string {compiler::Signatures::GET_INDEX_METHOD} + "(@@E2)";

    // Parse ArkTS code string and create and process corresponding AST node(s)
    auto *const loweringResult =
        parser->CreateFormattedExpression(CALL_EXPRESSION, memberExpression->Object(), memberExpression->Property());
    loweringResult->SetParent(memberExpression->Parent());
    loweringResult->SetRange(memberExpression->Range());

    CheckLoweredNode(checker->VarBinder()->AsETSBinder(), checker, loweringResult);
    loweringResult->SetBoxingUnboxingFlags(memberExpression->GetBoxingUnboxingFlags());
    return loweringResult;
}

bool ObjectIndexLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    auto *const parser = ctx->parser->AsETSParser();
    ES2PANDA_ASSERT(parser != nullptr);
    auto *const checker = ctx->checker->AsETSChecker();
    ES2PANDA_ASSERT(checker != nullptr);

    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, parser, checker](ir::AstNode *const ast) -> ir::AstNode * {
            if (ast->IsAssignmentExpression() && ast->AsAssignmentExpression()->Left()->IsMemberExpression() &&
                ast->AsAssignmentExpression()->Left()->AsMemberExpression()->Kind() ==
                    ir::MemberExpressionKind::ELEMENT_ACCESS) {
                if (auto const *const objectType =
                        ast->AsAssignmentExpression()->Left()->AsMemberExpression()->ObjType();
                    objectType != nullptr && !objectType->IsETSDynamicType()) {
                    return ProcessIndexSetAccess(parser, checker, ast->AsAssignmentExpression());
                }
            }
            return ast;
        },
        Name());

    program->Ast()->TransformChildrenRecursively(
        // CC-OFFNXT(G.FMT.14-CPP) project code style
        [this, parser, checker](ir::AstNode *const ast) -> ir::AstNode * {
            if (ast->IsMemberExpression() &&
                ast->AsMemberExpression()->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
                if (auto const *const objectType = ast->AsMemberExpression()->ObjType();
                    objectType != nullptr && !objectType->IsETSDynamicType()) {
                    return ProcessIndexGetAccess(parser, checker, ast->AsMemberExpression());
                }
            }
            return ast;
        },
        Name());

    return true;
}

bool ObjectIndexLowering::PostconditionForModule([[maybe_unused]] public_lib::Context *ctx,
                                                 const parser::Program *program)
{
    return !program->Ast()->IsAnyChild([](const ir::AstNode *ast) {
        if (ast->IsMemberExpression() &&
            ast->AsMemberExpression()->Kind() == ir::MemberExpressionKind::ELEMENT_ACCESS) {
            if (auto const *const objectType = ast->AsMemberExpression()->ObjType(); objectType != nullptr) {
                return !objectType->IsETSDynamicType();
            }
        }
        return false;
    });
}

}  // namespace ark::es2panda::compiler
