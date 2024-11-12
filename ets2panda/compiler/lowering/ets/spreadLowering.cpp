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

#include "spreadLowering.h"
#include "checker/ETSchecker.h"
#include "compiler/lowering/scopesInit/scopesInitPhase.h"
#include "compiler/lowering/util.h"
#include "ir/expressions/literals/numberLiteral.h"

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

static ir::AstNode *SetSourceRangesRecursively(ir::AstNode *node)
{
    auto const refine = [](ir::AstNode *n) { n->SetRange(n->Parent()->Range()); };

    refine(node);
    node->IterateRecursively(refine);
    return node;
}

void CreateSpreadArrayDeclareStatements(public_lib::Context *ctx, ir::ArrayExpression *array,
                                        std::vector<ir::Identifier *> &spreadArrayIds,
                                        ArenaVector<ir::Statement *> &statements)
{
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    for (auto element : array->Elements()) {
        if (element->Type() != ir::AstNodeType::SPREAD_ELEMENT) {
            continue;
        }
        ir::Identifier *const arrIdent = Gensym(allocator);
        auto *const initExpr = element->AsSpreadElement()->Argument()->Clone(allocator, nullptr);
        spreadArrayIds.emplace_back(arrIdent);
        statements.emplace_back(parser->CreateFormattedStatement("let @@I1 = (@@E2);", arrIdent, initExpr));
    }
}

void CreateNewArrayLengthStatement(public_lib::Context *ctx, ir::ArrayExpression *array,
                                   std::vector<ir::Identifier *> &spreadArrayIds,
                                   ArenaVector<ir::Statement *> &statements, ir::Identifier *newArrayLengthId)
{
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    std::vector<ir::AstNode *> nodesWaitingInsert {newArrayLengthId};
    int argumentCount = 1;
    std::stringstream lengthString;
    int normalElementCount = array->Elements().size() - spreadArrayIds.size();
    lengthString.clear();
    lengthString << "let @@I" << (argumentCount++) << " : int = " << normalElementCount << " + ";
    for (auto *spaId : spreadArrayIds) {
        lengthString << "@@I" << (argumentCount++) << ".length + ";
        nodesWaitingInsert.emplace_back(spaId->Clone(allocator, nullptr));
    }
    lengthString << "0;";
    statements.emplace_back(parser->CreateFormattedStatement(lengthString.str(), nodesWaitingInsert));
}

ir::Identifier *ClearIdentifierAnnotation(ir::Identifier *node)
{
    if (!node->IsAnnotatedExpression() || (node->AsAnnotatedExpression()->TypeAnnotation() == nullptr)) {
        return node;
    }

    node->AsAnnotatedExpression()->SetTsTypeAnnotation(nullptr);
    return node;
}

ir::Identifier *CreateNewArrayDeclareStatement(public_lib::Context *ctx, ir::ArrayExpression *array,
                                               ArenaVector<ir::Statement *> &statements,
                                               ir::Identifier *newArrayLengthId)
{
    auto *const checker = ctx->checker->AsETSChecker();
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    ir::Identifier *newArrayId = Gensym(allocator);
    auto arrayType = array->TsType()->AsETSArrayType();
    auto initElemType = arrayType->ElementType();
    checker::ETSArrayType *newArrayType = arrayType;
    if (checker->IsReferenceType(initElemType)) {
        newArrayType = checker->Allocator()->New<checker::ETSArrayType>(
            checker->CreateETSUnionType({initElemType, checker->GlobalETSNullType()}));
    }
    std::stringstream newArrayDeclareStr;
    // NOTE: For ETSUnionType(String|Int) or ETSObjectType(private constructor) or ..., we canot use "new Type[]" to
    //       declare an array, so we add "|null" to solve it temporarily.
    //       We might need to use cast Expression in the end of the generated source code to remove "|null", such as
    //       "newArrayName as arrayType[]".
    //       But now cast Expression doesn't support built-in array (cast fatherType[] to sonType[]), so "newArrayName
    //       as arrayType" should be added after cast Expression is implemented completely.
    newArrayDeclareStr.clear();
    newArrayDeclareStr << "let @@I1: @@T2 = new @@T3 [@@I4];";

    ir::Statement *newArrayDeclareSt = parser->CreateFormattedStatement(
        newArrayDeclareStr.str(), newArrayId, newArrayType, newArrayType->ElementType(),
        ClearIdentifierAnnotation(newArrayLengthId->Clone(allocator, nullptr)));
    statements.emplace_back(newArrayDeclareSt);
    return newArrayId;
}

ir::Statement *CreateSpreadArrIteratorStatement(public_lib::Context *ctx, ir::ArrayExpression *array,
                                                ir::Identifier *spreadArrIterator)
{
    auto *const parser = ctx->parser->AsETSParser();
    auto elemType = array->TsType()->AsETSArrayType()->ElementType();

    std::stringstream spArrIterDeclareStr;
    spArrIterDeclareStr.clear();
    spArrIterDeclareStr << "let @@I1: @@T2;";
    ir::Statement *spArrIterDeclareSt =
        parser->CreateFormattedStatement(spArrIterDeclareStr.str(), spreadArrIterator, elemType);

    return spArrIterDeclareSt;
}

ir::Statement *CreateElementsAssignStatementBySpreadArr(public_lib::Context *ctx, ir::Identifier *spId,
                                                        std::vector<ir::AstNode *> &newArrayAndIndex,
                                                        ir::Identifier *spreadArrIterator)
{
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    auto *const newArrayId = newArrayAndIndex[0];
    auto *const newArrayIndexId = newArrayAndIndex[1];

    std::stringstream elementsAssignStr;
    elementsAssignStr.clear();
    elementsAssignStr << "for (@@I2 of @@I3) {";
    elementsAssignStr << "@@I4[@@I5] = @@I6;";
    elementsAssignStr << "@@I7++;";
    elementsAssignStr << "}";

    ir::Statement *elementsAssignStatement = parser->CreateFormattedStatement(
        elementsAssignStr.str(), ClearIdentifierAnnotation(spreadArrIterator->Clone(allocator, nullptr)),
        ClearIdentifierAnnotation(spreadArrIterator->Clone(allocator, nullptr)), spId->Clone(allocator, nullptr),
        newArrayId->Clone(allocator, nullptr), newArrayIndexId->Clone(allocator, nullptr),
        ClearIdentifierAnnotation(spreadArrIterator->Clone(allocator, nullptr)),
        newArrayIndexId->Clone(allocator, nullptr));

    return elementsAssignStatement;
}

ir::Statement *CreateElementsAssignStatementBySingle(public_lib::Context *ctx, ir::AstNode *element,
                                                     std::vector<ir::AstNode *> &newArrayAndIndex)
{
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    auto *const newArrayId = newArrayAndIndex[0];
    auto *const newArrayIndexId = newArrayAndIndex[1];
    std::stringstream elementsAssignStr;
    elementsAssignStr.clear();
    elementsAssignStr << "@@I1[@@I2] = (@@E3);";
    elementsAssignStr << "@@I4++;";

    ir::Statement *elementsAssignStatement = parser->CreateFormattedStatement(
        elementsAssignStr.str(), newArrayId->Clone(allocator, nullptr), newArrayIndexId->Clone(allocator, nullptr),
        element->Clone(allocator, nullptr), newArrayIndexId->Clone(allocator, nullptr));

    return elementsAssignStatement;
}

void CreateNewArrayElementsAssignStatement(public_lib::Context *ctx, ir::ArrayExpression *array,
                                           std::vector<ir::Identifier *> &spArrIds,
                                           ArenaVector<ir::Statement *> &statements,
                                           std::vector<ir::AstNode *> &newArrayAndIndex)
{
    auto *const allocator = ctx->allocator;
    auto *const parser = ctx->parser->AsETSParser();
    auto *const newArrayId = newArrayAndIndex[0];
    int spArrIdx = 0;

    for (auto *element : array->Elements()) {
        if (element->Type() == ir::AstNodeType::SPREAD_ELEMENT) {
            ir::Identifier *spreadArrIterator = Gensym(allocator);
            statements.emplace_back(CreateSpreadArrIteratorStatement(ctx, array, spreadArrIterator));
            statements.emplace_back(CreateElementsAssignStatementBySpreadArr(ctx, spArrIds[spArrIdx++],
                                                                             newArrayAndIndex, spreadArrIterator));
        } else {
            statements.emplace_back(CreateElementsAssignStatementBySingle(ctx, element, newArrayAndIndex));
        }
    }

    statements.emplace_back(parser->CreateFormattedStatement("@@I1;", newArrayId->Clone(allocator, nullptr)));
}

/*
 * NOTE: Expand the SpreadExpr to BlockExpr, the rules as follows :
 * let spreadArrayId1 = spreadExpr1
 * let length : int = normalExprCount + spreadArrayId1.length + 0
 * type typeOfNewArray = arrayType
 * let newArray: typeOfNewArray[] = new typeOfNewArray[length]
 * let newArrayIndex = 0
 * let elementOfSpreadArray1: arrayType
 * for (elementOfSpreadArray1 of spreadArray1) {
 *     newArray[newArrayIndex] = elementOfSpreadArray1
 *     newArrayIndex++
 * }
 * newArray[newArrayIndex] = normalExpr1
 * newArrayIndex++
 * ...
 * newArray;
 */
ir::BlockExpression *CreateLoweredExpression(public_lib::Context *ctx, ir::ArrayExpression *array)
{
    auto *const checker = ctx->checker->AsETSChecker();
    auto *const parser = ctx->parser->AsETSParser();
    auto *const allocator = ctx->allocator;
    ArenaVector<ir::Statement *> statements(allocator->Adapter());
    std::vector<ir::Identifier *> spreadArrayIds = {};
    ir::Identifier *newArrayLengthId = Gensym(allocator);

    CreateSpreadArrayDeclareStatements(ctx, array, spreadArrayIds, statements);
    CreateNewArrayLengthStatement(ctx, array, spreadArrayIds, statements, newArrayLengthId);

    ir::Identifier *newArrayId = CreateNewArrayDeclareStatement(ctx, array, statements, newArrayLengthId);
    ir::Identifier *newArrayIndexId = Gensym(allocator);
    statements.emplace_back(parser->CreateFormattedStatement("let @@I1 = 0;", newArrayIndexId));
    std::vector<ir::AstNode *> newArrayAndIndex {ClearIdentifierAnnotation(newArrayId->Clone(allocator, nullptr)),
                                                 newArrayIndexId->Clone(allocator, nullptr)};

    CreateNewArrayElementsAssignStatement(ctx, array, spreadArrayIds, statements, newArrayAndIndex);
    return checker->AllocNode<ir::BlockExpression>(std::move(statements));
}

bool SpreadConstructionPhase::Perform(public_lib::Context *ctx, parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            Perform(ctx, extProg);
        }
    }

    checker::ETSChecker *const checker = ctx->checker->AsETSChecker();

    program->Ast()->TransformChildrenRecursively(
        [&checker, &ctx](ir::AstNode *const node) -> AstNodePtr {
            if (node->IsArrayExpression() &&
                std::any_of(node->AsArrayExpression()->Elements().begin(), node->AsArrayExpression()->Elements().end(),
                            [](const auto *param) { return param->Type() == ir::AstNodeType::SPREAD_ELEMENT; })) {
                auto scopeCtx =
                    varbinder::LexicalScope<varbinder::Scope>::Enter(checker->VarBinder(), NearestScope(node));

                ir::BlockExpression *blockExpression = CreateLoweredExpression(ctx, node->AsArrayExpression());
                blockExpression->SetParent(node->Parent());

                // NOTE: this blockExpression is a kind of formatted-dummy code, which is invisible to users,
                //       so, its source range should be same as the original code([element1, element2, ...spreadExpr])
                blockExpression->SetRange(node->Range());
                for (auto st : blockExpression->Statements()) {
                    SetSourceRangesRecursively(st);
                }

                Recheck(checker->VarBinder()->AsETSBinder(), checker, blockExpression);

                return blockExpression;
            }

            return node;
        },
        Name());
    return true;
}

bool SpreadConstructionPhase::Postcondition(public_lib::Context *ctx, const parser::Program *program)
{
    for (auto &[_, ext_programs] : program->ExternalSources()) {
        (void)_;
        for (auto *extProg : ext_programs) {
            if (!Postcondition(ctx, extProg)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace ark::es2panda::compiler
