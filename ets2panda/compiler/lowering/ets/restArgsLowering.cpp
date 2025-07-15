/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "restArgsLowering.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "ir/expressions/arrayExpression.h"

#include <checker/ETSchecker.h>
#include <sstream>

namespace ark::es2panda::compiler {

using AstNodePtr = ir::AstNode *;

static ir::BlockExpression *CreateRestArgsBlockExpression(public_lib::Context *context,
                                                          ir::SpreadElement *spreadElement)
{
    auto *allocator = context->allocator;
    auto *parser = context->parser->AsETSParser();
    auto *checker = context->checker->AsETSChecker();

    ArenaVector<ir::Statement *> blockStatements(allocator->Adapter());
    const auto arraySymbol = Gensym(allocator);
    const auto argumentSymbol = Gensym(allocator);
    const auto iteratorIndex = Gensym(allocator);
    const auto iteratorSymbol = Gensym(allocator);
    const auto elementType = checker->GetElementTypeOfArray(spreadElement->Argument()->TsType());
    auto *typeNode = allocator->New<ir::OpaqueTypeNode>(elementType, allocator);
    blockStatements.push_back(
        parser->CreateFormattedStatement("let @@I1 = @@E2;", argumentSymbol, spreadElement->Argument()));
    blockStatements.push_back(parser->CreateFormattedStatement("let @@I1 = 0;", iteratorIndex));
    blockStatements.push_back(parser->CreateFormattedStatement("let @@I1 = new Array<@@T2>(@@I3.length);", arraySymbol,
                                                               typeNode, argumentSymbol->Clone(allocator, nullptr)));
    std::vector<ir::AstNode *> args;
    std::stringstream ss;
    ss << "for (let @@I1 of @@I2){";
    args.emplace_back(iteratorSymbol);
    args.emplace_back(argumentSymbol->Clone(allocator, nullptr));
    ss << "@@I3[@@I4] = @@I5;";
    args.emplace_back(arraySymbol->Clone(allocator, nullptr));
    ES2PANDA_ASSERT(iteratorIndex != nullptr);
    args.emplace_back(iteratorIndex->Clone(allocator, nullptr));
    args.emplace_back(iteratorSymbol->Clone(allocator, nullptr));
    ss << "@@I6 = @@I7 + 1;";
    args.emplace_back(iteratorIndex->Clone(allocator, nullptr));
    args.emplace_back(iteratorIndex->Clone(allocator, nullptr));
    ss << "}";
    ir::Statement *loopStatement = parser->CreateFormattedStatement(ss.str(), args);

    blockStatements.push_back(loopStatement);
    blockStatements.push_back(parser->CreateFormattedStatement("@@I1", arraySymbol->Clone(allocator, nullptr)));
    auto *blockExpr = util::NodeAllocator::ForceSetParent<ir::BlockExpression>(allocator, std::move(blockStatements));
    return blockExpr;
}

static ir::BlockExpression *ConvertSpreadToBlockExpression(public_lib::Context *context,
                                                           ir::SpreadElement *spreadElement)
{
    auto *blockExpression = CreateRestArgsBlockExpression(context, spreadElement);
    ES2PANDA_ASSERT(blockExpression != nullptr);
    blockExpression->SetParent(spreadElement->Parent());
    blockExpression->SetRange(spreadElement->Range());

    for (auto *statement : blockExpression->Statements()) {
        SetSourceRangesRecursively(statement, spreadElement->Range());
    }
    return blockExpression;
}

static bool ShouldProcessRestParameters(checker::Signature *signature, const ArenaVector<ir::Expression *> &arguments)
{
    return signature != nullptr && signature->HasRestParameter() && !signature->RestVar()->TsType()->IsETSArrayType() &&
           arguments.size() >= signature->Params().size() && !signature->RestVar()->TsType()->IsETSTupleType();
}

static ir::Expression *CreateRestArgsArray(public_lib::Context *context, ArenaVector<ir::Expression *> &arguments,
                                           checker::Signature *signature)
{
    auto *allocator = context->allocator;
    auto *parser = context->parser->AsETSParser();
    auto *checker = context->checker->AsETSChecker();

    // Handle single spread element case
    const size_t extraArgs = arguments.size() - signature->Params().size();
    if (extraArgs == 1 && arguments.back()->IsSpreadElement()) {
        return ConvertSpreadToBlockExpression(context, arguments.back()->AsSpreadElement());
    }
    // Determine array type
    checker::Type *arrayType = signature->RestVar()->TsType();
    auto *type = checker->AllocNode<ir::OpaqueTypeNode>(checker->GetElementTypeOfArray(arrayType), allocator);
    if (extraArgs == 0) {
        return parser->CreateFormattedExpression("new Array<@@T1>(0)", type);
    }

    ArenaVector<ir::Expression *> copiedArguments(arguments.begin() + signature->Params().size(), arguments.end(),
                                                  allocator->Adapter());

    std::stringstream ss;
    auto *genSymIdent = Gensym(allocator);
    ss << "let @@I1 : FixedArray<@@T2> = @@E3;";
    ss << "Array.from<@@T4>(@@I5);";
    auto *arrayExpr = checker->AllocNode<ir::ArrayExpression>(std::move(copiedArguments), allocator);
    ES2PANDA_ASSERT(type != nullptr);
    auto *loweringResult =
        parser->CreateFormattedExpression(ss.str(), genSymIdent, type, arrayExpr, type->Clone(allocator, nullptr),
                                          genSymIdent->Clone(allocator, nullptr));
    return loweringResult;
}

static ir::CallExpression *RebuildCallExpression(public_lib::Context *context, ir::CallExpression *originalCall,
                                                 checker::Signature *signature, ir::Expression *restArgsArray)
{
    auto *allocator = context->allocator;
    auto *varbinder = context->checker->VarBinder()->AsETSBinder();
    ArenaVector<ir::Expression *> newArgs(allocator->Adapter());

    for (size_t i = 0; i < signature->Params().size(); ++i) {
        newArgs.push_back(originalCall->Arguments()[i]);
        newArgs[i]->SetBoxingUnboxingFlags(ir::BoxingUnboxingFlags::NONE);
    }

    newArgs.push_back(restArgsArray);

    auto *newCall = util::NodeAllocator::ForceSetParent<ir::CallExpression>(allocator, originalCall->Callee(),
                                                                            std::move(newArgs), nullptr, false);
    ES2PANDA_ASSERT(newCall != nullptr);
    restArgsArray->SetParent(newCall);
    newCall->SetParent(originalCall->Parent());
    newCall->AddModifier(originalCall->Modifiers());
    newCall->AddBoxingUnboxingFlags(originalCall->GetBoxingUnboxingFlags());
    newCall->SetTypeParams(originalCall->TypeParams());
    newCall->AddAstNodeFlags(ir::AstNodeFlags::RESIZABLE_REST);

    auto *scope = NearestScope(newCall->Parent());
    auto bscope = varbinder::LexicalScope<varbinder::Scope>::Enter(varbinder, scope);
    CheckLoweredNode(context->checker->VarBinder()->AsETSBinder(), context->checker->AsETSChecker(), newCall);
    newCall->RemoveAstNodeFlags(ir::AstNodeFlags::RESIZABLE_REST);
    return newCall;
}

static ir::ETSNewClassInstanceExpression *RebuildNewClassInstanceExpression(
    public_lib::Context *context, ir::ETSNewClassInstanceExpression *originalCall, checker::Signature *signature,
    ir::Expression *restArgsArray)
{
    auto *allocator = context->allocator;
    ArenaVector<ir::Expression *> newArgs(allocator->Adapter());

    for (size_t i = 0; i < signature->Params().size(); ++i) {
        newArgs.push_back(originalCall->GetArguments()[i]);
    }

    newArgs.push_back(restArgsArray);

    auto *newCall = util::NodeAllocator::ForceSetParent<ir::ETSNewClassInstanceExpression>(
        allocator, originalCall->GetTypeRef()->Clone(allocator, nullptr)->AsETSTypeReference(), std::move(newArgs));

    restArgsArray->SetParent(newCall);
    newCall->SetParent(originalCall->Parent());
    newCall->AddModifier(originalCall->Modifiers());
    newCall->AddBoxingUnboxingFlags(originalCall->GetBoxingUnboxingFlags());
    auto *scope = NearestScope(newCall->Parent());
    auto bscope = varbinder::LexicalScope<varbinder::Scope>::Enter(context->checker->VarBinder()->AsETSBinder(), scope);
    CheckLoweredNode(context->checker->VarBinder()->AsETSBinder(), context->checker->AsETSChecker(), newCall);
    return newCall;
}

ir::ETSNewClassInstanceExpression *RestArgsLowering::TransformCallConstructWithRestArgs(
    ir::ETSNewClassInstanceExpression *expr, public_lib::Context *context)
{
    checker::Signature *signature = expr->GetSignature();
    if (!ShouldProcessRestParameters(signature, expr->GetArguments())) {
        return expr;
    }

    auto *restArgsArray = CreateRestArgsArray(context, expr->GetArguments(), signature);
    restArgsArray->AddAstNodeFlags(ir::AstNodeFlags::RESIZABLE_REST);

    return RebuildNewClassInstanceExpression(context, expr, signature, restArgsArray);
}

ir::CallExpression *RestArgsLowering::TransformCallExpressionWithRestArgs(ir::CallExpression *callExpr,
                                                                          public_lib::Context *context)
{
    checker::Type *calleeType = callExpr->Callee()->TsType();
    if (calleeType == nullptr || calleeType->IsETSDynamicType() || calleeType->IsETSArrowType()) {
        return callExpr;
    }

    checker::Signature *signature = callExpr->Signature();
    if (!ShouldProcessRestParameters(signature, callExpr->Arguments())) {
        return callExpr;
    }

    auto *restArgsArray = CreateRestArgsArray(context, callExpr->Arguments(), signature);
    restArgsArray->AddAstNodeFlags(ir::AstNodeFlags::RESIZABLE_REST);

    return RebuildCallExpression(context, callExpr, signature, restArgsArray);
}

bool RestArgsLowering::PerformForModule(public_lib::Context *ctx, parser::Program *program)
{
    program->Ast()->TransformChildrenRecursively(
        [this, ctx](ir::AstNode *node) -> AstNodePtr {
            if (node->IsCallExpression()) {
                return TransformCallExpressionWithRestArgs(node->AsCallExpression(), ctx);
            }
            if (node->IsETSNewClassInstanceExpression()) {
                return TransformCallConstructWithRestArgs(node->AsETSNewClassInstanceExpression(), ctx);
            }
            return node;
        },
        Name());
    return true;
}
}  // namespace ark::es2panda::compiler