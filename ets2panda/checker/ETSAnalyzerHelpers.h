/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_CHECKER_ETSANALYZERHELPERS_H
#define ES2PANDA_CHECKER_ETSANALYZERHELPERS_H

#include "checker/types/type.h"
#include "varbinder/ETSBinder.h"
#include "checker/ETSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "util/helpers.h"

#include <memory>

namespace ark::es2panda::checker {
void CheckExtensionIsShadowedInCurrentClassOrInterface(checker::ETSChecker *checker, checker::ETSObjectType *objType,
                                                       ir::ScriptFunction *extensionFunc,
                                                       checker::Signature *signature);
void CheckExtensionIsShadowedByMethod(checker::ETSChecker *checker, checker::ETSObjectType *objType,
                                      ir::ScriptFunction *extensionFunc, checker::Signature *signature);
void CheckExtensionMethod(checker::ETSChecker *checker, ir::ScriptFunction *extensionFunc, ir::MethodDefinition *node);
void DoBodyTypeChecking(ETSChecker *checker, ir::MethodDefinition *node, ir::ScriptFunction *scriptFunc);
void ComposeAsyncImplFuncReturnType(ETSChecker *checker, ir::ScriptFunction *scriptFunc);
void ComposeAsyncImplMethod(ETSChecker *checker, ir::MethodDefinition *node);
void CheckPredefinedMethodReturnType(ETSChecker *checker, ir::ScriptFunction *scriptFunc);
void CheckIteratorMethodReturnType(ETSChecker *checker, ir::ScriptFunction *scriptFunc,
                                   const lexer::SourcePosition &position, const std::string &methodName);
checker::Type *InitAnonymousLambdaCallee(checker::ETSChecker *checker, ir::Expression *callee,
                                         checker::Type *calleeType);
checker::Signature *ResolveCallExtensionFunction(checker::ETSFunctionType *functionType, checker::ETSChecker *checker,
                                                 ir::CallExpression *expr);
checker::Signature *ResolveCallForETSExtensionFuncHelperType(checker::ETSExtensionFuncHelperType *type,
                                                             checker::ETSChecker *checker, ir::CallExpression *expr);
ArenaVector<checker::Signature *> GetUnionTypeSignatures(ETSChecker *checker, checker::ETSUnionType *etsUnionType);
ArenaVector<checker::Signature *> &ChooseSignatures(ETSChecker *checker, checker::Type *calleeType,
                                                    bool isConstructorCall, bool isFunctionalInterface,
                                                    bool isUnionTypeWithFunctionalInterface);
checker::ETSObjectType *ChooseCalleeObj(ETSChecker *checker, ir::CallExpression *expr, checker::Type *calleeType,
                                        bool isConstructorCall);
void ProcessExclamationMark(ETSChecker *checker, ir::UnaryExpression *expr, checker::Type *operandType);
void SetTsTypeForUnaryExpression(ETSChecker *checker, ir::UnaryExpression *expr, checker::Type *operandType);
checker::ETSObjectType *CreateSyntheticType(ETSChecker *checker, util::StringView const &syntheticName,
                                            checker::ETSObjectType *lastObjectType, ir::Identifier *id);
checker::Type *GetIteratorType(ETSChecker *checker, checker::Type *elemType, ir::AstNode *left);
bool CheckArgumentVoidType(checker::Type *&funcReturnType, ETSChecker *checker, const std::string &name,
                           ir::ReturnStatement *st);
bool CheckReturnType(ETSChecker *checker, checker::Type *funcReturnType, checker::Type *argumentType,
                     ir::Expression *stArgument, bool isAsync);
void InferReturnType(ETSChecker *checker, ir::ScriptFunction *containingFunc, checker::Type *&funcReturnType,
                     ir::Expression *stArgument);
void ProcessReturnStatements(ETSChecker *checker, ir::ScriptFunction *containingFunc, checker::Type *&funcReturnType,
                             ir::ReturnStatement *st, ir::Expression *stArgument);
bool IsAsyncMethod(ir::AstNode *node);

ETSObjectType *CreateOptionalSignaturesForFunctionalType(ETSChecker *checker, ir::ETSFunctionType *node,
                                                         ETSObjectType *genericInterfaceType,
                                                         size_t optionalParameterIndex);
ETSObjectType *CreateInterfaceTypeForETSFunctionType(ETSChecker *checker, ir::ETSFunctionType *node,
                                                     ETSObjectType *genericInterfaceType);
Type *CreateParamTypeWithDefaultParam(ETSChecker *checker, ir::Expression *params);

Type *InstantiateBoxedPrimitiveType(ETSChecker *checker, ir::Expression *param, Type *paramType);
}  // namespace ark::es2panda::checker

#endif  // ES2PANDA_CHECKER_ETSANALYZERHELPERS_H
