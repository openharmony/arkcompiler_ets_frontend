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

#ifndef ES2PANDA_CHECKER_ETSANALYZER_H
#define ES2PANDA_CHECKER_ETSANALYZER_H

#include "checker/SemanticAnalyzer.h"
#include "checker/ETSchecker.h"
#include "ETSAnalyzerHelpers.h"

namespace ark::es2panda::checker {

class ETSAnalyzer final : public SemanticAnalyzer {
public:
    explicit ETSAnalyzer(Checker *checker) : SemanticAnalyzer(checker) {};

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSANALYZER_CHECK_METHOD(_, nodeType) checker::Type *Check(ir::nodeType *node) const override;
    AST_NODE_MAPPING(DECLARE_ETSANALYZER_CHECK_METHOD)
#undef DECLARE_ETSANALYZER_CHECK_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_ETSANALYZER_CHECK_METHOD(_, __, nodeType, ___) \
    virtual checker::Type *Check(ir::nodeType *node) const override;
    AST_NODE_REINTERPRET_MAPPING(DECLARE_ETSANALYZER_CHECK_METHOD)
#undef DECLARE_ETSANALYZER_CHECK_METHOD
    checker::Type *PreferredType(ir::ObjectExpression *expr) const;
    checker::Type *GetPreferredType(ir::ArrayExpression *expr) const;
    void CheckObjectExprProps(const ir::ObjectExpression *expr, checker::PropertySearchFlags searchFlags) const;
    std::tuple<Type *, ir::Expression *> CheckAssignmentExprOperatorType(ir::AssignmentExpression *expr,
                                                                         Type *leftType) const;

private:
    ETSChecker *GetETSChecker() const;
    void CheckInstantatedClass(ir::ETSNewClassInstanceExpression *expr, ETSObjectType *&calleeObj) const;
    void CheckMethodModifiers(ir::MethodDefinition *node) const;
    checker::Signature *ResolveSignature(ETSChecker *checker, ir::CallExpression *expr, checker::Type *calleeType,
                                         bool isFunctionalInterface, bool isUnionTypeWithFunctionalInterface) const;
    checker::Type *GetReturnType(ir::CallExpression *expr, checker::Type *calleeType) const;
    checker::Type *GetFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc) const;
    checker::Type *SetAndAdjustType(ETSChecker *checker, ir::MemberExpression *expr, ETSObjectType *objectType) const;
    checker::Type *UnwrapPromiseType(checker::Type *type) const;
    bool CheckInferredFunctionReturnType(ir::ReturnStatement *st, ir::ScriptFunction *containingFunc,
                                         checker::Type *&funcReturnType, ir::TypeNode *returnTypeAnnotation,
                                         ETSChecker *checker) const;

    checker::Type *GetCalleeType(ETSChecker *checker, ir::ETSNewClassInstanceExpression *expr) const
    {
        checker::Type *calleeType = expr->GetTypeRef()->Check(checker);
        if (calleeType == nullptr) {
            return nullptr;
        }

        if (!calleeType->IsETSObjectType()) {
            checker->LogTypeError("This expression is not constructible.", expr->Start());
            return checker->GlobalTypeError();
        }

        return calleeType;
    }

    void CheckVoidTypeExpression(ETSChecker *checker, const ir::Expression *expr) const
    {
        // Existing void expression inconsistency,refer to #17762
        if (expr->TsType() == nullptr || !expr->TsType()->IsETSVoidType() || expr->Parent() == nullptr) {
            return;
        }
        auto parent = expr->Parent();
        while (parent->IsConditionalExpression()) {
            parent = parent->Parent();
            if (parent == nullptr) {
                return;
            }
        }
        bool acceptVoid = parent->IsExpressionStatement() || parent->IsReturnStatement() ||
                          parent->IsETSLaunchExpression() || parent->IsCallExpression();
        if (!acceptVoid) {
            checker->ThrowTypeError({"Cannot use type 'void' as value. "}, expr->Start());
        }
    }
};

}  // namespace ark::es2panda::checker

#endif  // ES2PANDA_CHECKER_ETSANALYZER_H
