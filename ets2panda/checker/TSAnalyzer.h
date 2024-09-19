/*
 * Copyright (c) 2021 - 2024 Huawei Device Co., Ltd.
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
#ifndef ES2PANDA_CHECKER_TSANALYZER_H
#define ES2PANDA_CHECKER_TSANALYZER_H

#include "checker/SemanticAnalyzer.h"
#include "checker/TSchecker.h"
#include "util/helpers.h"

namespace ark::es2panda::checker {

class TSAnalyzer final : public SemanticAnalyzer {
public:
    explicit TSAnalyzer(Checker *checker) : SemanticAnalyzer(checker) {};
    /* CC-OFFNXT(G.PRE.02,G.PRE.09) name part*/
    // NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_TSANALYZER_CHECK_METHOD(_, nodeType) checker::Type *Check(ir::nodeType *node) const override;
    AST_NODE_MAPPING(DECLARE_TSANALYZER_CHECK_METHOD)
#undef DECLARE_TSANALYZER_CHECK_METHOD

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_TSANALYZER_CHECK_METHOD(_, __, nodeType, ___) \
    virtual checker::Type *Check(ir::nodeType *node) const override;  // CC-OFF(G.PRE.02,G.PRE.09) name part
    AST_NODE_REINTERPRET_MAPPING(DECLARE_TSANALYZER_CHECK_METHOD)
#undef DECLARE_TSANALYZER_CHECK_METHOD

    checker::Type *CheckDeleteKeyword([[maybe_unused]] checker::TSChecker *checker, ir::UnaryExpression *expr) const;
    checker::Type *CheckLiteral([[maybe_unused]] checker::TSChecker *checker, ir::UnaryExpression *expr) const;
    checker::Type *CheckAssignmentExprOperatorType(ir::AssignmentExpression *expr, checker::Type *leftType,
                                                   checker::Type *rightType) const;
    checker::Type *CheckBinaryExprArithmLogical(ir::BinaryExpression *expr, ExpressionTypeInfo *leftRightType,
                                                TSChecker *checker) const;
    void CheckComputed(ir::MemberExpression *expr, checker::Type *indexType) const;
    void CheckSpread(std::unordered_map<util::StringView, lexer::SourcePosition> &allPropertiesMap,
                     checker::ObjectDescriptor *desc, ir::Expression *it) const;
    checker::IndexInfo *CreateUnionTypeHelper(ArenaVector<checker::Type *> &computedPropTypes,
                                              bool inConstContext) const;
    void CheckNonComputed(checker::ObjectDescriptor *desc, ir::Expression *it,
                          std::unordered_map<util::StringView, lexer::SourcePosition> &allPropertiesMap,
                          bool inConstContext) const;

private:
    TSChecker *GetTSChecker() const;

    varbinder::EnumMemberResult EvaluateBinaryExpression(checker::TSChecker *checker, varbinder::EnumVariable *enumVar,
                                                         const ir::BinaryExpression *expr) const;
    varbinder::EnumMemberResult EvaluateEnumMember(checker::TSChecker *checker, varbinder::EnumVariable *enumVar,
                                                   const ir::AstNode *expr) const;
    varbinder::EnumMemberResult EvaluateUnaryExpression(checker::TSChecker *checker, varbinder::EnumVariable *enumVar,
                                                        const ir::UnaryExpression *expr) const;
    void InferEnumVariableType(varbinder::EnumVariable *variable, double *value, bool *initNext, bool *isLiteralEnum,
                               bool isConstEnum) const;
    checker::Type *InferType(checker::TSChecker *checker, bool isConst, ir::TSEnumDeclaration *st) const;
};

}  // namespace ark::es2panda::checker

#endif  // ES2PANDA_CHECKER_TSSANALYZER_H
