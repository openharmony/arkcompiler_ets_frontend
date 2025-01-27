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

#include "ast_verifier_test.h"
#include "checker/ETSchecker.h"
#include "es2panda.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "macros.h"
#include "varbinder/ETSBinder.h"
#include "util/diagnosticEngine.h"

using ark::es2panda::ScriptExtension;
using ark::es2panda::checker::ETSChecker;
using ark::es2panda::compiler::ast_verifier::ArithmeticOperationValid;
using ark::es2panda::compiler::ast_verifier::NodeHasParent;
using ark::es2panda::compiler::ast_verifier::NodeHasSourceRange;
using ark::es2panda::compiler::ast_verifier::NodeHasType;
using ark::es2panda::compiler::ast_verifier::NoPrimitiveTypes;
using ark::es2panda::compiler::ast_verifier::SequenceExpressionHasLastType;
using ark::es2panda::compiler::ast_verifier::VariableHasEnclosingScope;
using ark::es2panda::compiler::ast_verifier::VariableHasScope;
using ark::es2panda::compiler::ast_verifier::VariableNameIdentifierNameSame;
using ark::es2panda::ir::BinaryExpression;
using ark::es2panda::ir::BooleanLiteral;
using ark::es2panda::ir::Expression;
using ark::es2panda::ir::Identifier;
using ark::es2panda::ir::NumberLiteral;
using ark::es2panda::ir::SequenceExpression;
using ark::es2panda::ir::StringLiteral;
using ark::es2panda::lexer::Number;
using ark::es2panda::lexer::TokenType;
using ark::es2panda::util::DiagnosticEngine;
using ark::es2panda::util::StringView;
using ark::es2panda::varbinder::FunctionScope;
using ark::es2panda::varbinder::LetDecl;
using ark::es2panda::varbinder::LocalScope;
using ark::es2panda::varbinder::LocalVariable;
using ark::es2panda::varbinder::VariableFlags;

TEST_F(ASTVerifierTest, NullParent)
{
    StringLiteral emptyNode;
    const auto &messages = VerifyNode<NodeHasParent>(&emptyNode);
    bool hasParent = messages.empty();
    ASSERT_FALSE(hasParent);
    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, NullRange)
{
    StringLiteral emptyNode;
    const auto &messages = VerifyNode<NodeHasSourceRange>(&emptyNode);
    bool hasSourceRange = messages.empty();
    ASSERT_FALSE(hasSourceRange);
    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, NullType)
{
    StringLiteral emptyNode;
    const auto &messages = VerifyNode<NodeHasType>(&emptyNode);
    bool hasType = messages.empty();
    ASSERT_EQ(hasType, false);
    ASSERT_NE(messages.size(), 0);
}

TEST_F(ASTVerifierTest, WithoutScope)
{
    StringLiteral emptyNode;
    const auto &messages = VerifyNode<VariableHasScope>(&emptyNode);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeTest)
{
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::STS);
    scope.BindNode(&ident);

    local.SetScope(&scope);

    const auto &messages = VerifyNode<VariableHasScope>(&ident);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeNodeTest)
{
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::STS);
    scope.BindNode(&ident);
    parentScope.BindNode(&ident);

    local.SetScope(&scope);

    const auto &messages = VerifyNode<VariableHasEnclosingScope>(&ident);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect1)
{
    DiagnosticEngine de {};
    ETSChecker etschecker {de};

    auto left = NumberLiteral(Number {1});
    auto right = NumberLiteral(Number {6});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_PLUS);

    left.SetTsType(etschecker.GlobalIntType());
    right.SetTsType(etschecker.GlobalIntType());

    const auto &messages = VerifyNode<ArithmeticOperationValid>(arithmeticExpression.AsBinaryExpression());
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect2)
{
    DiagnosticEngine de {};
    ETSChecker etschecker {de};

    constexpr uint32_t LEFT1_PARAM = 1;
    constexpr uint32_t LEFT2_PARAM = 12;
    constexpr uint32_t RIGHT2_PARAM = 6;
    auto left1 = NumberLiteral(Number {LEFT1_PARAM});
    auto left2 = NumberLiteral(Number {LEFT2_PARAM});
    auto right2 = NumberLiteral(Number {RIGHT2_PARAM});
    auto right1 = BinaryExpression(&left2, &right2, TokenType::PUNCTUATOR_MULTIPLY);
    auto arithmeticExpression = BinaryExpression(&left1, &right1, TokenType::PUNCTUATOR_PLUS);

    left1.SetTsType(etschecker.GlobalIntType());
    right1.SetTsType(etschecker.GlobalIntType());
    left2.SetTsType(etschecker.GlobalIntType());
    right2.SetTsType(etschecker.GlobalIntType());

    const auto &messages = VerifyNode<ArithmeticOperationValid>(arithmeticExpression.AsBinaryExpression());
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative1)
{
    DiagnosticEngine de {};
    ETSChecker etschecker {de};

    const StringView leftParam("1");
    constexpr uint32_t RIGHT_PARAM = 1;
    auto left = StringLiteral(leftParam);
    auto right = NumberLiteral(Number {RIGHT_PARAM});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    const auto &messages = VerifyNode<ArithmeticOperationValid>(arithmeticExpression.AsBinaryExpression());
    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative2)
{
    DiagnosticEngine de {};
    ETSChecker etschecker {de};

    auto left = BooleanLiteral(true);
    auto right = NumberLiteral(Number {1});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    const auto &messages = VerifyNode<ArithmeticOperationValid>(arithmeticExpression.AsBinaryExpression());
    ASSERT_EQ(messages.size(), 1);
}

TEST_F(ASTVerifierTest, PrimitiveType)
{
    DiagnosticEngine de {};
    ETSChecker etschecker {de};

    auto ast = BooleanLiteral(true);
    ast.SetTsType(etschecker.CreateETSBooleanType(true));

    auto messages = VerifyNode<NoPrimitiveTypes>(&ast);
    ASSERT_EQ(messages.size(), 1);
    std::get<NoPrimitiveTypes>(invariants_).SetNumberLoweringOccured();
    messages = VerifyNode<NoPrimitiveTypes>(&ast);
    ASSERT_EQ(messages.size(), 0);
    std::get<NoPrimitiveTypes>(invariants_).SetNumberLoweringOccured(false);
}

TEST_F(ASTVerifierTest, SequenceExpressionType)
{
    auto de = DiagnosticEngine();
    auto checker = ETSChecker(de);
    auto *last = Tree(Node<NumberLiteral>(Number {3}));
    auto *sequenceExpression = Tree(Node<SequenceExpression>(
        Nodes<Expression>(Node<NumberLiteral>(Number {1}), Node<NumberLiteral>(Number {2}), last)));

    last->SetTsType(checker.GlobalIntType());
    sequenceExpression->SetTsType(checker.GlobalIntType());

    const auto &messages = VerifyNode<SequenceExpressionHasLastType>(sequenceExpression);
    ASSERT_EQ(messages.size(), 0);
}

TEST_F(ASTVerifierTest, VariableNameIdentifierNameSameNegative)
{
    char const *text = R"(
        function main(): void {
            let tmp = 1;
            let lambda2: (value: int) => Int = (value: int): Int => {
                let a = 42;
                let num: Int = new Int(a + value);
                return num;
            }
            let n_tmp = tmp + 2;
            return 1;
        }
    )";

    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, text, "dummy.sts", ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<ark::es2panda::ir::ETSModule>(impl_, ctx);

    // Note(@kirillbychkov): Change Identifier name in variable lambda2
    ast->AsETSModule()
        ->Statements()[0]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[1]
        ->AsClassElement()
        ->Value()
        ->AsFunctionExpression()
        ->Function()
        ->AsScriptFunction()
        ->Body()
        ->AsBlockStatement()
        ->Statements()[1]
        ->AsVariableDeclaration()
        ->Declarators()[0]
        ->AsVariableDeclarator()
        ->Id()
        ->AsIdentifier()
        ->SetName("not_name");

    const auto &messages = Verify<VariableNameIdentifierNameSame>(ast);
    ASSERT_EQ(messages.size(), 1);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, VariableNameIdentifierNameSame)
{
    char const *text = R"(
        function main(): void {
            let tmp = 1;
            let lambda2: (value: int) => Int = (value: int): Int => {
                let a = 42;
                let num: Int = new Int(a + value);
                return num;
            }
            let n_tmp = tmp + 2;
            return 1;
        }
    )";

    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, text, "dummy.sts", ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<ark::es2panda::ir::ETSModule>(impl_, ctx);
    const auto &messages = Verify<VariableNameIdentifierNameSame>(ast);
    ASSERT_EQ(messages.size(), 0);
    impl_->DestroyContext(ctx);
}
