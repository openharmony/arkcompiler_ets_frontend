/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "compiler/core/ASTVerifier.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "macros.h"
#include "parser/ETSparser.h"
#include "varbinder/ETSBinder.h"

#include <algorithm>
#include <gtest/gtest.h>

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define TREE(node)                           \
    ([&]() {                                 \
        using namespace panda::es2panda::ir; \
        return node;                         \
    }())

#define NODE(Type, ...) allocator->New<Type>(__VA_ARGS__)
#define NODES(Type, ...)                                     \
    ([&]() -> ArenaVector<Type *> {                          \
        auto v = ArenaVector<Type *> {allocator->Adapter()}; \
        v.insert(v.end(), {__VA_ARGS__});                    \
        return v;                                            \
    }())
// NOLINTEND(cppcoreguidelines-macro-usage)

namespace panda::es2panda {

class ASTVerifierTest : public testing::Test {
public:
    ASTVerifierTest()
    {
        allocator_ = std::make_unique<ArenaAllocator>(SpaceType::SPACE_TYPE_COMPILER);
    }
    ~ASTVerifierTest() override = default;

    static void SetUpTestCase()
    {
        constexpr auto COMPILER_SIZE = operator""_MB(256ULL);
        mem::MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize();
    }

    ArenaAllocator *Allocator()
    {
        return allocator_.get();
    }

    NO_COPY_SEMANTIC(ASTVerifierTest);
    NO_MOVE_SEMANTIC(ASTVerifierTest);

private:
    std::unique_ptr<ArenaAllocator> allocator_;
};

TEST_F(ASTVerifierTest, NullParent)
{
    compiler::ASTVerifier verifier {Allocator()};
    ir::StringLiteral empty_node;

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("HasParent");
    bool has_parent = verifier.Verify(&empty_node, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(has_parent, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(name, "HasParent");
    ASSERT_EQ(error.message, "NULL_PARENT: STR_LITERAL <null>");
}

TEST_F(ASTVerifierTest, NullType)
{
    compiler::ASTVerifier verifier {Allocator()};
    ir::StringLiteral empty_node;

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("HasType");
    bool has_type = verifier.Verify(&empty_node, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(has_type, false);
    ASSERT_NE(errors.size(), 0);
    ASSERT_EQ(name, "HasType");
    ASSERT_EQ(error.message, "NULL_TS_TYPE: STR_LITERAL <null>");
}

TEST_F(ASTVerifierTest, WithoutScope)
{
    compiler::ASTVerifier verifier {Allocator()};
    ir::StringLiteral empty_node;

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("HasScope");
    bool has_scope = verifier.Verify(&empty_node, checks);
    const auto &errors = verifier.GetErrors();

    ASSERT_EQ(has_scope, true);
    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeTest)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    panda::es2panda::ir::Identifier ident(panda::es2panda::util::StringView("var_decl"), Allocator());
    panda::es2panda::varbinder::LetDecl decl("test", &ident);
    panda::es2panda::varbinder::LocalVariable local(&decl, panda::es2panda::varbinder::VariableFlags::LOCAL);
    ident.SetVariable(&local);

    panda::es2panda::varbinder::LocalScope scope(Allocator(), nullptr);
    panda::es2panda::varbinder::FunctionScope parent_scope(Allocator(), nullptr);
    scope.SetParent(&parent_scope);
    scope.AddDecl(Allocator(), &decl, panda::es2panda::ScriptExtension::ETS);
    scope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("HasScope");
    bool is_ok = verifier.Verify(&ident, checks);

    ASSERT_EQ(is_ok, true);
}

TEST_F(ASTVerifierTest, ScopeNodeTest)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    panda::es2panda::ir::Identifier ident(panda::es2panda::util::StringView("var_decl"), Allocator());
    panda::es2panda::varbinder::LetDecl decl("test", &ident);
    panda::es2panda::varbinder::LocalVariable local(&decl, panda::es2panda::varbinder::VariableFlags::LOCAL);
    ident.SetVariable(&local);

    panda::es2panda::varbinder::LocalScope scope(Allocator(), nullptr);
    panda::es2panda::varbinder::FunctionScope parent_scope(Allocator(), nullptr);
    scope.SetParent(&parent_scope);
    scope.AddDecl(Allocator(), &decl, panda::es2panda::ScriptExtension::ETS);
    scope.BindNode(&ident);
    parent_scope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyScopeNode");
    bool is_ok = verifier.Verify(&ident, checks);

    ASSERT_EQ(is_ok, true);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect1)
{
    panda::es2panda::checker::ETSChecker etschecker {};
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    auto program = panda::es2panda::parser::Program::NewProgram<panda::es2panda::varbinder::ETSBinder>(Allocator());
    auto parser = panda::es2panda::parser::ETSParser(&program, panda::es2panda::CompilerOptions {});

    auto left = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {1});
    auto right = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {6});
    auto arithmetic_expression =
        panda::es2panda::ir::BinaryExpression(&left, &right, panda::es2panda::lexer::TokenType::PUNCTUATOR_PLUS);

    left.SetTsType(etschecker.GlobalIntType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("CheckArithmeticExpression");
    bool is_correct = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);
    ASSERT_EQ(is_correct, true);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect2)
{
    panda::es2panda::checker::ETSChecker etschecker {};
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    auto program = panda::es2panda::parser::Program::NewProgram<panda::es2panda::varbinder::ETSBinder>(Allocator());
    auto parser = panda::es2panda::parser::ETSParser(&program, panda::es2panda::CompilerOptions {});

    constexpr uint32_t LEFT1_PARAM = 1;
    constexpr uint32_t LEFT2_PARAM = 12;
    constexpr uint32_t RIGHT2_PARAM = 6;
    auto left1 = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {LEFT1_PARAM});
    auto left2 = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {LEFT2_PARAM});
    auto right2 = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {RIGHT2_PARAM});
    auto right1 =
        panda::es2panda::ir::BinaryExpression(&left2, &right2, panda::es2panda::lexer::TokenType::PUNCTUATOR_MULTIPLY);
    auto arithmetic_expression =
        panda::es2panda::ir::BinaryExpression(&left1, &right1, panda::es2panda::lexer::TokenType::PUNCTUATOR_PLUS);

    left1.SetTsType(etschecker.GlobalIntType());
    right1.SetTsType(etschecker.GlobalIntType());
    left2.SetTsType(etschecker.GlobalIntType());
    right2.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("CheckArithmeticExpression");
    bool is_correct = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);
    ASSERT_EQ(is_correct, true);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative1)
{
    panda::es2panda::checker::ETSChecker etschecker {};
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    auto program = panda::es2panda::parser::Program::NewProgram<panda::es2panda::varbinder::ETSBinder>(Allocator());
    auto parser = panda::es2panda::parser::ETSParser(&program, panda::es2panda::CompilerOptions {});

    const util::StringView left_param("1");
    constexpr uint32_t RIGHT_PARAM = 1;
    auto left = panda::es2panda::ir::StringLiteral(left_param);
    auto right = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {RIGHT_PARAM});
    auto arithmetic_expression =
        panda::es2panda::ir::BinaryExpression(&left, &right, panda::es2panda::lexer::TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("CheckArithmeticExpression");
    bool is_correct = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);

    ASSERT_EQ(is_correct, false);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative2)
{
    panda::es2panda::checker::ETSChecker etschecker {};
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    auto program = panda::es2panda::parser::Program::NewProgram<panda::es2panda::varbinder::ETSBinder>(Allocator());
    auto parser = panda::es2panda::parser::ETSParser(&program, panda::es2panda::CompilerOptions {});
    auto left = panda::es2panda::ir::BooleanLiteral(true);
    auto right = panda::es2panda::ir::NumberLiteral(panda::es2panda::lexer::Number {1});
    auto arithmetic_expression =
        panda::es2panda::ir::BinaryExpression(&left, &right, panda::es2panda::lexer::TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("CheckArithmeticExpression");
    bool is_correct = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);

    ASSERT_EQ(is_correct, false);
}

}  // namespace panda::es2panda
