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
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "macros.h"
#include "parser/ETSparser.h"
#include "varbinder/ETSBinder.h"
#include "utils/json_builder.h"
#include <regex>
#include "compiler/core/ASTVerifier.h"

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

class ASTVerifierTest : public testing::Test {
public:
    ASTVerifierTest()
    {
        impl_ = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        char const *argv[] = {"../../../bin/es2panda test"};
        cfg_ = impl_->CreateConfig(1, argv);
        allocator_ = new panda::ArenaAllocator(panda::SpaceType::SPACE_TYPE_COMPILER);
    }
    ~ASTVerifierTest() override
    {
        delete allocator_;
        impl_->DestroyConfig(cfg_);
    }

    panda::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

    NO_COPY_SEMANTIC(ASTVerifierTest);
    NO_MOVE_SEMANTIC(ASTVerifierTest);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    panda::ArenaAllocator *allocator_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

static void CompareMinified(std::string_view actualJson, std::string_view expectedJson)
{
    std::string message {actualJson};
    static const std::regex R {R"(\s+)"};
    auto ss = std::stringstream {};

    std::regex_replace(std::ostream_iterator<char>(ss), message.begin(), message.end(), r, "");
    ASSERT_EQ(ss.str(), expectedJson);
}

TEST_F(ASTVerifierTest, NullParent)
{
    compiler::ASTVerifier verifier {Allocator()};
    panda::es2panda::ir::StringLiteral emptyNode;

    const auto check = "NodeHasParent";
    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert(check);
    const auto &errors = verifier.Verify(&empty_node, checks);
    bool hasParent = errors.size() == 0;
    ASSERT_EQ(hasParent, false);
    ASSERT_EQ(errors.size(), 1);

    const auto [name, error] = errors[0];
    ASSERT_EQ(name, check);
    auto messageExpected = JsonObjectBuilder {};
    message_expected.AddProperty("type", "StringLiteral");
    message_expected.AddProperty("value", "");
    compare_minified(error.message, std::move(message_expected).Build());
}

TEST_F(ASTVerifierTest, NullType)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    panda::es2panda::ir::StringLiteral emptyNode;

    auto check = "NodeHasType";
    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert(check);
    const auto &errors = verifier.Verify(&empty_node, checks);
    bool hasType = errors.size() == 0;
    ASSERT_EQ(hasType, false);
    ASSERT_NE(errors.size(), 0);

    const auto [name, error] = errors[0];
    ASSERT_EQ(name, check);

    auto messageExpected = JsonObjectBuilder {};
    message_expected.AddProperty("type", "StringLiteral");
    message_expected.AddProperty("value", "");
    compare_minified(error.message, std::move(message_expected).Build());
}

TEST_F(ASTVerifierTest, WithoutScope)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};
    panda::es2panda::ir::StringLiteral emptyNode;

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("VariableHasScope");
    const auto &errors = verifier.Verify(&empty_node, checks);

    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeTest)
{
    compiler::ASTVerifier verifier {Allocator()};
    ir::Identifier ident(util::StringView("var_decl"), Allocator());
    varbinder::LetDecl decl("test", &ident);
    varbinder::LocalVariable local(&decl, varbinder::VariableFlags::LOCAL);
    ident.SetVariable(&local);

    varbinder::LocalScope scope(Allocator(), nullptr);
    varbinder::FunctionScope parent_scope(Allocator(), nullptr);
    scope.SetParent(&parent_scope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("VariableHasScope");
    const auto &errors = verifier.Verify(&ident, checks);

    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeNodeTest)
{
    compiler::ASTVerifier verifier {Allocator()};
    ir::Identifier ident(util::StringView("var_decl"), Allocator());
    varbinder::LetDecl decl("test", &ident);
    varbinder::LocalVariable local(&decl, varbinder::VariableFlags::LOCAL);
    ident.SetVariable(&local);

    varbinder::LocalScope scope(Allocator(), nullptr);
    varbinder::FunctionScope parent_scope(Allocator(), nullptr);
    scope.SetParent(&parent_scope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);
    parentScope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("VariableHasEnclosingScope");
    const auto &errors = verifier.Verify(&ident, checks);

    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect1)
{
    checker::ETSChecker etschecker {};
    compiler::ASTVerifier verifier {Allocator()};
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    auto parser = parser::ETSParser(&program, CompilerOptions {});

    auto left = ir::NumberLiteral(lexer::Number {1});
    auto right = ir::NumberLiteral(lexer::Number {6});
    auto arithmeticExpression = ir::BinaryExpression(&left, &right, lexer::TokenType::PUNCTUATOR_PLUS);

    left.SetTsType(etschecker.GlobalIntType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &errors = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);
    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect2)
{
    checker::ETSChecker etschecker {};
    compiler::ASTVerifier verifier {Allocator()};
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    auto parser = parser::ETSParser(&program, CompilerOptions {});

    constexpr uint32_t LEFT1_PARAM = 1;
    constexpr uint32_t LEFT2_PARAM = 12;
    constexpr uint32_t RIGHT2_PARAM = 6;
    auto left1 = ir::NumberLiteral(lexer::Number {LEFT1_PARAM});
    auto left2 = ir::NumberLiteral(lexer::Number {LEFT2_PARAM});
    auto right2 = ir::NumberLiteral(lexer::Number {RIGHT2_PARAM});
    auto right1 = ir::BinaryExpression(&left2, &right2, lexer::TokenType::PUNCTUATOR_MULTIPLY);
    auto arithmeticExpression = ir::BinaryExpression(&left1, &right1, lexer::TokenType::PUNCTUATOR_PLUS);

    left1.SetTsType(etschecker.GlobalIntType());
    right1.SetTsType(etschecker.GlobalIntType());
    left2.SetTsType(etschecker.GlobalIntType());
    right2.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &errors = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);
    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative1)
{
    checker::ETSChecker etschecker {};
    compiler::ASTVerifier verifier {Allocator()};
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    auto parser = parser::ETSParser(&program, CompilerOptions {});

    const panda::es2panda::util::StringView leftParam("1");
    constexpr uint32_t RIGHT_PARAM = 1;
    auto left = ir::StringLiteral(left_param);
    auto right = ir::NumberLiteral(lexer::Number {RIGHT_PARAM});
    auto arithmeticExpression = ir::BinaryExpression(&left, &right, lexer::TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &errors = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);

    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative2)
{
    checker::ETSChecker etschecker {};
    compiler::ASTVerifier verifier {Allocator()};
    auto program = parser::Program::NewProgram<varbinder::ETSBinder>(Allocator());
    auto parser = parser::ETSParser(&program, CompilerOptions {});
    auto left = ir::BooleanLiteral(true);
    auto right = ir::NumberLiteral(lexer::Number {1});
    auto arithmeticExpression = ir::BinaryExpression(&left, &right, lexer::TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto &errors = verifier.Verify(arithmetic_expression.AsBinaryExpression(), checks);

    ASSERT_EQ(errors.size(), 0);
}

TEST_F(ASTVerifierTest, SequenceExpressionType)
{
    compiler::ASTVerifier verifier {Allocator()};
    auto *allocator = Allocator();

    auto checker = checker::ETSChecker();

    auto *last = TREE(NODE(NumberLiteral, lexer::Number {3}));
    // clang-format off
    auto *sequenceExpression =
        TREE(NODE(SequenceExpression,
                  NODES(Expression,
                        NODE(NumberLiteral, lexer::Number {1}),
                        NODE(NumberLiteral, lexer::Number {2}),
                        last
                        )));
    // clang-format on

    last->SetTsType(checker.GlobalIntType());
    sequence_expression->SetTsType(checker.GlobalIntType());

    auto checks = compiler::ASTVerifier::InvariantSet {};
    checks.insert("SequenceExpressionHasLastType");
    const auto &errors = verifier.Verify(sequence_expression, checks);

    ASSERT_EQ(errors.size(), 0);
}

constexpr char const *PRIVATE_PROTECTED_PUBLIC_TEST =
    R"XXX(
        class Base {
            public a: int = 1;
            protected b: int = 2;
            private c: int = 3;
            public publicMethod() {
                this.a = 4;
                this.protectedMethod();
                this.privateMethod();
            }
            protected protectedMethod() {
                this.b = 5;
                this.publicMethod();
                this.privateMethod();
            }
            private privateMethod() {
                this.c = 6;
                this.publicMethod();
                this.protectedMethod();
            }
        }
        class Derived extends Base {
            foo () {
                this.a = 7;
                this.b = 8;
                this.publicMethod();
                this.protectedMethod();
            }
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
            base.publicMethod();
            let derived1: Derived = new Derived();
            let b = derived1.a;
            derived1.publicMethod();
            derived1.foo();
            let derived2: Base = new Derived();
            let c = derived2.a;
            derived2.publicMethod();
        }
    )XXX";

TEST_F(ASTVerifierTest, PrivateProtectedPublicAccessTestCorrect)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, PRIVATE_PROTECTED_PUBLIC_TEST, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));
    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();

    ASSERT_EQ(isCorrect, true);
    ASSERT_EQ(errors.size(), 0);
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative1)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {
            public b: int = this.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR MUST BE UNREACHABLE.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative2)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID base.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative3)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            let a = derived.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative4)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            let a = derived.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative5)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public privateMethod() {
                this.a = 2;
            }
        }
        function main(): void {
            let base: Base = new Base();
            base.privateMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID base.ID privateMethod");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative6)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public privateMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            derived.privateMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID privateMethod");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative7)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public privateMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            derived.privateMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PRIVATE);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID privateMethod");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestCorrect)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class A {
            public a: int = 1;
        }
        class B extends A {
            public b: int = this.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();

    ASSERT_EQ(isCorrect, true);
    ASSERT_EQ(errors.size(), 0);
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative1)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID base.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative2)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            let a = derived.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative3)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            let a = derived.a;
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID a");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative4)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        function main(): void {
            let base: Base = new Base();
            base.protectedMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID base.ID protectedMethod");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative5)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            derived.protectedMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID protectedMethod");
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative6)
{
    panda::es2panda::compiler::ASTVerifier verifier {Allocator()};

    char const *text = R"XXX(
        class Base {
            public a: int = 1;
            public protectedMethod() {
                this.a = 2;
            }
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            derived.protectedMethod();
        }
    )XXX";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<panda::es2panda::ir::ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsBlockStatement()
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
        ->AsExpressionStatement()
        ->GetExpression()
        ->AsCallExpression()
        ->Signature()
        ->AddSignatureFlag(panda::es2panda::checker::SignatureFlags::PROTECTED);

    auto checks = panda::es2panda::compiler::ASTVerifier::CheckSet {Allocator()->Adapter()};
    checks.insert("VerifyModifierAccessRecursive");
    bool isCorrect = verifier.Verify(ast, checks);
    const auto &errors = verifier.GetErrors();
    const auto [name, error] = errors[0];

    ASSERT_EQ(isCorrect, false);
    ASSERT_EQ(errors.size(), 1);
    ASSERT_EQ(error.message, "PROPERTY_NOT_VISIBLE_HERE: MEMBER_EXPR ID derived.ID protectedMethod");
    impl_->DestroyContext(ctx);
}
