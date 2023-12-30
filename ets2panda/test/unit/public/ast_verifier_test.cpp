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
#include "compiler/core/ASTVerifier.h"

#include <gtest/gtest.h>

using panda::es2panda::CompilerOptions;
using panda::es2panda::ScriptExtension;
using panda::es2panda::checker::ETSChecker;
using panda::es2panda::compiler::ASTVerifier;
using panda::es2panda::ir::AstNode;
using panda::es2panda::ir::BinaryExpression;
using panda::es2panda::ir::BooleanLiteral;
using panda::es2panda::ir::ETSScript;
using panda::es2panda::ir::Expression;
using panda::es2panda::ir::Identifier;
using panda::es2panda::ir::NumberLiteral;
using panda::es2panda::ir::SequenceExpression;
using panda::es2panda::ir::StringLiteral;
using panda::es2panda::lexer::Number;
using panda::es2panda::lexer::TokenType;
using panda::es2panda::parser::ETSParser;
using panda::es2panda::parser::Program;
using panda::es2panda::util::StringView;
using panda::es2panda::varbinder::ETSBinder;
using panda::es2panda::varbinder::FunctionScope;
using panda::es2panda::varbinder::LetDecl;
using panda::es2panda::varbinder::LocalScope;
using panda::es2panda::varbinder::LocalVariable;
using panda::es2panda::varbinder::VariableFlags;

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
    template <typename Type>
    Type *Tree(Type *node)
    {
        return node;
    }

    template <typename Type, typename... Args>
    Type *Node(Args &&...args)
    {
        return allocator_->New<Type>(std::forward<Args>(args)...);
    }

    template <typename Type, typename... Args>
    panda::ArenaVector<Type *> Nodes(Args &&...args)
    {
        auto v = panda::ArenaVector<Type *> {allocator_->Adapter()};
        v.insert(v.end(), {std::forward<Args>(args)...});
        return v;
    }

    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    panda::ArenaAllocator *allocator_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

TEST_F(ASTVerifierTest, NullParent)
{
    ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    const auto check = "NodeHasParent";
    auto checks = ASTVerifier::InvariantSet {};
    checks.insert(check);
    const auto [warnings, errors] = verifier.Verify({{"NodeHasParent"}}, {{}}, &emptyNode, checks);
    bool hasParent = warnings.empty();
    ASSERT_FALSE(hasParent);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_EQ(warnings[0].GetName(), check);
}

TEST_F(ASTVerifierTest, NullType)
{
    ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    auto check = "NodeHasType";
    auto checks = ASTVerifier::InvariantSet {};
    checks.insert(check);
    const auto [warnings, errors] = verifier.Verify({{"NodeHasType"}}, {{}}, &emptyNode, checks);
    bool hasType = warnings.empty();
    ASSERT_EQ(hasType, false);
    ASSERT_NE(warnings.size(), 0);

    ASSERT_EQ(warnings[0].GetName(), check);
}

TEST_F(ASTVerifierTest, WithoutScope)
{
    ASTVerifier verifier {Allocator()};
    StringLiteral emptyNode;

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("VariableHasScope");
    const auto [warnings, errors] = verifier.Verify({{"VariableHasScope"}}, {{}}, &emptyNode, checks);

    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeTest)
{
    ASTVerifier verifier {Allocator()};
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("VariableHasScope");
    const auto [warnings, errors] = verifier.Verify({{"VariableHasScope"}}, {{}}, &ident, checks);

    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ScopeNodeTest)
{
    ASTVerifier verifier {Allocator()};
    Identifier ident(StringView("var_decl"), Allocator());
    LetDecl decl("test", &ident);
    LocalVariable local(&decl, VariableFlags::LOCAL);
    ident.SetVariable(&local);

    LocalScope scope(Allocator(), nullptr);
    FunctionScope parentScope(Allocator(), nullptr);
    scope.SetParent(&parentScope);
    scope.AddDecl(Allocator(), &decl, ScriptExtension::ETS);
    scope.BindNode(&ident);
    parentScope.BindNode(&ident);

    local.SetScope(&scope);

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("VariableHasEnclosingScope");
    const auto [warnings, errors] = verifier.Verify({{"VariableHasEnclosingScope"}}, {{}}, &ident, checks);

    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect1)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

    auto left = NumberLiteral(Number {1});
    auto right = NumberLiteral(Number {6});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_PLUS);

    left.SetTsType(etschecker.GlobalIntType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto [warnings, errors] =
        verifier.Verify({{"ArithmeticOperationValid"}}, {{}}, arithmeticExpression.AsBinaryExpression(), checks);
    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionCorrect2)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

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

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto [warnings, errors] =
        verifier.Verify({{"ArithmeticOperationValid"}}, {{}}, arithmeticExpression.AsBinaryExpression(), checks);
    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative1)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});

    const StringView leftParam("1");
    constexpr uint32_t RIGHT_PARAM = 1;
    auto left = StringLiteral(leftParam);
    auto right = NumberLiteral(Number {RIGHT_PARAM});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto [warnings, errors] =
        verifier.Verify({{"ArithmeticOperationValid"}}, {{}}, arithmeticExpression.AsBinaryExpression(), checks);

    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, ArithmeticExpressionNegative2)
{
    ETSChecker etschecker {};
    ASTVerifier verifier {Allocator()};
    auto program = Program::NewProgram<ETSBinder>(Allocator());
    auto parser = ETSParser(&program, CompilerOptions {});
    auto left = BooleanLiteral(true);
    auto right = NumberLiteral(Number {1});
    auto arithmeticExpression = BinaryExpression(&left, &right, TokenType::PUNCTUATOR_DIVIDE);

    left.SetTsType(etschecker.GlobalETSStringLiteralType());
    right.SetTsType(etschecker.GlobalIntType());

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("ArithmeticOperationValid");
    const auto [warnings, errors] =
        verifier.Verify({{"ArithmeticOperationValid"}}, {{}}, arithmeticExpression.AsBinaryExpression(), checks);

    ASSERT_EQ(warnings.size(), 0);
}

TEST_F(ASTVerifierTest, SequenceExpressionType)
{
    ASTVerifier verifier {Allocator()};
    auto checker = ETSChecker();
    auto *last = Tree(Node<NumberLiteral>(Number {3}));
    auto *sequenceExpression = Tree(Node<SequenceExpression>(
        Nodes<Expression>(Node<NumberLiteral>(Number {1}), Node<NumberLiteral>(Number {2}), last)));

    last->SetTsType(checker.GlobalIntType());
    sequenceExpression->SetTsType(checker.GlobalIntType());

    auto checks = ASTVerifier::InvariantSet {};
    checks.insert("SequenceExpressionHasLastType");
    const auto [warnings, errors] =
        verifier.Verify({{"SequenceExpressionHasLastType"}}, {{}}, sequenceExpression, checks);

    ASSERT_EQ(warnings.size(), 0);
}

constexpr char const *PRIVATE_PROTECTED_PUBLIC_TEST =
    R"(
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
    )";

TEST_F(ASTVerifierTest, PrivateProtectedPublicAccessTestCorrect)
{
    ASTVerifier verifier {Allocator()};

    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, PRIVATE_PROTECTED_PUBLIC_TEST, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));
    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);

    ASSERT_EQ(warnings.size(), 0);
    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative1)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {
            public b: int = this.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative2)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative3)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            let a = derived.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative4)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            let a = derived.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PRIVATE);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative5)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative6)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, PrivateAccessTestNegative7)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestCorrect)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class A {
            public a: int = 1;
        }
        class B extends A {
            public b: int = this.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);

    ASSERT_EQ(warnings.size(), 0);

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative1)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        function main(): void {
            let base: Base = new Base();
            let a = base.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative2)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Derived = new Derived();
            let a = derived.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative3)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
        class Base {
            public a: int = 1;
        }
        class Derived extends Base {}
        function main(): void {
            let derived: Base = new Derived();
            let a = derived.a;
        }
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
        ->Statements()[1]
        ->AsClassDeclaration()
        ->Definition()
        ->AsClassDefinition()
        ->Body()[0]
        ->AsClassProperty()
        ->AddModifier(panda::es2panda::ir::ModifierFlags::PROTECTED);

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative4)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative5)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");
    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}

TEST_F(ASTVerifierTest, ProtectedAccessTestNegative6)
{
    ASTVerifier verifier {Allocator()};

    char const *text = R"(
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
    )";
    es2panda_Context *ctx = impl_->CreateContextFromString(cfg_, text, "dummy.ets");
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto *ast = reinterpret_cast<ETSScript *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));

    ast->AsETSScript()
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

    ASTVerifier::InvariantSet checks;
    checks.insert("ModifierAccessValidForAll");

    const auto [warnings, errors] = verifier.Verify({{"ModifierAccessValidForAll"}}, {{}}, ast, checks);
    ASSERT_EQ(warnings.size(), 1);

    ASSERT_NE(checks.find(warnings[0].GetName() + "ForAll"), checks.end());

    impl_->DestroyContext(ctx);
}
