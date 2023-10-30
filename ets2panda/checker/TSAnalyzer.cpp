/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include "TSAnalyzer.h"

#include "checker/TSchecker.h"
#include "checker/ts/destructuringContext.h"

namespace panda::es2panda::checker {

TSChecker *TSAnalyzer::GetTSChecker() const
{
    return static_cast<TSChecker *>(GetChecker());
}

// from as folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::NamedType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::PrefixAssertionExpression *expr) const
{
    UNREACHABLE();
}
// from base folder
checker::Type *TSAnalyzer::Check(ir::CatchClause *st) const
{
    TSChecker *checker = GetTSChecker();
    ir::Expression *type_annotation = st->Param()->AsAnnotatedExpression()->TypeAnnotation();

    if (type_annotation != nullptr) {
        checker::Type *catch_param_type = type_annotation->Check(checker);

        if (!catch_param_type->HasTypeFlag(checker::TypeFlag::ANY_OR_UNKNOWN)) {
            checker->ThrowTypeError("Catch clause variable type annotation must be 'any' or 'unknown' if specified",
                                    st->Start());
        }
    }

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassDefinition *node) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassProperty *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassStaticBlock *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::Decorator *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::MetaProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::MethodDefinition *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::Property *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ScriptFunction *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::SpreadElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TemplateElement *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSIndexSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSMethodSignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSPropertySignature *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSSignatureDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}
// from ets folder
checker::Type *TSAnalyzer::Check(ir::ETSClassLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSImportDeclaration *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSLaunchExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSNewArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSNewClassInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSPackageDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSParameterExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSPrimitiveType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSStructDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSTypeReference *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSTypeReferencePart *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ETSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSWildcardType *node) const
{
    UNREACHABLE();
}
// compile methods for EXPRESSIONS in alphabetical order
checker::Type *TSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ArrowFunctionExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    varbinder::Variable *func_var = nullptr;

    if (expr->Function()->Parent()->Parent() != nullptr &&
        expr->Function()->Parent()->Parent()->IsVariableDeclarator() &&
        expr->Function()->Parent()->Parent()->AsVariableDeclarator()->Id()->IsIdentifier()) {
        func_var = expr->Function()->Parent()->Parent()->AsVariableDeclarator()->Id()->AsIdentifier()->Variable();
    }

    checker::ScopeContext scope_ctx(checker, expr->Function()->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(expr->Function()->Params(), signature_info);

    auto *signature = checker->Allocator()->New<checker::Signature>(
        signature_info, checker->GlobalResolvingReturnType(), expr->Function());
    checker::Type *func_type = checker->CreateFunctionTypeWithSignature(signature);

    if (func_var != nullptr && func_var->TsType() == nullptr) {
        func_var->SetTsType(func_type);
    }

    signature->SetReturnType(checker->HandleFunctionReturn(expr->Function()));

    if (!expr->Function()->Body()->IsExpression()) {
        expr->Function()->Body()->Check(checker);
    }

    return func_type;
}

checker::Type *TSAnalyzer::Check(ir::AssignmentExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::AwaitExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BlockExpression *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::CallExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ChainExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ClassExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::DirectEvalExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::FunctionExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::Identifier *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ImportExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::MemberExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::NewExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::OmittedExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::OpaqueTypeNode *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::SequenceExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::SuperExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TaggedTemplateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TemplateLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ThisExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::UpdateExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::YieldExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
checker::Type *TSAnalyzer::Check(ir::BigIntLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BooleanLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::CharLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::NullLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::NumberLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::RegExpLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::StringLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::UndefinedLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *TSAnalyzer::Check(ir::ExportAllDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ExportDefaultDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ExportNamedDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ExportSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ImportDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ImportDefaultSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ImportNamespaceSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ImportSpecifier *st) const
{
    (void)st;
    UNREACHABLE();
}
// compile methods for STATEMENTS in alphabetical order
checker::Type *TSAnalyzer::Check(ir::AssertStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BlockStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BreakStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ClassDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ContinueStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::DebuggerStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::DoWhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::EmptyStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ExpressionStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ForInStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ForOfStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::FunctionDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::IfStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::LabelledStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ReturnStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    ir::AstNode *ancestor = util::Helpers::FindAncestorGivenByType(st, ir::AstNodeType::SCRIPT_FUNCTION);
    ASSERT(ancestor && ancestor->IsScriptFunction());
    auto *containing_func = ancestor->AsScriptFunction();

    if (containing_func->Parent()->Parent()->IsMethodDefinition()) {
        const ir::MethodDefinition *containing_class_method = containing_func->Parent()->Parent()->AsMethodDefinition();
        if (containing_class_method->Kind() == ir::MethodDefinitionKind::SET) {
            checker->ThrowTypeError("Setters cannot return a value", st->Start());
        }
    }

    if (containing_func->ReturnTypeAnnotation() != nullptr) {
        checker::Type *return_type = checker->GlobalUndefinedType();
        checker::Type *func_return_type = containing_func->ReturnTypeAnnotation()->GetType(checker);

        if (st->Argument() != nullptr) {
            checker->ElaborateElementwise(func_return_type, st->Argument(), st->Start());
            return_type = checker->CheckTypeCached(st->Argument());
        }

        checker->IsTypeAssignableTo(return_type, func_return_type,
                                    {"Type '", return_type, "' is not assignable to type '", func_return_type, "'."},
                                    st->Start());
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::SwitchCaseStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::SwitchStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ThrowStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TryStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::VariableDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::WhileStatement *st) const
{
    (void)st;
    UNREACHABLE();
}
// from ts folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSAnyKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSArrayType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSBigintKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSBooleanKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSClassImplements *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSConditionalType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSConstructorType *node) const
{
    (void)node;
    UNREACHABLE();
}

static varbinder::EnumMemberResult EvaluateIdentifier(checker::TSChecker *checker, varbinder::EnumVariable *enum_var,
                                                      const ir::Identifier *expr)
{
    if (expr->Name() == "NaN") {
        return std::nan("");
    }
    if (expr->Name() == "Infinity") {
        return std::numeric_limits<double>::infinity();
    }

    varbinder::Variable *enum_member = expr->AsIdentifier()->Variable();

    if (enum_member == nullptr) {
        checker->ThrowTypeError({"Cannot find name ", expr->AsIdentifier()->Name()},
                                enum_var->Declaration()->Node()->Start());
    }

    if (enum_member->IsEnumVariable()) {
        varbinder::EnumVariable *expr_enum_var = enum_member->AsEnumVariable();
        if (std::holds_alternative<bool>(expr_enum_var->Value())) {
            checker->ThrowTypeError(
                "A member initializer in a enum declaration cannot reference members declared after it, "
                "including "
                "members defined in other enums.",
                enum_var->Declaration()->Node()->Start());
        }

        return expr_enum_var->Value();
    }

    return false;
}

static int32_t ToInt(double num)
{
    if (num >= std::numeric_limits<int32_t>::min() && num <= std::numeric_limits<int32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

static uint32_t ToUInt(double num)
{
    if (num >= std::numeric_limits<uint32_t>::min() && num <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

varbinder::EnumMemberResult TSAnalyzer::EvaluateBinaryExpression(checker::TSChecker *checker,
                                                                 varbinder::EnumVariable *enum_var,
                                                                 const ir::BinaryExpression *expr) const
{
    varbinder::EnumMemberResult left = EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Left());
    varbinder::EnumMemberResult right = EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Right());
    if (std::holds_alternative<double>(left) && std::holds_alternative<double>(right)) {
        switch (expr->AsBinaryExpression()->OperatorType()) {
            case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
                return static_cast<double>(ToUInt(std::get<double>(left)) | ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
                return static_cast<double>(ToUInt(std::get<double>(left)) & ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_BITWISE_XOR: {
                return static_cast<double>(ToUInt(std::get<double>(left)) ^ ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT: {  // NOLINTNEXTLINE(hicpp-signed-bitwise)
                return static_cast<double>(ToInt(std::get<double>(left)) << ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT: {  // NOLINTNEXTLINE(hicpp-signed-bitwise)
                return static_cast<double>(ToInt(std::get<double>(left)) >> ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT: {
                return static_cast<double>(ToUInt(std::get<double>(left)) >> ToUInt(std::get<double>(right)));
            }
            case lexer::TokenType::PUNCTUATOR_PLUS: {
                return std::get<double>(left) + std::get<double>(right);
            }
            case lexer::TokenType::PUNCTUATOR_MINUS: {
                return std::get<double>(left) - std::get<double>(right);
            }
            case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
                return std::get<double>(left) * std::get<double>(right);
            }
            case lexer::TokenType::PUNCTUATOR_DIVIDE: {
                return std::get<double>(left) / std::get<double>(right);
            }
            case lexer::TokenType::PUNCTUATOR_MOD: {
                return std::fmod(std::get<double>(left), std::get<double>(right));
            }
            case lexer::TokenType::PUNCTUATOR_EXPONENTIATION: {
                return std::pow(std::get<double>(left), std::get<double>(right));
            }
            default: {
                break;
            }
        }

        return false;
    }

    if (std::holds_alternative<util::StringView>(left) && std::holds_alternative<util::StringView>(right) &&
        expr->AsBinaryExpression()->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS) {
        std::stringstream ss;
        ss << std::get<util::StringView>(left) << std::get<util::StringView>(right);

        util::UString res(ss.str(), checker->Allocator());
        return res.View();
    }

    return false;
}

varbinder::EnumMemberResult TSAnalyzer::EvaluateUnaryExpression(checker::TSChecker *checker,
                                                                varbinder::EnumVariable *enum_var,
                                                                const ir::UnaryExpression *expr) const
{
    varbinder::EnumMemberResult value = EvaluateEnumMember(checker, enum_var, expr->Argument());
    if (!std::holds_alternative<double>(value)) {
        return false;
    }

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            return std::get<double>(value);
        }
        case lexer::TokenType::PUNCTUATOR_MINUS: {
            return -std::get<double>(value);
        }
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            return static_cast<double>(~ToInt(std::get<double>(value)));  // NOLINT(hicpp-signed-bitwise)
        }
        default: {
            break;
        }
    }

    return false;
}

varbinder::EnumMemberResult TSAnalyzer::EvaluateEnumMember(checker::TSChecker *checker,
                                                           varbinder::EnumVariable *enum_var,
                                                           const ir::AstNode *expr) const
{
    switch (expr->Type()) {
        case ir::AstNodeType::UNARY_EXPRESSION: {
            return EvaluateUnaryExpression(checker, enum_var, expr->AsUnaryExpression());
        }
        case ir::AstNodeType::BINARY_EXPRESSION: {
            return EvaluateBinaryExpression(checker, enum_var, expr->AsBinaryExpression());
        }
        case ir::AstNodeType::NUMBER_LITERAL: {
            return expr->AsNumberLiteral()->Number().GetDouble();
        }
        case ir::AstNodeType::STRING_LITERAL: {
            return expr->AsStringLiteral()->Str();
        }
        case ir::AstNodeType::IDENTIFIER: {
            return EvaluateIdentifier(checker, enum_var, expr->AsIdentifier());
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            return EvaluateEnumMember(checker, enum_var, expr->AsMemberExpression());
        }
        default:
            break;
    }

    return false;
}

static bool IsComputedEnumMember(const ir::Expression *init)
{
    if (init->IsLiteral()) {
        return !init->AsLiteral()->IsStringLiteral() && !init->AsLiteral()->IsNumberLiteral();
    }

    if (init->IsTemplateLiteral()) {
        return !init->AsTemplateLiteral()->Quasis().empty();
    }

    return true;
}

static void AddEnumValueDeclaration(checker::TSChecker *checker, double number, varbinder::EnumVariable *variable)
{
    variable->SetTsType(checker->GlobalNumberType());

    util::StringView member_str = util::Helpers::ToStringView(checker->Allocator(), number);

    varbinder::LocalScope *enum_scope = checker->Scope()->AsLocalScope();
    varbinder::Variable *res = enum_scope->FindLocal(member_str, varbinder::ResolveBindingOptions::BINDINGS);
    varbinder::EnumVariable *enum_var = nullptr;

    if (res == nullptr) {
        auto *decl = checker->Allocator()->New<varbinder::EnumDecl>(member_str);
        decl->BindNode(variable->Declaration()->Node());
        enum_scope->AddDecl(checker->Allocator(), decl, ScriptExtension::TS);
        res = enum_scope->FindLocal(member_str, varbinder::ResolveBindingOptions::BINDINGS);
        ASSERT(res && res->IsEnumVariable());
        enum_var = res->AsEnumVariable();
        enum_var->AsEnumVariable()->SetBackReference();
        enum_var->SetTsType(checker->GlobalStringType());
    } else {
        ASSERT(res->IsEnumVariable());
        enum_var = res->AsEnumVariable();
        auto *decl = checker->Allocator()->New<varbinder::EnumDecl>(member_str);
        decl->BindNode(variable->Declaration()->Node());
        enum_var->ResetDecl(decl);
    }

    enum_var->SetValue(variable->Declaration()->Name());
}

void TSAnalyzer::InferEnumVariableType(checker::TSChecker *checker, varbinder::EnumVariable *variable, double *value,
                                       bool *init_next, bool *is_literal_enum, bool is_const_enum,
                                       const ir::Expression *computed_expr) const
{
    const ir::Expression *init = variable->Declaration()->Node()->AsTSEnumMember()->Init();

    if (init == nullptr && *init_next) {
        checker->ThrowTypeError("Enum member must have initializer.", variable->Declaration()->Node()->Start());
    }

    if (init == nullptr && !*init_next) {
        variable->SetValue(++(*value));
        AddEnumValueDeclaration(checker, *value, variable);
        return;
    }

    ASSERT(init);

    if (IsComputedEnumMember(init)) {
        if (*is_literal_enum) {
            checker->ThrowTypeError("Computed values are not permitted in an enum with string valued members.",
                                    init->Start());
        }

        computed_expr = init;
    }

    varbinder::EnumMemberResult res = EvaluateEnumMember(checker, variable, init);
    if (std::holds_alternative<util::StringView>(res)) {
        if (computed_expr != nullptr) {
            checker->ThrowTypeError("Computed values are not permitted in an enum with string valued members.",
                                    computed_expr->Start());
        }

        *is_literal_enum = true;
        variable->SetTsType(checker->GlobalStringType());
        *init_next = true;
        return;
    }

    if (std::holds_alternative<bool>(res)) {
        if (is_const_enum) {
            checker->ThrowTypeError(
                "const enum member initializers can only contain literal values and other computed enum "
                "values.",
                init->Start());
        }

        *init_next = true;
        return;
    }

    ASSERT(std::holds_alternative<double>(res));
    variable->SetValue(res);

    *value = std::get<double>(res);
    if (is_const_enum) {
        if (std::isnan(*value)) {
            checker->ThrowTypeError("'const' enum member initializer was evaluated to disallowed value 'NaN'.",
                                    init->Start());
        }

        if (std::isinf(*value)) {
            checker->ThrowTypeError("'const' enum member initializer was evaluated to a non-finite value.",
                                    init->Start());
        }
    }

    *init_next = false;
    AddEnumValueDeclaration(checker, *value, variable);
}

checker::Type *TSAnalyzer::InferType(checker::TSChecker *checker, bool is_const, ir::TSEnumDeclaration *st) const
{
    double value = -1.0;

    varbinder::LocalScope *enum_scope = checker->Scope()->AsLocalScope();

    bool init_next = false;
    bool is_literal_enum = false;
    const ir::Expression *computed_expr = nullptr;
    size_t locals_size = enum_scope->Decls().size();

    for (size_t i = 0; i < locals_size; i++) {
        const util::StringView &current_name = enum_scope->Decls()[i]->Name();
        varbinder::Variable *current_var =
            enum_scope->FindLocal(current_name, varbinder::ResolveBindingOptions::BINDINGS);
        ASSERT(current_var && current_var->IsEnumVariable());
        InferEnumVariableType(checker, current_var->AsEnumVariable(), &value, &init_next, &is_literal_enum, is_const,
                              computed_expr);
    }

    checker::Type *enum_type = checker->Allocator()->New<checker::EnumLiteralType>(
        st->Key()->Name(), checker->Scope(),
        is_literal_enum ? checker::EnumLiteralType::EnumLiteralTypeKind::LITERAL
                        : checker::EnumLiteralType::EnumLiteralTypeKind::NUMERIC);

    return enum_type;
}

checker::Type *TSAnalyzer::Check(ir::TSEnumDeclaration *st) const
{
    TSChecker *checker = GetTSChecker();
    varbinder::Variable *enum_var = st->Key()->Variable();
    ASSERT(enum_var);

    if (enum_var->TsType() == nullptr) {
        checker::ScopeContext scope_ctx(checker, st->Scope());
        checker::Type *enum_type = InferType(checker, st->IsConst(), st);
        enum_type->SetVariable(enum_var);
        enum_var->SetTsType(enum_type);
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSEnumMember *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSExternalModuleReference *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSFunctionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSImportEqualsDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSImportType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSIndexedAccessType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSInferType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSInterfaceBody *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSInterfaceHeritage *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSIntersectionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSLiteralType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSMappedType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSModuleBlock *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSModuleDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSNamedTupleMember *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSNeverKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSNonNullExpression *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSNullKeyword *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNumberKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSParameterProperty *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSParenthesizedType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSQualifiedName *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSStringKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSThisType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTupleType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeAssertion *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeLiteral *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeOperator *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeParameter *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeParameterDeclaration *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeParameterInstantiation *expr) const
{
    (void)expr;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypePredicate *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeQuery *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeReference *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSUndefinedKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSUnionType *node) const
{
    (void)node;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSUnknownKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSVoidKeyword *node) const
{
    return nullptr;
}

}  // namespace panda::es2panda::checker
