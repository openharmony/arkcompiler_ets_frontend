/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "tsEnumDeclaration.h"

#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/base/methodDefinition.h"
#include "plugins/ecmascript/es2panda/ir/expressions/memberExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/unaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/binaryExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/templateLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumMember.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"

namespace panda::es2panda::ir {
void TSEnumDeclaration::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(key_);

    for (auto *it : members_) {
        cb(it);
    }
}

void TSEnumDeclaration::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSEnumDeclaration"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"id", key_},
                 {"members", members_},
                 {"const", is_const_}});
}

void TSEnumDeclaration::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

int32_t ToInt(double num)
{
    if (num >= std::numeric_limits<int32_t>::min() && num <= std::numeric_limits<int32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

uint32_t ToUInt(double num)
{
    if (num >= std::numeric_limits<uint32_t>::min() && num <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // TODO(aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

binder::EnumMemberResult EvaluateIdentifier(checker::TSChecker *checker, binder::EnumVariable *enum_var,
                                            const ir::Identifier *expr)
{
    if (expr->Name() == "NaN") {
        return std::nan("");
    }
    if (expr->Name() == "Infinity") {
        return std::numeric_limits<double>::infinity();
    }

    binder::Variable *enum_member = expr->AsIdentifier()->Variable();

    if (enum_member == nullptr) {
        checker->ThrowTypeError({"Cannot find name ", expr->AsIdentifier()->Name()},
                                enum_var->Declaration()->Node()->Start());
    }

    if (enum_member->IsEnumVariable()) {
        binder::EnumVariable *expr_enum_var = enum_member->AsEnumVariable();
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

binder::EnumMemberResult EvaluateUnaryExpression(checker::TSChecker *checker, binder::EnumVariable *enum_var,
                                                 const ir::UnaryExpression *expr)
{
    binder::EnumMemberResult value = TSEnumDeclaration::EvaluateEnumMember(checker, enum_var, expr->Argument());
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

binder::EnumMemberResult EvaluateMemberExpression(checker::TSChecker *checker,
                                                  [[maybe_unused]] binder::EnumVariable *enum_var,
                                                  ir::MemberExpression *expr)
{
    if (checker::TSChecker::IsConstantMemberAccess(expr->AsExpression())) {
        if (expr->Check(checker)->TypeFlags() == checker::TypeFlag::ENUM) {
            util::StringView name;
            if (!expr->IsComputed()) {
                name = expr->Property()->AsIdentifier()->Name();
            } else {
                ASSERT(checker::TSChecker::IsStringLike(expr->Property()));
                name = reinterpret_cast<const ir::StringLiteral *>(expr->Property())->Str();
            }

            // TODO(aszilagyi)
        }
    }

    return false;
}

binder::EnumMemberResult EvaluateBinaryExpression(checker::TSChecker *checker, binder::EnumVariable *enum_var,
                                                  const ir::BinaryExpression *expr)
{
    binder::EnumMemberResult left =
        TSEnumDeclaration::EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Left());
    binder::EnumMemberResult right =
        TSEnumDeclaration::EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Right());
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

binder::EnumMemberResult TSEnumDeclaration::EvaluateEnumMember(checker::TSChecker *checker,
                                                               binder::EnumVariable *enum_var, const ir::AstNode *expr)
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

bool IsComputedEnumMember(const ir::Expression *init)
{
    if (init->IsLiteral()) {
        return !init->AsLiteral()->IsStringLiteral() && !init->AsLiteral()->IsNumberLiteral();
    }

    if (init->IsTemplateLiteral()) {
        return !init->AsTemplateLiteral()->Quasis().empty();
    }

    return true;
}

void AddEnumValueDeclaration(checker::TSChecker *checker, double number, binder::EnumVariable *variable)
{
    variable->SetTsType(checker->GlobalNumberType());

    util::StringView member_str = util::Helpers::ToStringView(checker->Allocator(), number);

    binder::LocalScope *enum_scope = checker->Scope()->AsLocalScope();
    binder::Variable *res = enum_scope->FindLocal(member_str);
    binder::EnumVariable *enum_var = nullptr;

    if (res == nullptr) {
        auto *decl = checker->Allocator()->New<binder::EnumDecl>(member_str);
        decl->BindNode(variable->Declaration()->Node());
        enum_scope->AddDecl(checker->Allocator(), decl, ScriptExtension::TS);
        res = enum_scope->FindLocal(member_str);
        ASSERT(res && res->IsEnumVariable());
        enum_var = res->AsEnumVariable();
        enum_var->AsEnumVariable()->SetBackReference();
        enum_var->SetTsType(checker->GlobalStringType());
    } else {
        ASSERT(res->IsEnumVariable());
        enum_var = res->AsEnumVariable();
        auto *decl = checker->Allocator()->New<binder::EnumDecl>(member_str);
        decl->BindNode(variable->Declaration()->Node());
        enum_var->ResetDecl(decl);
    }

    enum_var->SetValue(variable->Declaration()->Name());
}

void InferEnumVariableType(checker::TSChecker *checker, binder::EnumVariable *variable, double *value, bool *init_next,
                           bool *is_literal_enum, bool is_const_enum, const ir::Expression *computed_expr)
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

    binder::EnumMemberResult res = TSEnumDeclaration::EvaluateEnumMember(checker, variable, init);
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

checker::Type *TSEnumDeclaration::InferType(checker::TSChecker *checker, bool is_const) const
{
    double value = -1.0;

    binder::LocalScope *enum_scope = checker->Scope()->AsLocalScope();

    bool init_next = false;
    bool is_literal_enum = false;
    const ir::Expression *computed_expr = nullptr;
    size_t locals_size = enum_scope->Decls().size();

    for (size_t i = 0; i < locals_size; i++) {
        const util::StringView &current_name = enum_scope->Decls()[i]->Name();
        binder::Variable *current_var = enum_scope->FindLocal(current_name);
        ASSERT(current_var && current_var->IsEnumVariable());
        InferEnumVariableType(checker, current_var->AsEnumVariable(), &value, &init_next, &is_literal_enum, is_const,
                              computed_expr);
    }

    checker::Type *enum_type = checker->Allocator()->New<checker::EnumLiteralType>(
        key_->Name(), checker->Scope(),
        is_literal_enum ? checker::EnumLiteralType::EnumLiteralTypeKind::LITERAL
                        : checker::EnumLiteralType::EnumLiteralTypeKind::NUMERIC);

    return enum_type;
}

checker::Type *TSEnumDeclaration::Check([[maybe_unused]] checker::TSChecker *checker)
{
    binder::Variable *enum_var = key_->Variable();
    ASSERT(enum_var);

    if (enum_var->TsType() == nullptr) {
        checker::ScopeContext scope_ctx(checker, scope_);
        checker::Type *enum_type = InferType(checker, is_const_);
        enum_type->SetVariable(enum_var);
        enum_var->SetTsType(enum_type);
    }

    return nullptr;
}

checker::Type *TSEnumDeclaration::Check(checker::ETSChecker *const checker)
{
    binder::Variable *enum_var = key_->Variable();
    ASSERT(enum_var != nullptr);

    if (enum_var->TsType() == nullptr) {
        auto *const ets_enum_type = checker->CreateETSEnumType(this);
        SetTsType(ets_enum_type);
        ets_enum_type->SetVariable(enum_var);
        enum_var->SetTsType(ets_enum_type);
    } else if (TsType() == nullptr) {
        SetTsType(enum_var->TsType());
    }

    return TsType();
}
}  // namespace panda::es2panda::ir
