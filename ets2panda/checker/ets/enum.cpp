/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http: //www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "binder/ETSBinder.h"
#include "binder/variable.h"
#include "checker/ETSchecker.h"
#include "ir/base/classProperty.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/updateExpression.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/forUpdateStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsEnumMember.h"
#include "ir/ts/tsInterfaceBody.h"
#include "parser/program/program.h"
#include "ir/ets/etsParameterExpression.h"

namespace panda::es2panda::checker {

namespace {
void AppendParentNames(util::UString &qualified_name, const ir::AstNode *const node)
{
    if (node != nullptr && !node->IsProgram()) {
        AppendParentNames(qualified_name, node->Parent());
        if (node->IsTSInterfaceDeclaration()) {
            qualified_name.Append(node->AsTSInterfaceDeclaration()->Id()->Name());
        } else if (node->IsClassDefinition()) {
            qualified_name.Append(node->AsClassDefinition()->Ident()->Name());
        } else {
            ASSERT(node->IsClassDeclaration() || node->IsTSInterfaceBody());
            return;
        }
        qualified_name.Append('#');
    }
}

[[nodiscard]] ir::Identifier *MakeQualifiedIdentifier(panda::ArenaAllocator *const allocator,
                                                      const ir::TSEnumDeclaration *const enum_decl,
                                                      const util::StringView &name)
{
    util::UString qualified_name(util::StringView("#"), allocator);
    AppendParentNames(qualified_name, enum_decl->Parent());
    qualified_name.Append(enum_decl->Key()->Name());
    qualified_name.Append('#');
    qualified_name.Append(name);
    return allocator->New<ir::Identifier>(qualified_name.View(), allocator);
}

template <typename ElementMaker>
[[nodiscard]] ir::Identifier *MakeArray(ETSChecker *const checker, binder::ETSBinder *const binder,
                                        const ETSEnumInterface *const enum_type, const util::StringView &name,
                                        Type *const element_type, ElementMaker &&element_maker)
{
    ArenaVector<ir::Expression *> elements(checker->Allocator()->Adapter());
    elements.reserve(enum_type->GetMembers().size());
    for (const auto *const member : enum_type->GetMembers()) {
        elements.push_back(element_maker(member->AsTSEnumMember()));
    }

    auto *const array_expr = checker->Allocator()->New<ir::ArrayExpression>(std::move(elements), checker->Allocator());
    array_expr->SetPreferredType(element_type);
    array_expr->SetTsType(checker->CreateETSArrayType(element_type));

    auto *const array_ident = MakeQualifiedIdentifier(checker->Allocator(), enum_type->GetDecl(), name);

    auto *const array_class_prop = checker->Allocator()->New<ir::ClassProperty>(
        array_ident, array_expr, nullptr,
        ir::ModifierFlags::STATIC | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::CONST, checker->Allocator(), false);
    array_class_prop->SetTsType(array_expr->TsType());
    array_class_prop->SetParent(binder->Program()->GlobalClass());
    array_ident->SetTsType(array_class_prop->TsType());
    binder->Program()->GlobalClass()->Body().push_back(array_class_prop);

    auto [array_decl, array_var] =
        binder->NewVarDecl<binder::ConstDecl>(array_ident->Start(), array_ident->Name(), array_class_prop);
    array_ident->SetVariable(array_var);
    array_var->SetTsType(array_class_prop->TsType());
    array_var->AddFlag(binder::VariableFlags::PUBLIC | binder::VariableFlags::STATIC | binder::VariableFlags::PROPERTY);
    array_decl->Node()->SetParent(binder->Program()->GlobalClass());
    return array_ident;
}

[[nodiscard]] ir::ETSParameterExpression *MakeFunctionParam(ETSChecker *const checker, binder::ETSBinder *const binder,
                                                            binder::FunctionParamScope *const scope,
                                                            const util::StringView &name, Type *const type)
{
    const auto param_ctx = binder::LexicalScope<binder::FunctionParamScope>::Enter(binder, scope, false);
    auto *const param_ident = checker->Allocator()->New<ir::Identifier>(name, checker->Allocator());
    auto *const param = checker->Allocator()->New<ir::ETSParameterExpression>(param_ident, nullptr);
    auto *const param_var = std::get<1>(binder->AddParamDecl(param));
    param_var->SetTsType(type);
    param->Ident()->SetVariable(param_var);
    param->Ident()->SetTsType(type);
    param->SetTsType(type);
    return param;
}

[[nodiscard]] ir::ETSTypeReference *MakeTypeReference(panda::ArenaAllocator *allocator, const util::StringView &name)
{
    auto *const ident = allocator->New<ir::Identifier>(name, allocator);
    auto *const reference_part = allocator->New<ir::ETSTypeReferencePart>(ident);
    return allocator->New<ir::ETSTypeReference>(reference_part);
}

[[nodiscard]] ir::ScriptFunction *MakeFunction(ETSChecker *const checker, binder::ETSBinder *const binder,
                                               binder::FunctionParamScope *const param_scope,
                                               ArenaVector<ir::Expression *> &&params,
                                               ArenaVector<ir::Statement *> &&body,
                                               ir::TypeNode *const return_type_annotation)
{
    auto *const function_scope = binder->Allocator()->New<binder::FunctionScope>(checker->Allocator(), param_scope);
    function_scope->BindParamScope(param_scope);
    param_scope->BindFunctionScope(function_scope);

    auto *const body_block =
        checker->Allocator()->New<ir::BlockStatement>(checker->Allocator(), function_scope, std::move(body));

    auto *const function = checker->Allocator()->New<ir::ScriptFunction>(
        function_scope, std::move(params), nullptr, body_block, return_type_annotation, ir::ScriptFunctionFlags::METHOD,
        ir::ModifierFlags::PUBLIC, false, Language(Language::Id::ETS));

    binder->AsETSBinder()->BuildInternalName(function);
    binder->AsETSBinder()->AddCompilableFunction(function);
    param_scope->BindNode(function);
    function_scope->BindNode(function);

    return function;
}

void MakeMethodDef(ETSChecker *const checker, binder::ETSBinder *const binder, ir::Identifier *const ident,
                   ir::ScriptFunction *const function)
{
    auto *const function_expr = checker->Allocator()->New<ir::FunctionExpression>(function);
    function->SetParent(function_expr);

    auto *const method_def = checker->Allocator()->New<ir::MethodDefinition>(
        ir::MethodDefinitionKind::METHOD, ident, function_expr, ir::ModifierFlags::PUBLIC, checker->Allocator(), false);
    method_def->SetParent(binder->Program()->GlobalClass());
    function_expr->SetParent(method_def);

    auto *const method_var = std::get<1>(binder->NewVarDecl<binder::FunctionDecl>(
        method_def->Start(), checker->Allocator(), method_def->Id()->Name(), method_def));
    method_var->AddFlag(binder::VariableFlags::STATIC | binder::VariableFlags::SYNTHETIC |
                        binder::VariableFlags::METHOD);
    method_def->Function()->Id()->SetVariable(method_var);
}

[[nodiscard]] ETSFunctionType *MakeProxyFunctionType(ETSChecker *const checker, const util::StringView &name,
                                                     const std::initializer_list<binder::LocalVariable *> &params,
                                                     ir::ScriptFunction *const global_function, Type *const return_type)
{
    auto *const signature_info = checker->CreateSignatureInfo();
    signature_info->params.insert(signature_info->params.end(), params);
    signature_info->min_arg_count = signature_info->params.size();

    auto *const signature = checker->CreateSignature(signature_info, return_type, name);
    signature->SetFunction(global_function);
    signature->AddSignatureFlag(SignatureFlags::PROXY);

    return checker->CreateETSFunctionType(signature, name);
}

[[nodiscard]] Signature *MakeGlobalSignature(ETSChecker *const checker, ir::ScriptFunction *const function,
                                             Type *const return_type)
{
    auto *const signature_info = checker->CreateSignatureInfo();
    signature_info->params.reserve(function->Params().size());
    for (const auto *const param : function->Params()) {
        signature_info->params.push_back(param->AsETSParameterExpression()->Variable()->AsLocalVariable());
    }
    signature_info->min_arg_count = signature_info->params.size();

    auto *const signature = checker->CreateSignature(signature_info, return_type, function);
    signature->AddSignatureFlag(SignatureFlags::PUBLIC | SignatureFlags::STATIC);
    function->SetSignature(signature);

    return signature;
}
}  // namespace

ir::Identifier *ETSChecker::CreateEnumNamesArray(ETSEnumInterface const *const enum_type)
{
    return MakeArray(this, Binder()->AsETSBinder(), enum_type, "NamesArray", GlobalBuiltinETSStringType(),
                     [this](const ir::TSEnumMember *const member) {
                         auto *const enum_name_string_literal =
                             Allocator()->New<ir::StringLiteral>(member->Key()->AsIdentifier()->Name());
                         enum_name_string_literal->SetTsType(GlobalBuiltinETSStringType());
                         return enum_name_string_literal;
                     });
}

ir::Identifier *ETSChecker::CreateEnumValuesArray(ETSEnumType *const enum_type)
{
    return MakeArray(
        this, Binder()->AsETSBinder(), enum_type, "ValuesArray", GlobalIntType(),
        [this](const ir::TSEnumMember *const member) {
            auto *const enum_value_literal = Allocator()->New<ir::NumberLiteral>(lexer::Number(
                member->AsTSEnumMember()->Init()->AsNumberLiteral()->Number().GetValue<ETSEnumType::ValueType>()));
            enum_value_literal->SetTsType(GlobalIntType());
            return enum_value_literal;
        });
}

ir::Identifier *ETSChecker::CreateEnumStringValuesArray(ETSEnumInterface *const enum_type)
{
    return MakeArray(this, Binder()->AsETSBinder(), enum_type, "StringValuesArray", GlobalETSStringLiteralType(),
                     [this, is_string_enum = enum_type->IsETSStringEnumType()](const ir::TSEnumMember *const member) {
                         auto const string_value =
                             is_string_enum ? member->AsTSEnumMember()->Init()->AsStringLiteral()->Str()
                                            : util::UString(std::to_string(member->AsTSEnumMember()
                                                                               ->Init()
                                                                               ->AsNumberLiteral()
                                                                               ->Number()
                                                                               .GetValue<ETSEnumType::ValueType>()),
                                                            Allocator())
                                                  .View();
                         auto *const enum_value_string_literal = Allocator()->New<ir::StringLiteral>(string_value);
                         enum_value_string_literal->SetTsType(GlobalETSStringLiteralType());
                         return enum_value_string_literal;
                     });
}

ir::Identifier *ETSChecker::CreateEnumItemsArray(ETSEnumInterface *const enum_type)
{
    auto *const enum_type_ident = Allocator()->New<ir::Identifier>(enum_type->GetName(), Allocator());
    enum_type_ident->SetTsType(enum_type);

    return MakeArray(
        this, Binder()->AsETSBinder(), enum_type, "ItemsArray", enum_type,
        [this, enum_type_ident](const ir::TSEnumMember *const member) {
            auto *const enum_member_ident =
                Allocator()->New<ir::Identifier>(member->AsTSEnumMember()->Key()->AsIdentifier()->Name(), Allocator());
            auto *const enum_member_expr = Allocator()->New<ir::MemberExpression>(
                enum_type_ident, enum_member_ident, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
            enum_member_expr->SetTsType(member->AsTSEnumMember()->Key()->AsIdentifier()->Variable()->TsType());
            return enum_member_expr;
        });
}

ETSEnumType::Method ETSChecker::CreateEnumFromIntMethod(ir::Identifier *const names_array_ident,
                                                        ETSEnumInterface *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const input_ordinal_ident =
        MakeFunctionParam(this, Binder()->AsETSBinder(), param_scope, "ordinal", GlobalIntType());

    auto *const in_array_size_expr = [this, names_array_ident, input_ordinal_ident]() {
        auto *const length_ident = Allocator()->New<ir::Identifier>("length", Allocator());
        auto *const values_array_length_expr = Allocator()->New<ir::MemberExpression>(
            names_array_ident, length_ident, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        auto *const expr = Allocator()->New<ir::BinaryExpression>(input_ordinal_ident, values_array_length_expr,
                                                                  lexer::TokenType::PUNCTUATOR_LESS_THAN);
        expr->SetOperationType(GlobalIntType());
        expr->SetTsType(GlobalETSBooleanType());
        return expr;
    }();

    auto *const return_enum_stmt = [this, input_ordinal_ident, enum_type]() {
        input_ordinal_ident->SetTsType(enum_type);
        return Allocator()->New<ir::ReturnStatement>(input_ordinal_ident);
    }();

    auto *const if_ordinal_exists_stmt =
        Allocator()->New<ir::IfStatement>(in_array_size_expr, return_enum_stmt, nullptr);

    auto *const throw_no_enum_stmt = [this, input_ordinal_ident, enum_type]() {
        auto *const exception_reference = MakeTypeReference(Allocator(), "Exception");

        util::UString message_string(util::StringView("No enum constant in "), Allocator());
        message_string.Append(enum_type->GetName());
        message_string.Append(" with ordinal value ");

        auto *const message = Allocator()->New<ir::StringLiteral>(message_string.View());
        auto *const new_expr_arg =
            Allocator()->New<ir::BinaryExpression>(message, input_ordinal_ident, lexer::TokenType::PUNCTUATOR_PLUS);
        ArenaVector<ir::Expression *> new_expr_args(Allocator()->Adapter());
        new_expr_args.push_back(new_expr_arg);

        auto *const new_expr = Allocator()->New<ir::ETSNewClassInstanceExpression>(
            exception_reference, std::move(new_expr_args),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());

        new_expr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), new_expr->GetArguments(), new_expr->Start()));
        new_expr->SetTsType(GlobalBuiltinExceptionType());

        return Allocator()->New<ir::ThrowStatement>(new_expr);
    }();

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(input_ordinal_ident);

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(if_ordinal_exists_stmt);
    body.push_back(throw_no_enum_stmt);
    body.push_back(return_enum_stmt);

    auto *const enum_type_annotation = MakeTypeReference(Allocator(), enum_type->GetName());

    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        enum_type_annotation);
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);

    auto *const ident = MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::FROM_INT_METHOD_NAME);
    function->SetIdent(ident);
    function->Scope()->BindInternalName(ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), ident, function);

    return {MakeGlobalSignature(this, function, enum_type), nullptr};
}

ETSEnumType::Method ETSChecker::CreateEnumToStringMethod(ir::Identifier *const string_values_array_ident,
                                                         ETSEnumInterface *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());

    auto *const input_enum_ident = MakeFunctionParam(this, Binder()->AsETSBinder(), param_scope, "ordinal", enum_type);

    auto *const return_stmt = [this, input_enum_ident, string_values_array_ident]() {
        auto *const array_access_expr = Allocator()->New<ir::MemberExpression>(
            string_values_array_ident, input_enum_ident, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        array_access_expr->SetTsType(GlobalETSStringLiteralType());

        return Allocator()->New<ir::ReturnStatement>(array_access_expr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(return_stmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(input_enum_ident);

    auto *const string_type_annotation = MakeTypeReference(Allocator(), GlobalBuiltinETSStringType()->Name());
    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        string_type_annotation);

    auto *const function_ident =
        MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::TO_STRING_METHOD_NAME);
    function->SetIdent(function_ident);
    function->Scope()->BindInternalName(function_ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), function_ident, function);

    return {
        MakeGlobalSignature(this, function, GlobalETSStringLiteralType()),
        MakeProxyFunctionType(this, ETSEnumType::TO_STRING_METHOD_NAME, {}, function, GlobalETSStringLiteralType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetValueMethod(ir::Identifier *const values_array_ident,
                                                         ETSEnumType *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalClassScope());

    auto *const input_enum_ident = MakeFunctionParam(this, Binder()->AsETSBinder(), param_scope, "e", enum_type);

    auto *const return_stmt = [this, input_enum_ident, values_array_ident]() {
        auto *const array_access_expr = Allocator()->New<ir::MemberExpression>(
            values_array_ident, input_enum_ident, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        array_access_expr->SetTsType(GlobalIntType());

        return Allocator()->New<ir::ReturnStatement>(array_access_expr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(return_stmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(input_enum_ident);

    auto *const int_type_annotation = Allocator()->New<ir::ETSPrimitiveType>(ir::PrimitiveType::INT);
    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        int_type_annotation);

    auto *const function_ident =
        MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::GET_VALUE_METHOD_NAME);
    function->SetIdent(function_ident);
    function->Scope()->BindInternalName(function_ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), function_ident, function);

    return {MakeGlobalSignature(this, function, GlobalIntType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_VALUE_METHOD_NAME, {}, function, GlobalIntType())};
}

ETSEnumType::Method ETSChecker::CreateEnumGetNameMethod(ir::Identifier *const names_array_ident,
                                                        ETSEnumInterface *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const input_enum_ident = MakeFunctionParam(this, Binder()->AsETSBinder(), param_scope, "ordinal", enum_type);

    auto *const return_stmt = [this, input_enum_ident, names_array_ident]() {
        auto *const array_access_expr = Allocator()->New<ir::MemberExpression>(
            names_array_ident, input_enum_ident, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        array_access_expr->SetTsType(GlobalBuiltinETSStringType());

        return Allocator()->New<ir::ReturnStatement>(array_access_expr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(return_stmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(input_enum_ident);

    auto *const string_type_annotation = MakeTypeReference(Allocator(), GlobalBuiltinETSStringType()->Name());

    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        string_type_annotation);

    auto *const function_ident =
        MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::GET_NAME_METHOD_NAME);
    function->SetIdent(function_ident);
    function->Scope()->BindInternalName(function_ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), function_ident, function);

    return {MakeGlobalSignature(this, function, GlobalBuiltinETSStringType()),
            MakeProxyFunctionType(this, ETSEnumType::GET_NAME_METHOD_NAME, {}, function, GlobalBuiltinETSStringType())};
}

ETSEnumType::Method ETSChecker::CreateEnumValueOfMethod(ir::Identifier *const names_array_ident,
                                                        ETSEnumInterface *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const input_name_ident =
        MakeFunctionParam(this, Binder()->AsETSBinder(), param_scope, "name", GlobalBuiltinETSStringType());

    binder::LexicalScope<binder::LoopDeclarationScope> loop_decl_scope(Binder());

    auto *const for_loop_i_ident = [this]() {
        auto *const ident = Allocator()->New<ir::Identifier>("i", Allocator());
        ident->SetTsType(GlobalIntType());
        auto [decl, var] = Binder()->NewVarDecl<binder::LetDecl>(ident->Start(), ident->Name());
        ident->SetVariable(var);
        var->SetTsType(GlobalIntType());
        var->SetScope(Binder()->GetScope());
        var->AddFlag(binder::VariableFlags::LOCAL);
        decl->BindNode(ident);
        return ident;
    }();

    auto *const for_loop_init_var_decl = [this, for_loop_i_ident]() {
        auto *const init = Allocator()->New<ir::NumberLiteral>("0");
        init->SetTsType(GlobalIntType());
        auto *const decl = Allocator()->New<ir::VariableDeclarator>(for_loop_i_ident, init);
        decl->SetTsType(GlobalIntType());
        ArenaVector<ir::VariableDeclarator *> decls(Allocator()->Adapter());
        decls.push_back(decl);
        return Allocator()->New<ir::VariableDeclaration>(ir::VariableDeclaration::VariableDeclarationKind::LET,
                                                         Allocator(), std::move(decls), false);
    }();

    auto *const for_loop_test = [this, names_array_ident, for_loop_i_ident]() {
        auto *const length_ident = Allocator()->New<ir::Identifier>("length", Allocator());
        auto *const array_length_expr = Allocator()->New<ir::MemberExpression>(
            names_array_ident, length_ident, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        array_length_expr->SetTsType(GlobalIntType());
        auto *const binary_expr = Allocator()->New<ir::BinaryExpression>(for_loop_i_ident, array_length_expr,
                                                                         lexer::TokenType::PUNCTUATOR_LESS_THAN);
        binary_expr->SetOperationType(GlobalIntType());
        binary_expr->SetTsType(GlobalETSBooleanType());
        return binary_expr;
    }();

    auto *const for_loop_update = [this, for_loop_i_ident]() {
        auto *const increment_expr =
            Allocator()->New<ir::UpdateExpression>(for_loop_i_ident, lexer::TokenType::PUNCTUATOR_PLUS_PLUS, true);
        increment_expr->SetTsType(GlobalIntType());
        return increment_expr;
    }();

    auto *const if_stmt = [this, names_array_ident, for_loop_i_ident, input_name_ident]() {
        auto *const names_array_element_expr = Allocator()->New<ir::MemberExpression>(
            names_array_ident, for_loop_i_ident, ir::MemberExpressionKind::ELEMENT_ACCESS, true, false);
        names_array_element_expr->SetTsType(GlobalBuiltinETSStringType());

        auto *const names_equal_expr = Allocator()->New<ir::BinaryExpression>(
            input_name_ident, names_array_element_expr, lexer::TokenType::PUNCTUATOR_EQUAL);
        names_equal_expr->SetOperationType(GlobalBuiltinETSStringType());
        names_equal_expr->SetTsType(GlobalETSBooleanType());

        auto *const return_stmt = Allocator()->New<ir::ReturnStatement>(for_loop_i_ident);
        return Allocator()->New<ir::IfStatement>(names_equal_expr, return_stmt, nullptr);
    }();

    binder::LexicalScope<binder::LoopScope> loop_scope(Binder());
    loop_scope.GetScope()->BindDecls(loop_decl_scope.GetScope());

    auto *const for_loop = Allocator()->New<ir::ForUpdateStatement>(loop_scope.GetScope(), for_loop_init_var_decl,
                                                                    for_loop_test, for_loop_update, if_stmt);
    loop_scope.GetScope()->BindNode(for_loop);
    loop_scope.GetScope()->DeclScope()->BindNode(for_loop);

    auto *const throw_stmt = [this, input_name_ident, enum_type]() {
        util::UString message_string(util::StringView("No enum constant "), Allocator());
        message_string.Append(enum_type->GetName());
        message_string.Append('.');

        auto *const message = Allocator()->New<ir::StringLiteral>(message_string.View());
        auto *const new_expr_arg =
            Allocator()->New<ir::BinaryExpression>(message, input_name_ident, lexer::TokenType::PUNCTUATOR_PLUS);

        ArenaVector<ir::Expression *> new_expr_args(Allocator()->Adapter());
        new_expr_args.push_back(new_expr_arg);

        auto *const exception_reference = MakeTypeReference(Allocator(), "Exception");

        auto *const new_expr = Allocator()->New<ir::ETSNewClassInstanceExpression>(
            exception_reference, std::move(new_expr_args),
            GlobalBuiltinExceptionType()->GetDeclNode()->AsClassDefinition());
        new_expr->SetSignature(
            ResolveConstructExpression(GlobalBuiltinExceptionType(), new_expr->GetArguments(), new_expr->Start()));
        new_expr->SetTsType(GlobalBuiltinExceptionType());

        return Allocator()->New<ir::ThrowStatement>(new_expr);
    }();

    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(for_loop);
    body.push_back(throw_stmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    params.push_back(input_name_ident);

    auto *const enum_type_annotation = MakeTypeReference(Allocator(), enum_type->GetName());

    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        enum_type_annotation);
    function->AddFlag(ir::ScriptFunctionFlags::THROWS);

    auto *const function_ident =
        MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::VALUE_OF_METHOD_NAME);
    function->SetIdent(function_ident);
    function->Scope()->BindInternalName(function_ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), function_ident, function);

    return {MakeGlobalSignature(this, function, enum_type),
            MakeProxyFunctionType(this, ETSEnumType::VALUE_OF_METHOD_NAME,
                                  {function->Params()[0]->AsETSParameterExpression()->Variable()->AsLocalVariable()},
                                  function, enum_type)};
}

ETSEnumType::Method ETSChecker::CreateEnumValuesMethod(ir::Identifier *const items_array_ident,
                                                       ETSEnumInterface *const enum_type)
{
    auto *const param_scope =
        Binder()->Allocator()->New<binder::FunctionParamScope>(Allocator(), Program()->GlobalScope());

    auto *const return_stmt = Allocator()->New<ir::ReturnStatement>(items_array_ident);
    ArenaVector<ir::Statement *> body(Allocator()->Adapter());
    body.push_back(return_stmt);

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    auto *const enum_array_type_annotation =
        Allocator()->New<ir::TSArrayType>(MakeTypeReference(Allocator(), enum_type->GetName()));

    auto *const function = MakeFunction(this, Binder()->AsETSBinder(), param_scope, std::move(params), std::move(body),
                                        enum_array_type_annotation);

    auto *const function_ident =
        MakeQualifiedIdentifier(Allocator(), enum_type->GetDecl(), ETSEnumType::VALUES_METHOD_NAME);
    function->SetIdent(function_ident);
    function->Scope()->BindInternalName(function_ident->Name());

    MakeMethodDef(this, Binder()->AsETSBinder(), function_ident, function);

    return {MakeGlobalSignature(this, function, CreateETSArrayType(enum_type)),
            MakeProxyFunctionType(this, ETSEnumType::VALUES_METHOD_NAME, {}, function, CreateETSArrayType(enum_type))};
}
}  // namespace panda::es2panda::checker
