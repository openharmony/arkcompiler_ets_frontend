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

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::MetaProperty *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::MethodDefinition *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::Property *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ScriptFunction *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SpreadElement *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TemplateElement *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSIndexSignature *node) const
{
    TSChecker *checker = GetTSChecker();
    if (node->TsType() != nullptr) {
        return node->TsType();
    }

    const util::StringView &param_name = node->Param()->AsIdentifier()->Name();
    node->type_annotation_->Check(checker);
    checker::Type *index_type = node->type_annotation_->GetType(checker);
    checker::IndexInfo *info =
        checker->Allocator()->New<checker::IndexInfo>(index_type, param_name, node->Readonly(), node->Start());
    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
    checker::ObjectType *placeholder = checker->Allocator()->New<checker::ObjectLiteralType>(desc);

    if (node->Kind() == ir::TSIndexSignature::TSIndexSignatureKind::NUMBER) {
        placeholder->Desc()->number_index_info = info;
    } else {
        placeholder->Desc()->string_index_info = info;
    }

    node->SetTsType(placeholder);
    return placeholder;
}

checker::Type *TSAnalyzer::Check(ir::TSMethodSignature *node) const
{
    TSChecker *checker = GetTSChecker();
    if (node->Computed()) {
        checker->CheckComputedPropertyName(node->Key());
    }

    checker::ScopeContext scope_ctx(checker, node->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(node->Params(), signature_info);

    auto *call_signature = checker->Allocator()->New<checker::Signature>(signature_info, checker->GlobalAnyType());
    node->Variable()->SetTsType(checker->CreateFunctionTypeWithSignature(call_signature));

    if (node->ReturnTypeAnnotation() == nullptr) {
        checker->ThrowTypeError(
            "Method signature, which lacks return-type annotation, implicitly has an 'any' return type.",
            node->Start());
    }

    node->return_type_annotation_->Check(checker);
    call_signature->SetReturnType(node->return_type_annotation_->GetType(checker));

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSPropertySignature *node) const
{
    TSChecker *checker = GetTSChecker();
    if (node->TypeAnnotation() != nullptr) {
        node->TypeAnnotation()->Check(checker);
    }

    if (node->Computed()) {
        checker->CheckComputedPropertyName(node->Key());
    }

    if (node->TypeAnnotation() != nullptr) {
        node->Variable()->SetTsType(node->TypeAnnotation()->GetType(checker));
        return nullptr;
    }

    checker->ThrowTypeError("Property implicitly has an 'any' type.", node->Start());
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSSignatureDeclaration *node) const
{
    TSChecker *checker = GetTSChecker();
    if (node->TsType() != nullptr) {
        return node->TsType();
    }

    checker::ScopeContext scope_ctx(checker, node->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(node->Params(), signature_info);

    bool is_call_signature = (node->Kind() == ir::TSSignatureDeclaration::TSSignatureDeclarationKind::CALL_SIGNATURE);

    if (node->ReturnTypeAnnotation() == nullptr) {
        if (is_call_signature) {
            checker->ThrowTypeError(
                "Call signature, which lacks return-type annotation, implicitly has an 'any' return type.",
                node->Start());
        }

        checker->ThrowTypeError(
            "Construct signature, which lacks return-type annotation, implicitly has an 'any' return type.",
            node->Start());
    }

    node->return_type_annotation_->Check(checker);
    checker::Type *return_type = node->return_type_annotation_->GetType(checker);

    auto *signature = checker->Allocator()->New<checker::Signature>(signature_info, return_type);

    checker::Type *placeholder_obj = nullptr;

    if (is_call_signature) {
        placeholder_obj = checker->CreateObjectTypeWithCallSignature(signature);
    } else {
        placeholder_obj = checker->CreateObjectTypeWithConstructSignature(signature);
    }

    node->SetTsType(placeholder_obj);
    return placeholder_obj;
}
// from ets folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSScript *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSClassLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSFunctionType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSImportDeclaration *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSLaunchExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewArrayInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewClassInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSNewMultiDimArrayInstanceExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ETSPackageDeclaration *st) const
{
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

checker::Type *TSAnalyzer::Check(ir::ETSTuple *node) const
{
    (void)node;
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

static void GetSpreadElementType(checker::TSChecker *checker, checker::Type *spread_type,
                                 ArenaVector<checker::Type *> &element_types, const lexer::SourcePosition &loc)
{
    bool in_const_context = checker->HasStatus(checker::CheckerStatus::IN_CONST_CONTEXT);

    if (spread_type->IsObjectType() && spread_type->AsObjectType()->IsTupleType()) {
        ArenaVector<checker::Type *> tuple_element_types(checker->Allocator()->Adapter());
        checker::TupleType *spread_tuple = spread_type->AsObjectType()->AsTupleType();

        for (auto *it : spread_tuple->Properties()) {
            if (in_const_context) {
                element_types.push_back(it->TsType());
                continue;
            }

            tuple_element_types.push_back(it->TsType());
        }

        if (in_const_context) {
            return;
        }

        element_types.push_back(checker->CreateUnionType(std::move(tuple_element_types)));
        return;
    }

    if (spread_type->IsUnionType()) {
        ArenaVector<checker::Type *> spread_types(checker->Allocator()->Adapter());
        bool throw_error = false;

        for (auto *type : spread_type->AsUnionType()->ConstituentTypes()) {
            if (type->IsArrayType()) {
                spread_types.push_back(type->AsArrayType()->ElementType());
                continue;
            }

            if (type->IsObjectType() && type->AsObjectType()->IsTupleType()) {
                checker::TupleType *tuple = type->AsObjectType()->AsTupleType();

                for (auto *it : tuple->Properties()) {
                    spread_types.push_back(it->TsType());
                }

                continue;
            }

            throw_error = true;
            break;
        }

        if (!throw_error) {
            element_types.push_back(checker->CreateUnionType(std::move(spread_types)));
            return;
        }
    }

    checker->ThrowTypeError(
        {"Type '", spread_type, "' must have a '[Symbol.iterator]()' method that returns an iterator."}, loc);
}

checker::Type *TSAnalyzer::Check(ir::ArrayExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    ArenaVector<checker::Type *> element_types(checker->Allocator()->Adapter());
    ArenaVector<checker::ElementFlags> element_flags(checker->Allocator()->Adapter());
    bool in_const_context = checker->HasStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    bool create_tuple = checker->HasStatus(checker::CheckerStatus::FORCE_TUPLE);

    for (auto *it : expr->Elements()) {
        if (it->IsSpreadElement()) {
            checker::Type *spread_type = it->AsSpreadElement()->Argument()->Check(checker);

            if (spread_type->IsArrayType()) {
                element_types.push_back(in_const_context ? spread_type : spread_type->AsArrayType()->ElementType());
                element_flags.push_back(checker::ElementFlags::VARIADIC);
                continue;
            }

            GetSpreadElementType(checker, spread_type, element_types, it->Start());
            element_flags.push_back(checker::ElementFlags::REST);
            continue;
        }

        checker::Type *element_type = it->Check(checker);

        if (!in_const_context) {
            element_type = checker->GetBaseTypeOfLiteralType(element_type);
        }

        element_flags.push_back(checker::ElementFlags::REQUIRED);
        element_types.push_back(element_type);
    }

    if (in_const_context || create_tuple) {
        checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
        uint32_t index = 0;

        for (auto it = element_types.begin(); it != element_types.end(); it++, index++) {
            util::StringView member_index = util::Helpers::ToStringView(checker->Allocator(), index);
            varbinder::LocalVariable *tuple_member = varbinder::Scope::CreateVar(
                checker->Allocator(), member_index, varbinder::VariableFlags::PROPERTY, nullptr);

            if (in_const_context) {
                tuple_member->AddFlag(varbinder::VariableFlags::READONLY);
            }

            tuple_member->SetTsType(*it);
            desc->properties.push_back(tuple_member);
        }

        return checker->CreateTupleType(desc, std::move(element_flags), checker::ElementFlags::REQUIRED, index, index,
                                        in_const_context);
    }

    checker::Type *array_element_type = nullptr;
    if (element_types.empty()) {
        array_element_type = checker->GlobalAnyType();
    } else {
        array_element_type = checker->CreateUnionType(std::move(element_types));
    }

    return checker->Allocator()->New<checker::ArrayType>(array_element_type);
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
    TSChecker *checker = GetTSChecker();
    if (expr->Left()->IsArrayPattern()) {
        auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
        auto destructuring_context =
            checker::ArrayDestructuringContext(checker, expr->Left(), true, true, nullptr, expr->Right());
        destructuring_context.Start();
        return destructuring_context.InferredType();
    }

    if (expr->Left()->IsObjectPattern()) {
        auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
        auto destructuring_context =
            checker::ObjectDestructuringContext(checker, expr->Left(), true, true, nullptr, expr->Right());
        destructuring_context.Start();
        return destructuring_context.InferredType();
    }

    if (expr->Left()->IsIdentifier() && expr->Left()->AsIdentifier()->Variable() != nullptr &&
        expr->Left()->AsIdentifier()->Variable()->Declaration()->IsConstDecl()) {
        checker->ThrowTypeError(
            {"Cannot assign to ", expr->Left()->AsIdentifier()->Name(), " because it is a constant."},
            expr->Left()->Start());
    }

    auto *left_type = expr->Left()->Check(checker);

    if (left_type->HasTypeFlag(checker::TypeFlag::READONLY)) {
        checker->ThrowTypeError("Cannot assign to this property because it is readonly.", expr->Left()->Start());
    }

    if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        checker->ElaborateElementwise(left_type, expr->Right(), expr->Left()->Start());
        return checker->CheckTypeCached(expr->Right());
    }

    auto *right_type = expr->Right()->Check(checker);

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY_EQUAL:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION_EQUAL:
        case lexer::TokenType::PUNCTUATOR_DIVIDE_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MOD_EQUAL:
        case lexer::TokenType::PUNCTUATOR_MINUS_EQUAL:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR_EQUAL: {
            return checker->CheckBinaryOperator(left_type, right_type, expr->Left(), expr->Right(), expr,
                                                expr->OperatorType());
        }
        case lexer::TokenType::PUNCTUATOR_PLUS_EQUAL: {
            return checker->CheckPlusOperator(left_type, right_type, expr->Left(), expr->Right(), expr,
                                              expr->OperatorType());
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            checker->CheckAssignmentOperator(expr->OperatorType(), expr->Left(), left_type, right_type);
            return right_type;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::AwaitExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check(ir::BinaryExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    auto *left_type = expr->Left()->Check(checker);
    auto *right_type = expr->Right()->Check(checker);

    switch (expr->OperatorType()) {
        case lexer::TokenType::PUNCTUATOR_MULTIPLY:
        case lexer::TokenType::PUNCTUATOR_EXPONENTIATION:
        case lexer::TokenType::PUNCTUATOR_DIVIDE:
        case lexer::TokenType::PUNCTUATOR_MOD:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_LEFT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_UNSIGNED_RIGHT_SHIFT:
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND:
        case lexer::TokenType::PUNCTUATOR_BITWISE_XOR:
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            return checker->CheckBinaryOperator(left_type, right_type, expr->Left(), expr->Right(), expr,
                                                expr->OperatorType());
        }
        case lexer::TokenType::PUNCTUATOR_PLUS: {
            return checker->CheckPlusOperator(left_type, right_type, expr->Left(), expr->Right(), expr,
                                              expr->OperatorType());
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_GREATER_THAN: {
            return checker->CheckCompareOperator(left_type, right_type, expr->Left(), expr->Right(), expr,
                                                 expr->OperatorType());
        }
        case lexer::TokenType::PUNCTUATOR_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_STRICT_EQUAL:
        case lexer::TokenType::PUNCTUATOR_NOT_STRICT_EQUAL: {
            if (checker->IsTypeEqualityComparableTo(left_type, right_type) ||
                checker->IsTypeEqualityComparableTo(right_type, left_type)) {
                return checker->GlobalBooleanType();
            }

            checker->ThrowBinaryLikeError(expr->OperatorType(), left_type, right_type, expr->Start());
        }
        case lexer::TokenType::KEYW_INSTANCEOF: {
            return checker->CheckInstanceofExpression(left_type, right_type, expr->Right(), expr);
        }
        case lexer::TokenType::KEYW_IN: {
            return checker->CheckInExpression(left_type, right_type, expr->Left(), expr->Right(), expr);
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_AND: {
            return checker->CheckAndOperator(left_type, right_type, expr->Left());
        }
        case lexer::TokenType::PUNCTUATOR_LOGICAL_OR: {
            return checker->CheckOrOperator(left_type, right_type, expr->Left());
        }
        case lexer::TokenType::PUNCTUATOR_NULLISH_COALESCING: {
            // NOTE: Csaba Repasi. Implement checker for nullish coalescing
            return checker->GlobalAnyType();
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            checker->CheckAssignmentOperator(expr->OperatorType(), expr->Left(), left_type, right_type);
            return right_type;
        }
        default: {
            UNREACHABLE();
            break;
        }
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::BlockExpression *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::CallExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *callee_type = expr->callee_->Check(checker);

    // NOTE: aszilagyi. handle optional chain
    if (callee_type->IsObjectType()) {
        checker::ObjectType *callee_obj = callee_type->AsObjectType();
        return checker->ResolveCallOrNewExpression(callee_obj->CallSignatures(), expr->Arguments(), expr->Start());
    }

    checker->ThrowTypeError("This expression is not callable.", expr->Start());
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::ChainExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    return expr->expression_->Check(checker);
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ConditionalExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *test_type = expr->Test()->Check(checker);

    checker->CheckTruthinessOfType(test_type, expr->Test()->Start());
    checker->CheckTestingKnownTruthyCallableOrAwaitableType(expr->Test(), test_type, expr->consequent_);

    checker::Type *consequent_type = expr->consequent_->Check(checker);
    checker::Type *alternate_type = expr->alternate_->Check(checker);

    return checker->CreateUnionType({consequent_type, alternate_type});
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::DirectEvalExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::FunctionExpression *expr) const
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

    expr->Function()->Body()->Check(checker);

    return func_type;
}

checker::Type *TSAnalyzer::Check(ir::Identifier *expr) const
{
    TSChecker *checker = GetTSChecker();
    if (expr->Variable() == nullptr) {
        if (expr->Name().Is("undefined")) {
            return checker->GlobalUndefinedType();
        }

        checker->ThrowTypeError({"Cannot find name ", expr->Name()}, expr->Start());
    }

    const varbinder::Decl *decl = expr->Variable()->Declaration();

    if (decl->IsTypeAliasDecl() || decl->IsInterfaceDecl()) {
        checker->ThrowTypeError({expr->Name(), " only refers to a type, but is being used as a value here."},
                                expr->Start());
    }

    expr->SetTsType(checker->GetTypeOfVariable(expr->Variable()));
    return expr->TsType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::MemberExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *base_type = checker->CheckNonNullType(expr->Object()->Check(checker), expr->Object()->Start());

    if (expr->IsComputed()) {
        checker::Type *index_type = expr->Property()->Check(checker);
        checker::Type *indexed_access_type = checker->GetPropertyTypeForIndexType(base_type, index_type);

        if (indexed_access_type != nullptr) {
            return indexed_access_type;
        }

        if (!index_type->HasTypeFlag(checker::TypeFlag::STRING_LIKE | checker::TypeFlag::NUMBER_LIKE)) {
            checker->ThrowTypeError({"Type ", index_type, " cannot be used as index type"}, expr->Property()->Start());
        }

        if (index_type->IsNumberType()) {
            checker->ThrowTypeError("No index signature with a parameter of type 'string' was found on type this type",
                                    expr->Start());
        }

        if (index_type->IsStringType()) {
            checker->ThrowTypeError("No index signature with a parameter of type 'number' was found on type this type",
                                    expr->Start());
        }

        switch (expr->Property()->Type()) {
            case ir::AstNodeType::IDENTIFIER: {
                checker->ThrowTypeError(
                    {"Property ", expr->Property()->AsIdentifier()->Name(), " does not exist on this type."},
                    expr->Property()->Start());
            }
            case ir::AstNodeType::NUMBER_LITERAL: {
                checker->ThrowTypeError(
                    {"Property ", expr->Property()->AsNumberLiteral()->Str(), " does not exist on this type."},
                    expr->Property()->Start());
            }
            case ir::AstNodeType::STRING_LITERAL: {
                checker->ThrowTypeError(
                    {"Property ", expr->Property()->AsStringLiteral()->Str(), " does not exist on this type."},
                    expr->Property()->Start());
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    varbinder::Variable *prop = checker->GetPropertyOfType(base_type, expr->Property()->AsIdentifier()->Name());

    if (prop != nullptr) {
        checker::Type *prop_type = checker->GetTypeOfVariable(prop);
        if (prop->HasFlag(varbinder::VariableFlags::READONLY)) {
            prop_type->AddTypeFlag(checker::TypeFlag::READONLY);
        }

        return prop_type;
    }

    if (base_type->IsObjectType()) {
        checker::ObjectType *obj_type = base_type->AsObjectType();

        if (obj_type->StringIndexInfo() != nullptr) {
            checker::Type *index_type = obj_type->StringIndexInfo()->GetType();
            if (obj_type->StringIndexInfo()->Readonly()) {
                index_type->AddTypeFlag(checker::TypeFlag::READONLY);
            }

            return index_type;
        }
    }

    checker->ThrowTypeError({"Property ", expr->Property()->AsIdentifier()->Name(), " does not exist on this type."},
                            expr->Property()->Start());
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::NewExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *callee_type = expr->callee_->Check(checker);

    if (callee_type->IsObjectType()) {
        checker::ObjectType *callee_obj = callee_type->AsObjectType();
        return checker->ResolveCallOrNewExpression(callee_obj->ConstructSignatures(), expr->Arguments(), expr->Start());
    }

    checker->ThrowTypeError("This expression is not callable.", expr->Start());
    return nullptr;
}
static const util::StringView &GetPropertyName(const ir::Expression *key)
{
    if (key->IsIdentifier()) {
        return key->AsIdentifier()->Name();
    }

    if (key->IsStringLiteral()) {
        return key->AsStringLiteral()->Str();
    }

    ASSERT(key->IsNumberLiteral());
    return key->AsNumberLiteral()->Str();
}

static varbinder::VariableFlags GetFlagsForProperty(const ir::Property *prop)
{
    if (!prop->IsMethod()) {
        return varbinder::VariableFlags::PROPERTY;
    }

    varbinder::VariableFlags prop_flags = varbinder::VariableFlags::METHOD;

    if (prop->IsAccessor() && prop->Kind() == ir::PropertyKind::GET) {
        prop_flags |= varbinder::VariableFlags::READONLY;
    }

    return prop_flags;
}

static checker::Type *GetTypeForProperty(ir::Property *prop, checker::TSChecker *checker)
{
    if (prop->IsAccessor()) {
        checker::Type *func_type = prop->Value()->Check(checker);

        if (prop->Kind() == ir::PropertyKind::SET) {
            return checker->GlobalAnyType();
        }

        ASSERT(func_type->IsObjectType() && func_type->AsObjectType()->IsFunctionType());
        return func_type->AsObjectType()->CallSignatures()[0]->ReturnType();
    }

    if (prop->IsShorthand()) {
        return prop->Key()->Check(checker);
    }

    return prop->Value()->Check(checker);
}

checker::Type *TSAnalyzer::Check(ir::ObjectExpression *expr) const
{
    TSChecker *checker = GetTSChecker();

    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
    std::unordered_map<util::StringView, lexer::SourcePosition> all_properties_map;
    bool in_const_context = checker->HasStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    ArenaVector<checker::Type *> computed_number_prop_types(checker->Allocator()->Adapter());
    ArenaVector<checker::Type *> computed_string_prop_types(checker->Allocator()->Adapter());
    bool has_computed_number_property = false;
    bool has_computed_string_property = false;
    bool seen_spread = false;

    for (auto *it : expr->Properties()) {
        if (it->IsProperty()) {
            auto *prop = it->AsProperty();

            if (prop->IsComputed()) {
                checker::Type *computed_name_type = checker->CheckComputedPropertyName(prop->Key());

                if (computed_name_type->IsNumberType()) {
                    has_computed_number_property = true;
                    computed_number_prop_types.push_back(prop->Value()->Check(checker));
                    continue;
                }

                if (computed_name_type->IsStringType()) {
                    has_computed_string_property = true;
                    computed_string_prop_types.push_back(prop->Value()->Check(checker));
                    continue;
                }
            }

            checker::Type *prop_type = GetTypeForProperty(prop, checker);
            varbinder::VariableFlags flags = GetFlagsForProperty(prop);
            const util::StringView &prop_name = GetPropertyName(prop->Key());

            auto *member_var = varbinder::Scope::CreateVar(checker->Allocator(), prop_name, flags, it);

            if (in_const_context) {
                member_var->AddFlag(varbinder::VariableFlags::READONLY);
            } else {
                prop_type = checker->GetBaseTypeOfLiteralType(prop_type);
            }

            member_var->SetTsType(prop_type);

            if (prop->Key()->IsNumberLiteral()) {
                member_var->AddFlag(varbinder::VariableFlags::NUMERIC_NAME);
            }

            varbinder::LocalVariable *found_member = desc->FindProperty(prop_name);
            all_properties_map.insert({prop_name, it->Start()});

            if (found_member != nullptr) {
                found_member->SetTsType(prop_type);
                continue;
            }

            desc->properties.push_back(member_var);
            continue;
        }

        ASSERT(it->IsSpreadElement());

        checker::Type *const spread_type = it->AsSpreadElement()->Argument()->Check(checker);
        seen_spread = true;

        // NOTE: aszilagyi. handle union of object types
        if (!spread_type->IsObjectType()) {
            checker->ThrowTypeError("Spread types may only be created from object types.", it->Start());
        }

        for (auto *spread_prop : spread_type->AsObjectType()->Properties()) {
            auto found = all_properties_map.find(spread_prop->Name());
            if (found != all_properties_map.end()) {
                checker->ThrowTypeError(
                    {found->first, " is specified more than once, so this usage will be overwritten."}, found->second);
            }

            varbinder::LocalVariable *found_member = desc->FindProperty(spread_prop->Name());

            if (found_member != nullptr) {
                found_member->SetTsType(spread_prop->TsType());
                continue;
            }

            desc->properties.push_back(spread_prop);
        }
    }

    if (!seen_spread && (has_computed_number_property || has_computed_string_property)) {
        for (auto *it : desc->properties) {
            computed_string_prop_types.push_back(it->TsType());

            if (has_computed_number_property && it->HasFlag(varbinder::VariableFlags::NUMERIC_NAME)) {
                computed_number_prop_types.push_back(it->TsType());
            }
        }

        if (has_computed_number_property) {
            desc->number_index_info = checker->Allocator()->New<checker::IndexInfo>(
                checker->CreateUnionType(std::move(computed_number_prop_types)), "x", in_const_context);
        }

        if (has_computed_string_property) {
            desc->string_index_info = checker->Allocator()->New<checker::IndexInfo>(
                checker->CreateUnionType(std::move(computed_string_prop_types)), "x", in_const_context);
        }
    }

    checker::Type *return_type = checker->Allocator()->New<checker::ObjectLiteralType>(desc);
    return_type->AsObjectType()->AddObjectFlag(checker::ObjectFlags::RESOLVED_MEMBERS |
                                               checker::ObjectFlags::CHECK_EXCESS_PROPS);
    return return_type;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::OmittedExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    return checker->GlobalUndefinedType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::OpaqueTypeNode *expr) const
{
    return expr->TsType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SequenceExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SuperExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TaggedTemplateExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TemplateLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE(aszilagyi)
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ThisExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::CheckDeleteKeyword([[maybe_unused]] checker::TSChecker *checker,
                                              ir::UnaryExpression *expr) const
{
    checker::Type *prop_type = expr->argument_->Check(checker);
    if (!expr->Argument()->IsMemberExpression()) {
        checker->ThrowTypeError("The operand of a delete operator must be a property reference.",
                                expr->Argument()->Start());
    }
    if (prop_type->Variable()->HasFlag(varbinder::VariableFlags::READONLY)) {
        checker->ThrowTypeError("The operand of a delete operator cannot be a readonly property.",
                                expr->Argument()->Start());
    }
    if (!prop_type->Variable()->HasFlag(varbinder::VariableFlags::OPTIONAL)) {
        checker->ThrowTypeError("The operand of a delete operator must be a optional.", expr->Argument()->Start());
    }
    return checker->GlobalBooleanType();
}

checker::Type *TSAnalyzer::CheckLiteral([[maybe_unused]] checker::TSChecker *checker, ir::UnaryExpression *expr) const
{
    if (!expr->Argument()->IsLiteral()) {
        return nullptr;
    }

    const ir::Literal *lit = expr->Argument()->AsLiteral();
    if (lit->IsNumberLiteral()) {
        auto number_value = lit->AsNumberLiteral()->Number().GetDouble();
        if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_PLUS) {
            return checker->CreateNumberLiteralType(number_value);
        }
        if (expr->OperatorType() == lexer::TokenType::PUNCTUATOR_MINUS) {
            return checker->CreateNumberLiteralType(-number_value);
        }
    } else if (lit->IsBigIntLiteral() && expr->OperatorType() == lexer::TokenType::PUNCTUATOR_MINUS) {
        return checker->CreateBigintLiteralType(lit->AsBigIntLiteral()->Str(), true);
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::UnaryExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *operand_type = expr->argument_->Check(checker);

    if (expr->operator_ == lexer::TokenType::KEYW_TYPEOF) {
        return operand_type;
    }

    if (expr->operator_ == lexer::TokenType::KEYW_DELETE) {
        return CheckDeleteKeyword(checker, expr);
    }

    auto *res = CheckLiteral(checker, expr);
    if (res != nullptr) {
        return res;
    }

    switch (expr->operator_) {
        case lexer::TokenType::PUNCTUATOR_PLUS:
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::PUNCTUATOR_TILDE: {
            checker->CheckNonNullType(operand_type, expr->Start());
            // NOTE: aszilagyi. check Symbol like types

            if (expr->operator_ == lexer::TokenType::PUNCTUATOR_PLUS) {
                if (checker::TSChecker::MaybeTypeOfKind(operand_type, checker::TypeFlag::BIGINT_LIKE)) {
                    checker->ThrowTypeError({"Operator '+' cannot be applied to type '", operand_type, "'"},
                                            expr->Start());
                }

                return checker->GlobalNumberType();
            }

            return checker->GetUnaryResultType(operand_type);
        }
        case lexer::TokenType::PUNCTUATOR_EXCLAMATION_MARK: {
            checker->CheckTruthinessOfType(operand_type, expr->Start());
            auto facts = operand_type->GetTypeFacts();
            if ((facts & checker::TypeFacts::TRUTHY) != 0) {
                return checker->GlobalFalseType();
            }

            if ((facts & checker::TypeFacts::FALSY) != 0) {
                return checker->GlobalTrueType();
            }

            return checker->GlobalBooleanType();
        }
        default: {
            UNREACHABLE();
        }
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::UpdateExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *operand_type = expr->argument_->Check(checker);
    checker->CheckNonNullType(operand_type, expr->Start());

    if (!operand_type->HasTypeFlag(checker::TypeFlag::VALID_ARITHMETIC_TYPE)) {
        checker->ThrowTypeError("An arithmetic operand must be of type 'any', 'number', 'bigint' or an enum type.",
                                expr->Start());
    }

    checker->CheckReferenceExpression(
        expr->argument_, "The operand of an increment or decrement operator must be a variable or a property access",
        "The operand of an increment or decrement operator may not be an optional property access");

    return checker->GetUnaryResultType(operand_type);
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::YieldExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi.
    return checker->GlobalAnyType();
}
// compile methods for LITERAL EXPRESSIONS in alphabetical order
checker::Type *TSAnalyzer::Check(ir::BigIntLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    auto search = checker->BigintLiteralMap().find(expr->Str());
    if (search != checker->BigintLiteralMap().end()) {
        return search->second;
    }

    auto *new_bigint_literal_type = checker->Allocator()->New<checker::BigintLiteralType>(expr->Str(), false);
    checker->BigintLiteralMap().insert({expr->Str(), new_bigint_literal_type});
    return new_bigint_literal_type;
}

checker::Type *TSAnalyzer::Check(ir::BooleanLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    return expr->Value() ? checker->GlobalTrueType() : checker->GlobalFalseType();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::CharLiteral *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::NullLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    return checker->GlobalNullType();
}

checker::Type *TSAnalyzer::Check(ir::NumberLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    auto search = checker->NumberLiteralMap().find(expr->Number().GetDouble());
    if (search != checker->NumberLiteralMap().end()) {
        return search->second;
    }

    auto *new_num_literal_type = checker->Allocator()->New<checker::NumberLiteralType>(expr->Number().GetDouble());
    checker->NumberLiteralMap().insert({expr->Number().GetDouble(), new_num_literal_type});
    return new_num_literal_type;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::RegExpLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    // NOTE: aszilagyi
    return checker->GlobalAnyType();
}

checker::Type *TSAnalyzer::Check(ir::StringLiteral *expr) const
{
    TSChecker *checker = GetTSChecker();
    auto search = checker->StringLiteralMap().find(expr->Str());
    if (search != checker->StringLiteralMap().end()) {
        return search->second;
    }

    auto *new_str_literal_type = checker->Allocator()->New<checker::StringLiteralType>(expr->Str());
    checker->StringLiteralMap().insert({expr->Str(), new_str_literal_type});

    return new_str_literal_type;
}

checker::Type *TSAnalyzer::Check(ir::UndefinedLiteral *expr) const
{
    (void)expr;
    UNREACHABLE();
}

// compile methods for MODULE-related nodes in alphabetical order
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportAllDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportDefaultDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportNamedDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ExportSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportDefaultSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportNamespaceSpecifier *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ImportSpecifier *st) const
{
    UNREACHABLE();
}
// compile methods for STATEMENTS in alphabetical order
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::AssertStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::BlockStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    for (auto *it : st->Statements()) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::BreakStatement *st) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ClassDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ContinueStatement *st) const
{
    (void)st;
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::DebuggerStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::DoWhileStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker::Type *test_type = st->Test()->Check(checker);
    checker->CheckTruthinessOfType(test_type, st->Test()->Start());
    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::EmptyStatement *st) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::ExpressionStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    return st->GetExpression()->Check(checker);
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ForInStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ForOfStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::ForUpdateStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    if (st->Init() != nullptr) {
        st->Init()->Check(checker);
    }

    if (st->Test() != nullptr) {
        checker::Type *test_type = st->Test()->Check(checker);
        checker->CheckTruthinessOfType(test_type, st->Start());
    }

    if (st->Update() != nullptr) {
        st->Update()->Check(checker);
    }

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::FunctionDeclaration *st) const
{
    TSChecker *checker = GetTSChecker();
    if (st->Function()->IsOverload()) {
        return nullptr;
    }

    const util::StringView &func_name = st->Function()->Id()->Name();
    auto result = checker->Scope()->Find(func_name);
    ASSERT(result.variable);

    checker::ScopeContext scope_ctx(checker, st->Function()->Scope());

    if (result.variable->TsType() == nullptr) {
        checker->InferFunctionDeclarationType(result.variable->Declaration()->AsFunctionDecl(), result.variable);
    }

    st->Function()->Body()->Check(checker);

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::IfStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *test_type = st->test_->Check(checker);
    checker->CheckTruthinessOfType(test_type, st->Start());
    checker->CheckTestingKnownTruthyCallableOrAwaitableType(st->test_, test_type, st->consequent_);

    st->consequent_->Check(checker);

    if (st->Alternate() != nullptr) {
        st->alternate_->Check(checker);
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::LabelledStatement *st) const
{
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

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::SwitchCaseStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::SwitchStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker::Type *expr_type = st->discriminant_->Check(checker);
    bool expr_is_literal = checker::TSChecker::IsLiteralType(expr_type);

    for (auto *it : st->Cases()) {
        if (it->Test() != nullptr) {
            checker::Type *case_type = it->Test()->Check(checker);
            bool case_is_literal = checker::TSChecker::IsLiteralType(case_type);
            checker::Type *compared_expr_type = expr_type;

            if (!case_is_literal || !expr_is_literal) {
                case_type = case_is_literal ? checker->GetBaseTypeOfLiteralType(case_type) : case_type;
                compared_expr_type = checker->GetBaseTypeOfLiteralType(expr_type);
            }

            if (!checker->IsTypeEqualityComparableTo(compared_expr_type, case_type) &&
                !checker->IsTypeComparableTo(case_type, compared_expr_type)) {
                checker->ThrowTypeError({"Type ", case_type, " is not comparable to type ", compared_expr_type},
                                        it->Test()->Start());
            }
        }

        for (auto *case_stmt : it->Consequent()) {
            case_stmt->Check(checker);
        }
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::ThrowStatement *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TryStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    st->Block()->Check(checker);

    for (auto *catch_clause : st->CatchClauses()) {
        if (catch_clause != nullptr) {
            catch_clause->Check(checker);
        }
    }

    if (st->HasFinalizer()) {
        st->finalizer_->Check(checker);
    }

    return nullptr;
}

static void CheckSimpleVariableDeclaration(checker::TSChecker *checker, ir::VariableDeclarator *declarator)
{
    varbinder::Variable *const binding_var = declarator->Id()->AsIdentifier()->Variable();
    checker::Type *previous_type = binding_var->TsType();
    auto *const type_annotation = declarator->Id()->AsIdentifier()->TypeAnnotation();
    auto *const initializer = declarator->Init();
    const bool is_const = declarator->Parent()->AsVariableDeclaration()->Kind() ==
                          ir::VariableDeclaration::VariableDeclarationKind::CONST;

    if (is_const) {
        checker->AddStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    }

    if (type_annotation != nullptr) {
        type_annotation->Check(checker);
    }

    if (type_annotation != nullptr && initializer != nullptr) {
        checker::Type *const annotation_type = type_annotation->GetType(checker);
        checker->ElaborateElementwise(annotation_type, initializer, declarator->Id()->Start());
        binding_var->SetTsType(annotation_type);
    } else if (type_annotation != nullptr) {
        binding_var->SetTsType(type_annotation->GetType(checker));
    } else if (initializer != nullptr) {
        checker::Type *initializer_type = checker->CheckTypeCached(initializer);

        if (!is_const) {
            initializer_type = checker->GetBaseTypeOfLiteralType(initializer_type);
        }

        if (initializer_type->IsNullType()) {
            checker->ThrowTypeError(
                {"Cannot infer type for variable '", declarator->Id()->AsIdentifier()->Name(), "'."},
                declarator->Id()->Start());
        }

        binding_var->SetTsType(initializer_type);
    } else {
        checker->ThrowTypeError({"Variable ", declarator->Id()->AsIdentifier()->Name(), " implicitly has an any type."},
                                declarator->Id()->Start());
    }

    if (previous_type != nullptr) {
        checker->IsTypeIdenticalTo(binding_var->TsType(), previous_type,
                                   {"Subsequent variable declaration must have the same type. Variable '",
                                    binding_var->Name(), "' must be of type '", previous_type, "', but here has type '",
                                    binding_var->TsType(), "'."},
                                   declarator->Id()->Start());
    }

    checker->RemoveStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
}

checker::Type *TSAnalyzer::Check(ir::VariableDeclarator *st) const
{
    TSChecker *checker = GetTSChecker();

    if (st->TsType() == st->CHECKED) {
        return nullptr;
    }

    if (st->Id()->IsIdentifier()) {
        CheckSimpleVariableDeclaration(checker, st);
        st->SetTsType(st->CHECKED);
        return nullptr;
    }

    if (st->Id()->IsArrayPattern()) {
        auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
        checker::ArrayDestructuringContext(checker, st->Id(), false,
                                           st->Id()->AsArrayPattern()->TypeAnnotation() == nullptr,
                                           st->Id()->AsArrayPattern()->TypeAnnotation(), st->Init())
            .Start();

        st->SetTsType(st->CHECKED);
        return nullptr;
    }

    ASSERT(st->Id()->IsObjectPattern());
    auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
    checker::ObjectDestructuringContext(checker, st->Id(), false,
                                        st->Id()->AsObjectPattern()->TypeAnnotation() == nullptr,
                                        st->Id()->AsObjectPattern()->TypeAnnotation(), st->Init())
        .Start();

    st->SetTsType(st->CHECKED);
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::VariableDeclaration *st) const
{
    TSChecker *checker = GetTSChecker();
    for (auto *it : st->Declarators()) {
        it->Check(checker);
    }

    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::WhileStatement *st) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, st->Scope());

    checker::Type *test_type = st->Test()->Check(checker);
    checker->CheckTruthinessOfType(test_type, st->Test()->Start());

    st->Body()->Check(checker);
    return nullptr;
}
// from ts folder
checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSAnyKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSArrayType *node) const
{
    TSChecker *checker = GetTSChecker();
    node->element_type_->Check(checker);
    return nullptr;
}

static bool IsValidConstAssertionArgument(checker::Checker *checker, const ir::AstNode *arg)
{
    switch (arg->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL:
        case ir::AstNodeType::STRING_LITERAL:
        case ir::AstNodeType::BIGINT_LITERAL:
        case ir::AstNodeType::BOOLEAN_LITERAL:
        case ir::AstNodeType::ARRAY_EXPRESSION:
        case ir::AstNodeType::OBJECT_EXPRESSION:
        case ir::AstNodeType::TEMPLATE_LITERAL: {
            return true;
        }
        case ir::AstNodeType::UNARY_EXPRESSION: {
            const ir::UnaryExpression *unary_expr = arg->AsUnaryExpression();
            lexer::TokenType op = unary_expr->OperatorType();
            const ir::Expression *unary_arg = unary_expr->Argument();
            return (op == lexer::TokenType::PUNCTUATOR_MINUS && unary_arg->IsLiteral() &&
                    (unary_arg->AsLiteral()->IsNumberLiteral() || unary_arg->AsLiteral()->IsBigIntLiteral())) ||
                   (op == lexer::TokenType::PUNCTUATOR_PLUS && unary_arg->IsLiteral() &&
                    unary_arg->AsLiteral()->IsNumberLiteral());
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            const ir::MemberExpression *member_expr = arg->AsMemberExpression();
            if (member_expr->Object()->IsIdentifier()) {
                auto result = checker->Scope()->Find(member_expr->Object()->AsIdentifier()->Name());
                constexpr auto ENUM_LITERAL_TYPE = checker::EnumLiteralType::EnumLiteralTypeKind::LITERAL;
                if (result.variable != nullptr &&
                    result.variable->TsType()->HasTypeFlag(checker::TypeFlag::ENUM_LITERAL) &&
                    result.variable->TsType()->AsEnumLiteralType()->Kind() == ENUM_LITERAL_TYPE) {
                    return true;
                }
            }
            return false;
        }
        default:
            return false;
    }
}

checker::Type *TSAnalyzer::Check(ir::TSAsExpression *expr) const
{
    TSChecker *checker = GetTSChecker();
    if (expr->IsConst()) {
        auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::IN_CONST_CONTEXT);
        checker::Type *expr_type = expr->Expr()->Check(checker);

        if (!IsValidConstAssertionArgument(checker, expr->Expr())) {
            checker->ThrowTypeError(
                "A 'const' assertions can only be applied to references to enum members, or string, number, "
                "boolean, array, or object literals.",
                expr->Expr()->Start());
        }

        return expr_type;
    }

    auto context = checker::SavedCheckerContext(checker, checker::CheckerStatus::NO_OPTS);

    expr->TypeAnnotation()->Check(checker);
    checker::Type *expr_type = checker->GetBaseTypeOfLiteralType(expr->Expr()->Check(checker));
    checker::Type *target_type = expr->TypeAnnotation()->GetType(checker);

    checker->IsTypeComparableTo(
        target_type, expr_type,
        {"Conversion of type '", expr_type, "' to type '", target_type,
         "' may be a mistake because neither type sufficiently overlaps with the other. If this was ",
         "intentional, convert the expression to 'unknown' first."},
        expr->Start());

    return target_type;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSBigintKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSBooleanKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSClassImplements *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSConditionalType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSConstructorType *node) const
{
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, node->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(node->Params(), signature_info);
    node->return_type_->Check(checker);
    auto *construct_signature =
        checker->Allocator()->New<checker::Signature>(signature_info, node->return_type_->GetType(checker));

    return checker->CreateConstructorTypeWithSignature(construct_signature);
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

    // NOTE (aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

static uint32_t ToUInt(double num)
{
    if (num >= std::numeric_limits<uint32_t>::min() && num <= std::numeric_limits<uint32_t>::max()) {
        return static_cast<int32_t>(num);
    }

    // NOTE (aszilagyi): Perform ECMA defined toInt conversion

    return 0;
}

varbinder::EnumMemberResult GetOperationResulForDouble(lexer::TokenType type, varbinder::EnumMemberResult left,
                                                       varbinder::EnumMemberResult right)
{
    switch (type) {
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
            return false;
        }
    }
}

varbinder::EnumMemberResult TSAnalyzer::EvaluateBinaryExpression(checker::TSChecker *checker,
                                                                 varbinder::EnumVariable *enum_var,
                                                                 const ir::BinaryExpression *expr) const
{
    varbinder::EnumMemberResult left = EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Left());
    varbinder::EnumMemberResult right = EvaluateEnumMember(checker, enum_var, expr->AsBinaryExpression()->Right());
    if (std::holds_alternative<double>(left) && std::holds_alternative<double>(right)) {
        GetOperationResulForDouble(expr->AsBinaryExpression()->OperatorType(), left, right);
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

// NOLINTBEGIN(modernize-avoid-c-arrays)
static constexpr char const INVALID_COMPUTED_WITH_STRING[] =
    "Computed values are not permitted in an enum with string valued members.";
static constexpr char const INVALID_CONST_MEMBER[] =
    "'const' enum member initializers can only contain literal values and other computed enum values.";
static constexpr char const INVALID_CONST_NAN[] =
    "'const' enum member initializer was evaluated to disallowed value 'NaN'.";
static constexpr char const INVALID_CONST_INF[] =
    "'const' enum member initializer was evaluated to a non-finite value.";
// NOLINTEND(modernize-avoid-c-arrays)

void TSAnalyzer::InferEnumVariableType(varbinder::EnumVariable *variable, double *value, bool *init_next,
                                       bool *is_literal_enum, bool is_const_enum) const
{
    TSChecker *checker = GetTSChecker();
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
    if (IsComputedEnumMember(init) && *is_literal_enum) {
        checker->ThrowTypeError(INVALID_COMPUTED_WITH_STRING, init->Start());
    }

    varbinder::EnumMemberResult res = EvaluateEnumMember(checker, variable, init);
    if (std::holds_alternative<util::StringView>(res)) {
        *is_literal_enum = true;
        variable->SetTsType(checker->GlobalStringType());
        *init_next = true;
        return;
    }

    if (std::holds_alternative<bool>(res)) {
        if (is_const_enum) {
            checker->ThrowTypeError(INVALID_CONST_MEMBER, init->Start());
        }

        *init_next = true;
        return;
    }

    ASSERT(std::holds_alternative<double>(res));
    variable->SetValue(res);

    *value = std::get<double>(res);
    if (is_const_enum && std::isnan(*value)) {
        checker->ThrowTypeError(INVALID_CONST_NAN, init->Start());
    }

    if (is_const_enum && std::isinf(*value)) {
        checker->ThrowTypeError(INVALID_CONST_INF, init->Start());
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
    size_t locals_size = enum_scope->Decls().size();

    for (size_t i = 0; i < locals_size; i++) {
        const util::StringView &current_name = enum_scope->Decls()[i]->Name();
        varbinder::Variable *current_var =
            enum_scope->FindLocal(current_name, varbinder::ResolveBindingOptions::BINDINGS);
        ASSERT(current_var && current_var->IsEnumVariable());
        InferEnumVariableType(current_var->AsEnumVariable(), &value, &init_next, &is_literal_enum, is_const);
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
    TSChecker *checker = GetTSChecker();
    checker::ScopeContext scope_ctx(checker, node->Scope());

    auto *signature_info = checker->Allocator()->New<checker::SignatureInfo>(checker->Allocator());
    checker->CheckFunctionParameterDeclarations(node->Params(), signature_info);
    node->return_type_->Check(checker);
    auto *call_signature =
        checker->Allocator()->New<checker::Signature>(signature_info, node->return_type_->GetType(checker));

    return checker->CreateFunctionTypeWithSignature(call_signature);
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSImportEqualsDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSImportType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSIndexedAccessType *node) const
{
    TSChecker *checker = GetTSChecker();
    node->object_type_->Check(checker);
    node->index_type_->Check(checker);
    checker::Type *resolved = node->GetType(checker);

    if (resolved != nullptr) {
        return nullptr;
    }

    checker::Type *index_type = checker->CheckTypeCached(node->index_type_);

    if (!index_type->HasTypeFlag(checker::TypeFlag::STRING_LIKE | checker::TypeFlag::NUMBER_LIKE)) {
        checker->ThrowTypeError({"Type ", index_type, " cannot be used as index type"}, node->IndexType()->Start());
    }

    if (index_type->IsNumberType()) {
        checker->ThrowTypeError("Type has no matching signature for type 'number'", node->Start());
    }

    checker->ThrowTypeError("Type has no matching signature for type 'string'", node->Start());
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSInferType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSInterfaceBody *expr) const
{
    TSChecker *checker = GetTSChecker();
    for (auto *it : expr->Body()) {
        it->Check(checker);
    }

    return nullptr;
}

static void CheckInheritedPropertiesAreIdentical(checker::TSChecker *checker, checker::InterfaceType *type,
                                                 const lexer::SourcePosition &loc_info)
{
    checker->GetBaseTypes(type);

    size_t constexpr BASE_SIZE_LIMIT = 2;
    if (type->Bases().size() < BASE_SIZE_LIMIT) {
        return;
    }

    checker->ResolveDeclaredMembers(type);

    checker::InterfacePropertyMap properties;

    for (auto *it : type->Properties()) {
        properties.insert({it->Name(), {it, type}});
    }

    for (auto *base : type->Bases()) {
        checker->ResolveStructuredTypeMembers(base);
        ArenaVector<varbinder::LocalVariable *> inherited_properties(checker->Allocator()->Adapter());
        base->AsInterfaceType()->CollectProperties(&inherited_properties);

        for (auto *inherited_prop : inherited_properties) {
            auto res = properties.find(inherited_prop->Name());
            if (res == properties.end()) {
                properties.insert({inherited_prop->Name(), {inherited_prop, base->AsInterfaceType()}});
            } else if (res->second.second != type) {
                checker::Type *source_type = checker->GetTypeOfVariable(inherited_prop);
                checker::Type *target_type = checker->GetTypeOfVariable(res->second.first);
                checker->IsTypeIdenticalTo(source_type, target_type,
                                           {"Interface '", type, "' cannot simultaneously extend types '",
                                            res->second.second, "' and '", base->AsInterfaceType(), "'."},
                                           loc_info);
            }
        }
    }
}

checker::Type *TSAnalyzer::Check(ir::TSInterfaceDeclaration *st) const
{
    TSChecker *checker = GetTSChecker();
    varbinder::Variable *var = st->Id()->Variable();
    ASSERT(var->Declaration()->Node() && var->Declaration()->Node()->IsTSInterfaceDeclaration());

    if (st == var->Declaration()->Node()) {
        checker::Type *resolved_type = var->TsType();

        if (resolved_type == nullptr) {
            checker::ObjectDescriptor *desc =
                checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
            resolved_type =
                checker->Allocator()->New<checker::InterfaceType>(checker->Allocator(), st->Id()->Name(), desc);
            resolved_type->SetVariable(var);
            var->SetTsType(resolved_type);
        }

        checker::InterfaceType *resolved_interface = resolved_type->AsObjectType()->AsInterfaceType();
        CheckInheritedPropertiesAreIdentical(checker, resolved_interface, st->Id()->Start());

        for (auto *base : resolved_interface->Bases()) {
            checker->IsTypeAssignableTo(
                resolved_interface, base,
                {"Interface '", st->Id()->Name(), "' incorrectly extends interface '", base, "'"}, st->Id()->Start());
        }

        checker->CheckIndexConstraints(resolved_interface);
    }

    st->Body()->Check(checker);

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSInterfaceHeritage *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSIntersectionType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSLiteralType *node) const
{
    TSChecker *checker = GetTSChecker();
    node->GetType(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSMappedType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSModuleBlock *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSModuleDeclaration *st) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSNamedTupleMember *node) const
{
    TSChecker *checker = GetTSChecker();
    node->ElementType()->Check(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNeverKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNonNullExpression *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNullKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSNumberKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSObjectKeyword *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSParameterProperty *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSParenthesizedType *node) const
{
    TSChecker *checker = GetTSChecker();
    node->type_->Check(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSQualifiedName *expr) const
{
    TSChecker *checker = GetTSChecker();
    checker::Type *base_type = checker->CheckNonNullType(expr->Left()->Check(checker), expr->Left()->Start());
    varbinder::Variable *prop = checker->GetPropertyOfType(base_type, expr->Right()->Name());

    if (prop != nullptr) {
        return checker->GetTypeOfVariable(prop);
    }

    if (base_type->IsObjectType()) {
        checker::ObjectType *obj_type = base_type->AsObjectType();

        if (obj_type->StringIndexInfo() != nullptr) {
            return obj_type->StringIndexInfo()->GetType();
        }
    }

    checker->ThrowTypeError({"Property ", expr->Right()->Name(), " does not exist on this type."},
                            expr->Right()->Start());
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSStringKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSThisType *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTupleType *node) const
{
    TSChecker *checker = GetTSChecker();
    for (auto *it : node->ElementType()) {
        it->Check(checker);
    }

    node->GetType(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSTypeAliasDeclaration *st) const
{
    TSChecker *checker = GetTSChecker();
    st->TypeAnnotation()->Check(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeAssertion *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeLiteral *node) const
{
    TSChecker *checker = GetTSChecker();

    for (auto *it : node->Members()) {
        it->Check(checker);
    }

    checker::Type *type = node->GetType(checker);
    checker->CheckIndexConstraints(type);

    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeOperator *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameter *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterDeclaration *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypeParameterInstantiation *expr) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSTypePredicate *node) const
{
    UNREACHABLE();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeQuery *node) const
{
    TSChecker *checker = GetTSChecker();
    if (node->TsType() != nullptr) {
        return node->TsType();
    }

    node->SetTsType(node->expr_name_->Check(checker));
    return node->TsType();
}

checker::Type *TSAnalyzer::Check(ir::TSTypeReference *node) const
{
    TSChecker *checker = GetTSChecker();
    node->GetType(checker);
    return nullptr;
}

checker::Type *TSAnalyzer::Check([[maybe_unused]] ir::TSUndefinedKeyword *node) const
{
    return nullptr;
}

checker::Type *TSAnalyzer::Check(ir::TSUnionType *node) const
{
    TSChecker *checker = GetTSChecker();
    for (auto *it : node->Types()) {
        it->Check(checker);
    }

    node->GetType(checker);
    return nullptr;
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
