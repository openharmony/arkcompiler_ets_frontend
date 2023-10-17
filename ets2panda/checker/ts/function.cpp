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

#include "ir/typeNode.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/property.h"
#include "ir/base/spreadElement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/functionDeclaration.h"
#include "util/helpers.h"
#include "binder/variable.h"
#include "binder/scope.h"
#include "binder/declaration.h"

#include "checker/TSchecker.h"
#include "checker/ts/destructuringContext.h"
#include "checker/types/ts/objectDescriptor.h"
#include "checker/types/ts/objectType.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace panda::es2panda::checker {
Type *TSChecker::HandleFunctionReturn(ir::ScriptFunction *func)
{
    if (func->ReturnTypeAnnotation() != nullptr) {
        func->ReturnTypeAnnotation()->Check(this);
        Type *return_type = func->ReturnTypeAnnotation()->GetType(this);

        if (func->IsArrow() && func->Body()->IsExpression()) {
            ElaborateElementwise(return_type, func->Body()->AsExpression(), func->Body()->Start());
        }

        if (return_type->IsNeverType()) {
            ThrowTypeError("A function returning 'never' cannot have a reachable end point.",
                           func->ReturnTypeAnnotation()->Start());
        }

        if (!MaybeTypeOfKind(return_type, TypeFlag::ANY_OR_VOID)) {
            CheckAllCodePathsInNonVoidFunctionReturnOrThrow(
                func, func->ReturnTypeAnnotation()->Start(),
                "A function whose declared type is neither 'void' nor 'any' must return a value.");
        }

        return return_type;
    }

    if (func->Declare()) {
        return GlobalAnyType();
    }

    if (func->IsArrow() && func->Body()->IsExpression()) {
        return func->Body()->Check(this);
    }

    ArenaVector<Type *> return_types(Allocator()->Adapter());
    CollectTypesFromReturnStatements(func->Body(), &return_types);

    if (return_types.empty()) {
        return GlobalVoidType();
    }

    if (return_types.size() == 1 && return_types[0] == GlobalResolvingReturnType()) {
        ThrowReturnTypeCircularityError(func);
    }

    for (auto *it : return_types) {
        if (it == GlobalResolvingReturnType()) {
            ThrowReturnTypeCircularityError(func);
        }
    }

    return CreateUnionType(std::move(return_types));
}

void TSChecker::ThrowReturnTypeCircularityError(ir::ScriptFunction *func)
{
    if (func->ReturnTypeAnnotation() != nullptr) {
        ThrowTypeError("Return type annotation circularly reference itself", func->ReturnTypeAnnotation()->Start());
    }

    if (func->Id() != nullptr) {
        ThrowTypeError({func->Id()->AsIdentifier()->Name(),
                        " implicitly has return type 'any' because it does not have a return type annotation and is "
                        "referenced directly or indirectly in one of its return expressions."},
                       func->Id()->Start());
    }

    ThrowTypeError(
        "Function implicitly has return type 'any' because it does not have a return type annotation and is "
        "referenced directly or indirectly in one of its return expressions.",
        func->Start());
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionIdentifierParameter(
    ir::Identifier *param)
{
    ASSERT(param->Variable());
    binder::Variable *param_var = param->Variable();
    bool is_optional = param->IsOptional();

    if (param->TypeAnnotation() == nullptr) {
        ThrowTypeError({"Parameter ", param->Name(), " implicitly has any type."}, param->Start());
    }

    if (is_optional) {
        param_var->AddFlag(binder::VariableFlags::OPTIONAL);
    }

    param->TypeAnnotation()->Check(this);
    param_var->SetTsType(param->TypeAnnotation()->GetType(this));
    return {param_var->AsLocalVariable(), nullptr, is_optional};
}

Type *TSChecker::CreateParameterTypeForArrayAssignmentPattern(ir::ArrayExpression *array_pattern, Type *inferred_type)
{
    if (!inferred_type->IsObjectType()) {
        return inferred_type;
    }

    ASSERT(inferred_type->AsObjectType()->IsTupleType());
    TupleType *inferred_tuple = inferred_type->AsObjectType()->AsTupleType();

    if (inferred_tuple->FixedLength() > array_pattern->Elements().size()) {
        return inferred_type;
    }

    TupleType *new_tuple =
        inferred_tuple->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsObjectType()->AsTupleType();

    for (uint32_t index = inferred_tuple->FixedLength(); index < array_pattern->Elements().size(); index++) {
        util::StringView member_index = util::Helpers::ToStringView(Allocator(), index);
        binder::LocalVariable *new_member = binder::Scope::CreateVar(
            Allocator(), member_index, binder::VariableFlags::PROPERTY | binder::VariableFlags::OPTIONAL, nullptr);
        new_member->SetTsType(GlobalAnyType());
        new_tuple->AddProperty(new_member);
    }

    return new_tuple;
}

Type *TSChecker::CreateParameterTypeForObjectAssignmentPattern(ir::ObjectExpression *object_pattern,
                                                               Type *inferred_type)
{
    if (!inferred_type->IsObjectType()) {
        return inferred_type;
    }

    ObjectType *new_object =
        inferred_type->Instantiate(Allocator(), Relation(), GetGlobalTypesHolder())->AsObjectType();

    for (auto *it : object_pattern->Properties()) {
        if (it->IsRestElement()) {
            continue;
        }

        ir::Property *prop = it->AsProperty();
        binder::LocalVariable *found_var = new_object->GetProperty(prop->Key()->AsIdentifier()->Name(), true);

        if (found_var != nullptr) {
            if (prop->Value()->IsAssignmentPattern()) {
                found_var->AddFlag(binder::VariableFlags::OPTIONAL);
            }

            continue;
        }

        ASSERT(prop->Value()->IsAssignmentPattern());
        ir::AssignmentExpression *assignment_pattern = prop->Value()->AsAssignmentPattern();

        binder::LocalVariable *new_prop =
            binder::Scope::CreateVar(Allocator(), prop->Key()->AsIdentifier()->Name(),
                                     binder::VariableFlags::PROPERTY | binder::VariableFlags::OPTIONAL, nullptr);
        new_prop->SetTsType(GetBaseTypeOfLiteralType(CheckTypeCached(assignment_pattern->Right())));
        new_object->AddProperty(new_prop);
    }

    new_object->AddObjectFlag(ObjectFlags::RESOLVED_MEMBERS);
    return new_object;
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionAssignmentPatternParameter(
    ir::AssignmentExpression *param)
{
    if (param->Left()->IsIdentifier()) {
        ir::Identifier *param_ident = param->Left()->AsIdentifier();
        binder::Variable *param_var = param_ident->Variable();
        ASSERT(param_var);

        if (param_ident->TypeAnnotation() != nullptr) {
            param_ident->TypeAnnotation()->Check(this);
            Type *param_type = param_ident->TypeAnnotation()->GetType(this);
            param_var->SetTsType(param_type);
            ElaborateElementwise(param_type, param->Right(), param_ident->Start());
            return {param_var->AsLocalVariable(), nullptr, true};
        }

        param_var->SetTsType(GetBaseTypeOfLiteralType(param->Right()->Check(this)));
        param_var->AddFlag(binder::VariableFlags::OPTIONAL);
        return {param_var->AsLocalVariable(), nullptr, true};
    }

    Type *param_type = nullptr;
    std::stringstream ss;

    auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE | CheckerStatus::IN_PARAMETER);

    if (param->Left()->IsArrayPattern()) {
        ir::ArrayExpression *array_pattern = param->Left()->AsArrayPattern();
        auto context = ArrayDestructuringContext(this, array_pattern, false, true, array_pattern->TypeAnnotation(),
                                                 param->Right());
        context.Start();
        param_type = CreateParameterTypeForArrayAssignmentPattern(array_pattern, context.InferredType());
        CreatePatternParameterName(param->Left(), ss);
    } else {
        ir::ObjectExpression *object_pattern = param->Left()->AsObjectPattern();
        auto context = ObjectDestructuringContext(this, object_pattern, false, true, object_pattern->TypeAnnotation(),
                                                  param->Right());
        context.Start();
        param_type = CreateParameterTypeForObjectAssignmentPattern(object_pattern, context.InferredType());
        CreatePatternParameterName(param->Left(), ss);
    }

    util::UString pn(ss.str(), Allocator());
    binder::LocalVariable *pattern_var =
        binder::Scope::CreateVar(Allocator(), pn.View(), binder::VariableFlags::NONE, param);
    pattern_var->SetTsType(param_type);
    pattern_var->AddFlag(binder::VariableFlags::OPTIONAL);
    return {pattern_var->AsLocalVariable(), nullptr, true};
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionRestParameter(
    ir::SpreadElement *param, SignatureInfo *signature_info)
{
    ir::TypeNode *type_annotation = nullptr;
    if (param->Argument() != nullptr) {
        type_annotation = param->Argument()->AsAnnotatedExpression()->TypeAnnotation();
    }

    Type *rest_type = Allocator()->New<ArrayType>(GlobalAnyType());

    if (type_annotation != nullptr) {
        type_annotation->Check(this);
        rest_type = type_annotation->GetType(this);
        if (!rest_type->IsArrayType()) {
            ThrowTypeError("A rest parameter must be of an array type", param->Start());
        }
    }

    switch (param->Argument()->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            ir::Identifier *rest_ident = param->Argument()->AsIdentifier();
            ASSERT(rest_ident->Variable());
            rest_ident->Variable()->SetTsType(rest_type->AsArrayType()->ElementType());
            return {nullptr, rest_ident->Variable()->AsLocalVariable(), false};
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            ASSERT(param->Argument()->IsObjectPattern());
            auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE);
            auto destructuring_context =
                ObjectDestructuringContext(this, param->Argument(), false, false, nullptr, nullptr);
            destructuring_context.SetInferredType(rest_type);
            destructuring_context.SetSignatureInfo(signature_info);
            destructuring_context.Start();
            return {nullptr, nullptr, false};
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE);
            auto destructuring_context =
                ArrayDestructuringContext(this, param->Argument(), false, false, nullptr, nullptr);
            destructuring_context.SetInferredType(rest_type);
            destructuring_context.SetSignatureInfo(signature_info);
            destructuring_context.Start();
            return {nullptr, nullptr, false};
        }
        default: {
            UNREACHABLE();
        }
    }
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionArrayPatternParameter(
    ir::ArrayExpression *param)
{
    std::stringstream ss;
    CreatePatternParameterName(param, ss);
    util::UString pn(ss.str(), Allocator());
    binder::LocalVariable *pattern_var =
        binder::Scope::CreateVar(Allocator(), pn.View(), binder::VariableFlags::NONE, param);

    if (param->TypeAnnotation() != nullptr) {
        auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE);
        auto destructuring_context =
            ArrayDestructuringContext(this, param->AsArrayPattern(), false, false, param->TypeAnnotation(), nullptr);
        destructuring_context.Start();
        pattern_var->SetTsType(destructuring_context.InferredType());
        return {pattern_var->AsLocalVariable(), nullptr, false};
    }

    pattern_var->SetTsType(param->CheckPattern(this));
    return {pattern_var->AsLocalVariable(), nullptr, false};
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionObjectPatternParameter(
    ir::ObjectExpression *param)
{
    std::stringstream ss;
    CreatePatternParameterName(param, ss);
    util::UString pn(ss.str(), Allocator());
    binder::LocalVariable *pattern_var =
        binder::Scope::CreateVar(Allocator(), pn.View(), binder::VariableFlags::NONE, param);

    if (param->TypeAnnotation() != nullptr) {
        auto saved_context = SavedCheckerContext(this, CheckerStatus::FORCE_TUPLE);
        auto destructuring_context =
            ObjectDestructuringContext(this, param->AsObjectPattern(), false, false, param->TypeAnnotation(), nullptr);
        destructuring_context.Start();
        pattern_var->SetTsType(destructuring_context.InferredType());
        return {pattern_var->AsLocalVariable(), nullptr, false};
    }

    pattern_var->SetTsType(param->CheckPattern(this));
    return {pattern_var->AsLocalVariable(), nullptr, false};
}

std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> TSChecker::CheckFunctionParameter(
    ir::Expression *param, SignatureInfo *signature_info)
{
    if (param->TsType() != nullptr) {
        ASSERT(param->TsType()->Variable());
        binder::Variable *var = param->TsType()->Variable();
        return {var->AsLocalVariable(), nullptr, var->HasFlag(binder::VariableFlags::OPTIONAL)};
    }

    std::tuple<binder::LocalVariable *, binder::LocalVariable *, bool> result;
    bool cache = true;

    switch (param->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            result = CheckFunctionIdentifierParameter(param->AsIdentifier());
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            result = CheckFunctionAssignmentPatternParameter(param->AsAssignmentPattern());
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            result = CheckFunctionRestParameter(param->AsRestElement(), signature_info);
            cache = false;
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            result = CheckFunctionArrayPatternParameter(param->AsArrayPattern());
            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            result = CheckFunctionObjectPatternParameter(param->AsObjectPattern());
            break;
        }
        default: {
            UNREACHABLE();
        }
    }

    if (cache) {
        Type *placeholder = Allocator()->New<ArrayType>(GlobalAnyType());
        placeholder->SetVariable(std::get<0>(result));
        param->SetTsType(placeholder);
    }

    return result;
}

void TSChecker::CheckFunctionParameterDeclarations(const ArenaVector<ir::Expression *> &params,
                                                   SignatureInfo *signature_info)
{
    signature_info->rest_var = nullptr;
    signature_info->min_arg_count = 0;

    for (auto it = params.rbegin(); it != params.rend(); it++) {
        auto [paramVar, restVar, isOptional] = CheckFunctionParameter(*it, signature_info);

        if (restVar != nullptr) {
            signature_info->rest_var = restVar;
            continue;
        }

        if (paramVar == nullptr) {
            continue;
        }

        signature_info->params.insert(signature_info->params.begin(), paramVar);

        if (!isOptional) {
            signature_info->min_arg_count++;
        }
    }
}

bool ShouldCreatePropertyValueName(ir::Expression *prop_value)
{
    return prop_value->IsArrayPattern() || prop_value->IsObjectPattern() ||
           (prop_value->IsAssignmentPattern() && (prop_value->AsAssignmentPattern()->Left()->IsArrayPattern() ||
                                                  prop_value->AsAssignmentPattern()->Left()->IsObjectPattern()));
}

void TSChecker::CreatePatternParameterName(ir::AstNode *node, std::stringstream &ss)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            ss << node->AsIdentifier()->Name();
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            ss << "[";

            const auto &elements = node->AsArrayPattern()->Elements();
            for (auto it = elements.begin(); it != elements.end(); it++) {
                CreatePatternParameterName(*it, ss);
                if (std::next(it) != elements.end()) {
                    ss << ", ";
                }
            }

            ss << "]";
            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            ss << "{ ";

            const auto &properties = node->AsObjectPattern()->Properties();
            for (auto it = properties.begin(); it != properties.end(); it++) {
                CreatePatternParameterName(*it, ss);
                if (std::next(it) != properties.end()) {
                    ss << ", ";
                }
            }

            ss << " }";
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            CreatePatternParameterName(node->AsAssignmentPattern()->Left(), ss);
            break;
        }
        case ir::AstNodeType::PROPERTY: {
            ir::Property *prop = node->AsProperty();
            util::StringView prop_name;

            if (prop->Key()->IsIdentifier()) {
                prop_name = prop->Key()->AsIdentifier()->Name();
            } else {
                switch (prop->Key()->Type()) {
                    case ir::AstNodeType::NUMBER_LITERAL: {
                        prop_name = util::Helpers::ToStringView(Allocator(),
                                                                prop->Key()->AsNumberLiteral()->Number().GetDouble());
                        break;
                    }
                    case ir::AstNodeType::BIGINT_LITERAL: {
                        prop_name = prop->Key()->AsBigIntLiteral()->Str();
                        break;
                    }
                    case ir::AstNodeType::STRING_LITERAL: {
                        prop_name = prop->Key()->AsStringLiteral()->Str();
                        break;
                    }
                    default: {
                        UNREACHABLE();
                        break;
                    }
                }
            }

            ss << prop_name;

            if (ShouldCreatePropertyValueName(prop->Value())) {
                ss << ": ";
                TSChecker::CreatePatternParameterName(prop->Value(), ss);
            }

            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            ss << "...";
            TSChecker::CreatePatternParameterName(node->AsRestElement()->Argument(), ss);
            break;
        }
        default:
            break;
    }
}

ir::Statement *FindSubsequentFunctionNode(ir::BlockStatement *block, ir::ScriptFunction *node)
{
    for (auto it = block->Statements().begin(); it != block->Statements().end(); it++) {
        if ((*it)->IsFunctionDeclaration() && (*it)->AsFunctionDeclaration()->Function() == node) {
            return *(++it);
        }
    }

    UNREACHABLE();
    return nullptr;
}

void TSChecker::InferFunctionDeclarationType(const binder::FunctionDecl *decl, binder::Variable *func_var)
{
    ir::ScriptFunction *body_declaration = decl->Decls().back();

    if (body_declaration->IsOverload()) {
        ThrowTypeError("Function implementation is missing or not immediately following the declaration.",
                       body_declaration->Id()->Start());
    }

    ObjectDescriptor *desc_with_overload = Allocator()->New<ObjectDescriptor>(Allocator());

    for (auto it = decl->Decls().begin(); it != decl->Decls().end() - 1; it++) {
        ir::ScriptFunction *func = *it;
        ASSERT(func->IsOverload() && (*it)->Parent()->Parent()->IsBlockStatement());
        ir::Statement *subsequent_node =
            FindSubsequentFunctionNode((*it)->Parent()->Parent()->AsBlockStatement(), func);
        ASSERT(subsequent_node);

        if (!subsequent_node->IsFunctionDeclaration()) {
            ThrowTypeError("Function implementation is missing or not immediately following the declaration.",
                           func->Id()->Start());
        }

        ir::ScriptFunction *subsequent_func = subsequent_node->AsFunctionDeclaration()->Function();

        if (subsequent_func->Id()->Name() != func->Id()->Name()) {
            ThrowTypeError("Function implementation is missing or not immediately following the declaration.",
                           func->Id()->Start());
        }

        if (subsequent_func->Declare() != func->Declare()) {
            ThrowTypeError("Overload signatures must all be ambient or non-ambient.", func->Id()->Start());
        }

        ScopeContext scope_ctx(this, func->Scope());

        auto *overload_signature_info = Allocator()->New<checker::SignatureInfo>(Allocator());
        CheckFunctionParameterDeclarations(func->Params(), overload_signature_info);

        Type *return_type = GlobalAnyType();

        if (func->ReturnTypeAnnotation() != nullptr) {
            func->ReturnTypeAnnotation()->Check(this);
            return_type = func->ReturnTypeAnnotation()->GetType(this);
        }

        Signature *overload_signature =
            Allocator()->New<checker::Signature>(overload_signature_info, return_type, func);
        desc_with_overload->call_signatures.push_back(overload_signature);
    }

    ScopeContext scope_ctx(this, body_declaration->Scope());

    auto *signature_info = Allocator()->New<checker::SignatureInfo>(Allocator());
    CheckFunctionParameterDeclarations(body_declaration->Params(), signature_info);
    auto *body_call_signature = Allocator()->New<checker::Signature>(signature_info, GlobalResolvingReturnType());

    if (desc_with_overload->call_signatures.empty()) {
        Type *func_type = CreateFunctionTypeWithSignature(body_call_signature);
        func_type->SetVariable(func_var);
        func_var->SetTsType(func_type);
    }

    body_call_signature->SetReturnType(HandleFunctionReturn(body_declaration));

    if (!desc_with_overload->call_signatures.empty()) {
        Type *func_type = Allocator()->New<FunctionType>(desc_with_overload);
        func_type->SetVariable(func_var);
        func_var->SetTsType(func_type);

        for (auto *iter : desc_with_overload->call_signatures) {
            if (body_call_signature->ReturnType()->IsVoidType() ||
                IsTypeAssignableTo(body_call_signature->ReturnType(), iter->ReturnType()) ||
                IsTypeAssignableTo(iter->ReturnType(), body_call_signature->ReturnType())) {
                body_call_signature->AssignmentTarget(Relation(), iter);

                if (Relation()->IsTrue()) {
                    continue;
                }
            }

            ASSERT(iter->Function());
            ThrowTypeError("This overload signature is not compatible with its implementation signature",
                           iter->Function()->Id()->Start());
        }
    }
}

void TSChecker::CollectTypesFromReturnStatements(ir::AstNode *parent, ArenaVector<Type *> *return_types)
{
    parent->Iterate([this, return_types](ir::AstNode *child_node) -> void {
        if (child_node->IsScriptFunction()) {
            return;
        }

        if (child_node->IsReturnStatement()) {
            ir::ReturnStatement *return_stmt = child_node->AsReturnStatement();

            if (return_stmt->Argument() == nullptr) {
                return;
            }

            return_types->push_back(
                GetBaseTypeOfLiteralType(CheckTypeCached(child_node->AsReturnStatement()->Argument())));
        }

        CollectTypesFromReturnStatements(child_node, return_types);
    });
}

static bool SearchForReturnOrThrow(ir::AstNode *parent)
{
    bool found = false;

    parent->Iterate([&found](ir::AstNode *child_node) -> void {
        if (child_node->IsThrowStatement() || child_node->IsReturnStatement()) {
            found = true;
            return;
        }

        if (child_node->IsScriptFunction()) {
            return;
        }

        SearchForReturnOrThrow(child_node);
    });

    return found;
}

void TSChecker::CheckAllCodePathsInNonVoidFunctionReturnOrThrow(ir::ScriptFunction *func,
                                                                lexer::SourcePosition line_info, const char *err_msg)
{
    if (!SearchForReturnOrThrow(func->Body())) {
        ThrowTypeError(err_msg, line_info);
    }
    // TODO(aszilagyi): this function is not fully implement the TSC one, in the future if we will have a
    // noImplicitReturn compiler option for TypeScript we should update this function
}

ArgRange TSChecker::GetArgRange(const ArenaVector<Signature *> &signatures,
                                ArenaVector<Signature *> *potential_signatures, uint32_t call_args_size,
                                bool *have_signature_with_rest)
{
    uint32_t min_arg = UINT32_MAX;
    uint32_t max_arg = 0;

    for (auto *it : signatures) {
        if (it->RestVar() != nullptr) {
            *have_signature_with_rest = true;
        }

        if (it->MinArgCount() < min_arg) {
            min_arg = it->MinArgCount();
        }

        if (it->Params().size() > max_arg) {
            max_arg = it->Params().size();
        }

        if (call_args_size >= it->MinArgCount() &&
            (call_args_size <= it->Params().size() || it->RestVar() != nullptr)) {
            potential_signatures->push_back(it);
        }
    }

    return {min_arg, max_arg};
}

bool TSChecker::CallMatchesSignature(const ArenaVector<ir::Expression *> &args, Signature *signature, bool throw_error)
{
    for (size_t index = 0; index < args.size(); index++) {
        checker::Type *sig_arg_type = nullptr;
        bool validate_rest_arg = false;

        if (index >= signature->Params().size()) {
            ASSERT(signature->RestVar());
            validate_rest_arg = true;
            sig_arg_type = signature->RestVar()->TsType();
        } else {
            sig_arg_type = signature->Params()[index]->TsType();
        }

        if (validate_rest_arg || !throw_error) {
            checker::Type *call_arg_type = GetBaseTypeOfLiteralType(args[index]->Check(this));
            if (!IsTypeAssignableTo(call_arg_type, sig_arg_type)) {
                if (throw_error) {
                    ThrowTypeError({"Argument of type '", call_arg_type, "' is not assignable to parameter of type '",
                                    sig_arg_type, "'."},
                                   args[index]->Start());
                }

                return false;
            }

            continue;
        }

        ElaborateElementwise(sig_arg_type, args[index], args[index]->Start());
    }

    return true;
}

Type *TSChecker::ResolveCallOrNewExpression(const ArenaVector<Signature *> &signatures,
                                            ArenaVector<ir::Expression *> arguments,
                                            const lexer::SourcePosition &err_pos)
{
    if (signatures.empty()) {
        ThrowTypeError("This expression is not callable.", err_pos);
    }

    ArenaVector<checker::Signature *> potential_signatures(Allocator()->Adapter());
    bool have_signature_with_rest = false;

    auto arg_range = GetArgRange(signatures, &potential_signatures, arguments.size(), &have_signature_with_rest);

    if (potential_signatures.empty()) {
        if (have_signature_with_rest) {
            ThrowTypeError({"Expected at least ", arg_range.first, " arguments, but got ", arguments.size(), "."},
                           err_pos);
        }

        if (signatures.size() == 1 && arg_range.first == arg_range.second) {
            lexer::SourcePosition loc =
                (arg_range.first > arguments.size()) ? err_pos : arguments[arg_range.second]->Start();
            ThrowTypeError({"Expected ", arg_range.first, " arguments, but got ", arguments.size(), "."}, loc);
        }

        ThrowTypeError({"Expected ", arg_range.first, "-", arg_range.second, " arguments, but got ", arguments.size()},
                       err_pos);
    }

    checker::Type *return_type = nullptr;
    for (auto *it : potential_signatures) {
        if (CallMatchesSignature(arguments, it, potential_signatures.size() == 1)) {
            return_type = it->ReturnType();
            break;
        }
    }

    if (return_type == nullptr) {
        ThrowTypeError("No overload matches this call.", err_pos);
    }

    return return_type;
}
}  // namespace panda::es2panda::checker
