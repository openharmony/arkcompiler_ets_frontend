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

#include "destructuringContext.h"

#include "util/helpers.h"
#include "binder/scope.h"
#include "ir/typeNode.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/base/spreadElement.h"
#include "ir/base/property.h"
#include "ir/expression.h"

namespace panda::es2panda::checker {
void DestructuringContext::Prepare(ir::TypeNode *type_annotation, ir::Expression *initializer,
                                   const lexer::SourcePosition &loc)
{
    if (type_annotation != nullptr) {
        type_annotation->Check(checker_);
        Type *annotation_type = type_annotation->GetType(checker_);

        if (initializer != nullptr) {
            checker_->ElaborateElementwise(annotation_type, initializer, loc);
        }

        validate_type_annotation_ = true;
        inferred_type_ = annotation_type;
        return;
    }

    if (initializer != nullptr) {
        if (!initializer->IsObjectExpression()) {
            validate_object_pattern_initializer_ = false;
        }

        inferred_type_ = initializer->Check(checker_);
    }
}

void DestructuringContext::HandleDestructuringAssignment(ir::Identifier *ident, Type *inferred_type, Type *default_type)
{
    if (ident->Variable() == nullptr) {
        checker_->ThrowTypeError({"Cannot find name '", ident->Name(), "'."}, ident->Start());
    }

    binder::Variable *variable = ident->Variable();
    ASSERT(variable->TsType());

    if (default_type != nullptr && !checker_->IsTypeAssignableTo(default_type, variable->TsType())) {
        checker_->ThrowAssignmentError(default_type, variable->TsType(), ident->Start());
    }

    if (inferred_type != nullptr && !checker_->IsTypeAssignableTo(inferred_type, variable->TsType())) {
        checker_->ThrowAssignmentError(inferred_type, variable->TsType(), ident->Start());
    }
}

void DestructuringContext::SetInferredTypeForVariable(binder::Variable *var, Type *inferred_type,
                                                      const lexer::SourcePosition &loc)
{
    ASSERT(var);

    if (!checker_->HasStatus(CheckerStatus::IN_CONST_CONTEXT)) {
        inferred_type = checker_->GetBaseTypeOfLiteralType(inferred_type);
    }

    if (var->TsType() != nullptr) {
        checker_->IsTypeIdenticalTo(var->TsType(), inferred_type,
                                    {"Subsequent variable declaration must have the same type. Variable '", var->Name(),
                                     "' must be of type '", var->TsType(), "', but here has type '", inferred_type,
                                     "'."},
                                    loc);
        return;
    }

    if (signature_info_ != nullptr) {
        signature_info_->params.push_back(var->AsLocalVariable());
        signature_info_->min_arg_count++;
    }

    var->SetTsType(inferred_type);
}

void DestructuringContext::ValidateObjectLiteralType(ObjectType *obj_type, ir::ObjectExpression *obj_pattern)
{
    for (const auto *source_prop : obj_type->Properties()) {
        const util::StringView &source_name = source_prop->Name();
        bool found = false;

        for (const auto *target_prop : obj_pattern->Properties()) {
            if (target_prop->IsRestElement()) {
                continue;
            }

            ASSERT(target_prop->IsProperty());
            const util::StringView &target_name = target_prop->AsProperty()->Key()->AsIdentifier()->Name();

            if (source_name == target_name) {
                found = true;
                break;
            }
        }

        if (!found) {
            checker_->ThrowTypeError({"Object literal may only specify known properties, and property '", source_name,
                                      "' does not exist in the pattern."},
                                     obj_pattern->Start());
        }
    }
}

void DestructuringContext::HandleAssignmentPattern(ir::AssignmentExpression *assignment_pattern, Type *inferred_type,
                                                   bool validate_default)
{
    if (!assignment_pattern->Left()->IsArrayPattern()) {
        checker_->RemoveStatus(CheckerStatus::FORCE_TUPLE);
    }

    Type *default_type = assignment_pattern->Right()->Check(checker_);

    if (!checker_->HasStatus(CheckerStatus::IN_CONST_CONTEXT)) {
        default_type = checker_->GetBaseTypeOfLiteralType(default_type);
    }

    if (validate_default && assignment_pattern->Right()->IsObjectExpression() &&
        assignment_pattern->Left()->IsObjectPattern()) {
        ValidateObjectLiteralType(default_type->AsObjectType(), assignment_pattern->Left()->AsObjectPattern());
    }

    Type *init_type = inferred_type;
    checker_->AddStatus(CheckerStatus::FORCE_TUPLE);

    if (validate_type_annotation_) {
        if (inferred_type == nullptr) {
            inferred_type = checker_->GlobalUndefinedType();
        }
    } else {
        if (inferred_type == nullptr) {
            inferred_type = default_type;
        } else if (inferred_type->IsUnionType()) {
            inferred_type->AsUnionType()->AddConstituentType(default_type, checker_->Relation());
        } else {
            inferred_type = checker_->CreateUnionType({inferred_type, default_type});
        }
    }

    if (assignment_pattern->Left()->IsIdentifier()) {
        if (in_assignment_) {
            HandleDestructuringAssignment(assignment_pattern->Left()->AsIdentifier(), init_type, default_type);
            return;
        }

        if (validate_type_annotation_ && !checker_->IsTypeAssignableTo(default_type, inferred_type)) {
            checker_->ThrowAssignmentError(default_type, inferred_type, assignment_pattern->Left()->Start());
        }

        SetInferredTypeForVariable(assignment_pattern->Left()->AsIdentifier()->Variable(), inferred_type,
                                   assignment_pattern->Start());
        return;
    }

    if (assignment_pattern->Left()->IsArrayPattern()) {
        ArrayDestructuringContext next_context = ArrayDestructuringContext(
            checker_, assignment_pattern->Left(), in_assignment_, convert_tuple_to_array_, nullptr, nullptr);
        next_context.SetInferredType(inferred_type);
        next_context.Start();
        return;
    }

    ASSERT(assignment_pattern->Left()->IsObjectPattern());
    ObjectDestructuringContext next_context = ObjectDestructuringContext(
        checker_, assignment_pattern->Left(), in_assignment_, convert_tuple_to_array_, nullptr, nullptr);
    next_context.SetInferredType(inferred_type);
    next_context.Start();
}

void ArrayDestructuringContext::ValidateInferredType()
{
    if (!inferred_type_->IsArrayType() && !inferred_type_->IsUnionType() &&
        (!inferred_type_->IsObjectType() || !inferred_type_->AsObjectType()->IsTupleType())) {
        checker_->ThrowTypeError(
            {"Type ", inferred_type_, " must have a '[Symbol.iterator]()' method that returns an iterator."},
            id_->Start());
    }

    if (inferred_type_->IsUnionType()) {
        for (auto *it : inferred_type_->AsUnionType()->ConstituentTypes()) {
            if (!it->IsArrayType() && (!it->IsObjectType() || !it->AsObjectType()->IsTupleType())) {
                checker_->ThrowTypeError(
                    {"Type ", inferred_type_, " must have a '[Symbol.iterator]()' method that returns an iterator."},
                    id_->Start());
            }
        }
    }
}

Type *ArrayDestructuringContext::GetTypeFromTupleByIndex(TupleType *tuple)
{
    util::StringView member_index = util::Helpers::ToStringView(checker_->Allocator(), index_);
    binder::Variable *member_var = tuple->GetProperty(member_index, false);

    if (member_var == nullptr) {
        return nullptr;
    }

    return member_var->TsType();
}

Type *ArrayDestructuringContext::NextInferredType([[maybe_unused]] const util::StringView &search_name,
                                                  bool throw_error)
{
    if (inferred_type_->IsArrayType()) {
        return inferred_type_->AsArrayType()->ElementType();
    }

    if (inferred_type_->IsObjectType()) {
        ASSERT(inferred_type_->AsObjectType()->IsTupleType());
        Type *return_type = GetTypeFromTupleByIndex(inferred_type_->AsObjectType()->AsTupleType());

        if (return_type == nullptr && throw_error) {
            if (!validate_type_annotation_ && checker_->HasStatus(CheckerStatus::IN_PARAMETER)) {
                return return_type;
            }

            checker_->ThrowTypeError({"Tuple type ", inferred_type_, " of length ",
                                      inferred_type_->AsObjectType()->AsTupleType()->FixedLength(),
                                      " has no element at index ", index_, "."},
                                     id_->Start());
        }

        return return_type;
    }

    ASSERT(inferred_type_->IsUnionType());

    ArenaVector<Type *> union_types(checker_->Allocator()->Adapter());

    for (auto *type : inferred_type_->AsUnionType()->ConstituentTypes()) {
        if (type->IsArrayType()) {
            union_types.push_back(type->AsArrayType()->ElementType());
            continue;
        }

        ASSERT(type->IsObjectType() && type->AsObjectType()->IsTupleType());
        Type *element_type = GetTypeFromTupleByIndex(type->AsObjectType()->AsTupleType());

        if (element_type == nullptr) {
            continue;
        }

        union_types.push_back(element_type);
    }

    if (union_types.empty()) {
        if (throw_error) {
            checker_->ThrowTypeError({"Property ", index_, " does not exist on type ", inferred_type_, "."},
                                     id_->Start());
        }

        return nullptr;
    }

    return checker_->CreateUnionType(std::move(union_types));
}

Type *ArrayDestructuringContext::CreateArrayTypeForRest(UnionType *inferred_type)
{
    ArenaVector<Type *> union_types(checker_->Allocator()->Adapter());
    uint32_t saved_idx = index_;

    for (auto *it : inferred_type->ConstituentTypes()) {
        if (it->IsArrayType()) {
            union_types.push_back(it->AsArrayType()->ElementType());
            continue;
        }

        ASSERT(it->IsObjectType() && it->AsObjectType()->IsTupleType());
        Type *tuple_element_type = GetTypeFromTupleByIndex(it->AsObjectType()->AsTupleType());

        while (tuple_element_type != nullptr) {
            union_types.push_back(tuple_element_type);
            index_++;
            tuple_element_type = GetTypeFromTupleByIndex(it->AsObjectType()->AsTupleType());
        }

        index_ = saved_idx;
    }

    Type *rest_array_element_type = checker_->CreateUnionType(std::move(union_types));
    return checker_->Allocator()->New<ArrayType>(rest_array_element_type);
}

Type *ArrayDestructuringContext::CreateTupleTypeForRest(TupleType *tuple)
{
    ObjectDescriptor *desc = checker_->Allocator()->New<ObjectDescriptor>(checker_->Allocator());
    ArenaVector<ElementFlags> element_flags(checker_->Allocator()->Adapter());
    uint32_t saved_idx = index_;
    uint32_t iter_index = 0;

    Type *tuple_element_type = GetTypeFromTupleByIndex(tuple);

    while (tuple_element_type != nullptr) {
        ElementFlags member_flag = ElementFlags::REQUIRED;
        util::StringView member_index = util::Helpers::ToStringView(checker_->Allocator(), iter_index);
        auto *member_var =
            binder::Scope::CreateVar(checker_->Allocator(), member_index, binder::VariableFlags::PROPERTY, nullptr);
        member_var->SetTsType(tuple_element_type);
        element_flags.push_back(member_flag);
        desc->properties.push_back(member_var);

        index_++;
        iter_index++;

        tuple_element_type = GetTypeFromTupleByIndex(tuple);
    }

    index_ = saved_idx;
    return checker_->CreateTupleType(desc, std::move(element_flags), ElementFlags::REQUIRED, iter_index, iter_index,
                                     false);
}

Type *ArrayDestructuringContext::GetRestType([[maybe_unused]] const lexer::SourcePosition &loc)
{
    if (inferred_type_->IsArrayType()) {
        return inferred_type_;
    }

    if (inferred_type_->IsObjectType() && inferred_type_->AsObjectType()->IsTupleType()) {
        return CreateTupleTypeForRest(inferred_type_->AsObjectType()->AsTupleType());
    }

    ASSERT(inferred_type_->IsUnionType());
    bool create_array_type = false;

    for (auto *it : inferred_type_->AsUnionType()->ConstituentTypes()) {
        if (it->IsArrayType()) {
            create_array_type = true;
            break;
        }
    }

    if (create_array_type) {
        return CreateArrayTypeForRest(inferred_type_->AsUnionType());
    }

    ArenaVector<Type *> tuple_union(checker_->Allocator()->Adapter());

    for (auto *it : inferred_type_->AsUnionType()->ConstituentTypes()) {
        ASSERT(it->IsObjectType() && it->AsObjectType()->IsTupleType());
        Type *new_tuple = CreateTupleTypeForRest(it->AsObjectType()->AsTupleType());
        tuple_union.push_back(new_tuple);
    }

    return checker_->CreateUnionType(std::move(tuple_union));
}

void ArrayDestructuringContext::HandleRest(ir::SpreadElement *rest)
{
    Type *inferred_rest_type = GetRestType(rest->Start());

    if (rest->Argument()->IsIdentifier()) {
        if (in_assignment_) {
            HandleDestructuringAssignment(rest->Argument()->AsIdentifier(), inferred_rest_type, nullptr);
            return;
        }

        SetInferredTypeForVariable(rest->Argument()->AsIdentifier()->Variable(), inferred_rest_type, rest->Start());
        return;
    }

    if (rest->Argument()->IsArrayPattern()) {
        ArrayDestructuringContext next_context = ArrayDestructuringContext(checker_, rest->Argument(), in_assignment_,
                                                                           convert_tuple_to_array_, nullptr, nullptr);
        next_context.SetInferredType(inferred_rest_type);
        next_context.Start();
        return;
    }

    ASSERT(rest->Argument()->IsObjectPattern());
    ObjectDestructuringContext next_context = ObjectDestructuringContext(checker_, rest->Argument(), in_assignment_,
                                                                         convert_tuple_to_array_, nullptr, nullptr);
    next_context.SetInferredType(inferred_rest_type);
    next_context.Start();
}

Type *ArrayDestructuringContext::ConvertTupleTypeToArrayTypeIfNecessary(ir::AstNode *node, Type *type)
{
    if (!convert_tuple_to_array_) {
        return type;
    }

    if (type == nullptr) {
        return type;
    }

    if (node->IsArrayPattern() ||
        (node->IsAssignmentPattern() && node->AsAssignmentPattern()->Left()->IsArrayPattern())) {
        return type;
    }

    if (type->IsObjectType() && type->AsObjectType()->IsTupleType()) {
        return type->AsObjectType()->AsTupleType()->ConvertToArrayType(checker_);
    }

    return type;
}

static void SetParameterType(ir::AstNode *parent, Type *type)
{
    parent->Iterate([type](ir::AstNode *child_node) -> void {
        if (child_node->IsIdentifier() && child_node->AsIdentifier()->Variable() != nullptr) {
            child_node->AsIdentifier()->Variable()->SetTsType(type);
            return;
        }

        SetParameterType(child_node, type);
    });
}

void ArrayDestructuringContext::SetRemainingParameterTypes()
{
    do {
        auto *it = id_->AsArrayPattern()->Elements()[index_];
        ASSERT(it);
        SetParameterType(it, checker_->GlobalAnyType());
    } while (++index_ != id_->AsArrayPattern()->Elements().size());
}

void ArrayDestructuringContext::Start()
{
    ASSERT(id_->IsArrayPattern());

    ValidateInferredType();

    util::StringView name = util::Helpers::ToStringView(checker_->Allocator(), 0);

    for (auto *it : id_->AsArrayPattern()->Elements()) {
        if (it->IsRestElement()) {
            HandleRest(it->AsRestElement());
            break;
        }

        Type *next_inferred_type =
            ConvertTupleTypeToArrayTypeIfNecessary(it, NextInferredType(name, !it->IsAssignmentPattern()));

        if (next_inferred_type == nullptr && checker_->HasStatus(CheckerStatus::IN_PARAMETER)) {
            SetRemainingParameterTypes();
            return;
        }

        if (convert_tuple_to_array_ && next_inferred_type != nullptr && inferred_type_->IsObjectType()) {
            ASSERT(inferred_type_->AsObjectType()->IsTupleType());

            binder::Variable *current_tuple_element = inferred_type_->AsObjectType()->Properties()[index_];

            if (current_tuple_element != nullptr) {
                current_tuple_element->SetTsType(next_inferred_type);
            }
        }

        switch (it->Type()) {
            case ir::AstNodeType::IDENTIFIER: {
                if (in_assignment_) {
                    HandleDestructuringAssignment(it->AsIdentifier(), next_inferred_type, nullptr);
                    break;
                }

                SetInferredTypeForVariable(it->AsIdentifier()->Variable(), next_inferred_type, it->Start());
                break;
            }
            case ir::AstNodeType::ARRAY_PATTERN: {
                ArrayDestructuringContext next_context =
                    ArrayDestructuringContext(checker_, it, in_assignment_, convert_tuple_to_array_, nullptr, nullptr);
                next_context.SetInferredType(next_inferred_type);
                next_context.Start();
                break;
            }
            case ir::AstNodeType::OBJECT_PATTERN: {
                ObjectDestructuringContext next_context =
                    ObjectDestructuringContext(checker_, it, in_assignment_, convert_tuple_to_array_, nullptr, nullptr);
                next_context.SetInferredType(next_inferred_type);
                next_context.Start();
                break;
            }
            case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                HandleAssignmentPattern(it->AsAssignmentPattern(), next_inferred_type, false);
                break;
            }
            case ir::AstNodeType::OMITTED_EXPRESSION: {
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        index_++;
    }
}

void ObjectDestructuringContext::ValidateInferredType()
{
    if (!inferred_type_->IsObjectType()) {
        return;
    }

    ValidateObjectLiteralType(inferred_type_->AsObjectType(), id_->AsObjectPattern());
}

void ObjectDestructuringContext::HandleRest(ir::SpreadElement *rest)
{
    Type *inferred_rest_type = GetRestType(rest->Start());
    ASSERT(rest->Argument()->IsIdentifier());

    if (in_assignment_) {
        HandleDestructuringAssignment(rest->Argument()->AsIdentifier(), inferred_rest_type, nullptr);
        return;
    }

    SetInferredTypeForVariable(rest->Argument()->AsIdentifier()->Variable(), inferred_rest_type, rest->Start());
}

Type *ObjectDestructuringContext::CreateObjectTypeForRest(ObjectType *obj_type)
{
    ObjectDescriptor *desc = checker_->Allocator()->New<ObjectDescriptor>(checker_->Allocator());

    for (auto *it : obj_type->AsObjectType()->Properties()) {
        if (!it->HasFlag(binder::VariableFlags::INFERRED_IN_PATTERN)) {
            auto *member_var =
                binder::Scope::CreateVar(checker_->Allocator(), it->Name(), binder::VariableFlags::NONE, nullptr);
            member_var->SetTsType(it->TsType());
            member_var->AddFlag(it->Flags());
            desc->properties.push_back(member_var);
        }
    }

    Type *return_type = checker_->Allocator()->New<ObjectLiteralType>(desc);
    return_type->AsObjectType()->AddObjectFlag(ObjectFlags::RESOLVED_MEMBERS);
    return return_type;
}

Type *ObjectDestructuringContext::GetRestType([[maybe_unused]] const lexer::SourcePosition &loc)
{
    if (inferred_type_->IsUnionType()) {
        ArenaVector<Type *> union_types(checker_->Allocator()->Adapter());

        for (auto *it : inferred_type_->AsUnionType()->ConstituentTypes()) {
            if (it->IsObjectType()) {
                union_types.push_back(CreateObjectTypeForRest(it->AsObjectType()));
                continue;
            }

            checker_->ThrowTypeError("Rest types may only be created from object types.", loc);
        }

        return checker_->CreateUnionType(std::move(union_types));
    }

    if (inferred_type_->IsObjectType()) {
        return CreateObjectTypeForRest(inferred_type_->AsObjectType());
    }

    checker_->ThrowTypeError("Rest types may only be created from object types.", loc);
}

Type *ObjectDestructuringContext::ConvertTupleTypeToArrayTypeIfNecessary(ir::AstNode *node, Type *type)
{
    if (!convert_tuple_to_array_) {
        return type;
    }

    if (type == nullptr) {
        return type;
    }

    ASSERT(node->IsProperty());

    ir::Property *property = node->AsProperty();

    if (property->Value()->IsArrayPattern()) {
        return type;
    }

    if (property->Value()->IsAssignmentPattern() &&
        property->Value()->AsAssignmentPattern()->Left()->IsArrayPattern()) {
        return type;
    }

    if (type->IsObjectType() && type->AsObjectType()->IsTupleType()) {
        return type->AsObjectType()->AsTupleType()->ConvertToArrayType(checker_);
    }

    return type;
}

Type *ObjectDestructuringContext::NextInferredType([[maybe_unused]] const util::StringView &search_name,
                                                   bool throw_error)
{
    binder::Variable *prop = checker_->GetPropertyOfType(inferred_type_, search_name, !throw_error,
                                                         binder::VariableFlags::INFERRED_IN_PATTERN);

    if (prop != nullptr) {
        prop->AddFlag(binder::VariableFlags::INFERRED_IN_PATTERN);
        return prop->TsType();
    }

    if (inferred_type_->IsObjectType()) {
        checker::ObjectType *obj_type = inferred_type_->AsObjectType();

        if (obj_type->StringIndexInfo() != nullptr) {
            return obj_type->StringIndexInfo()->GetType();
        }
    }

    if (throw_error) {
        checker_->ThrowTypeError({"Property ", search_name, " does not exist on type ", inferred_type_, "."},
                                 id_->Start());
    }

    return nullptr;
}

void ObjectDestructuringContext::Start()
{
    ASSERT(id_->IsObjectPattern());

    if (!id_->AsObjectPattern()->Properties().back()->IsRestElement() && validate_object_pattern_initializer_) {
        ValidateInferredType();
    }

    for (auto *it : id_->AsObjectPattern()->Properties()) {
        switch (it->Type()) {
            case ir::AstNodeType::PROPERTY: {
                ir::Property *property = it->AsProperty();

                if (property->IsComputed()) {
                    // TODO(aszilagyi)
                    return;
                }

                Type *next_inferred_type = ConvertTupleTypeToArrayTypeIfNecessary(
                    it->AsProperty(),
                    NextInferredType(property->Key()->AsIdentifier()->Name(),
                                     (!property->Value()->IsAssignmentPattern() || validate_type_annotation_)));

                if (property->Value()->IsIdentifier()) {
                    if (in_assignment_) {
                        HandleDestructuringAssignment(property->Value()->AsIdentifier(), next_inferred_type, nullptr);
                        break;
                    }

                    SetInferredTypeForVariable(property->Value()->AsIdentifier()->Variable(), next_inferred_type,
                                               it->Start());
                    break;
                }

                if (property->Value()->IsArrayPattern()) {
                    ArrayDestructuringContext next_context =
                        ArrayDestructuringContext(checker_, property->Value()->AsArrayPattern(), in_assignment_,
                                                  convert_tuple_to_array_, nullptr, nullptr);
                    next_context.SetInferredType(next_inferred_type);
                    next_context.Start();
                    break;
                }

                if (property->Value()->IsObjectPattern()) {
                    ObjectDestructuringContext next_context =
                        ObjectDestructuringContext(checker_, property->Value()->AsObjectPattern(), in_assignment_,
                                                   convert_tuple_to_array_, nullptr, nullptr);
                    next_context.SetInferredType(next_inferred_type);
                    next_context.Start();
                    break;
                }

                ASSERT(property->Value()->IsAssignmentPattern());
                HandleAssignmentPattern(property->Value()->AsAssignmentPattern(), next_inferred_type, true);
                break;
            }
            case ir::AstNodeType::REST_ELEMENT: {
                HandleRest(it->AsRestElement());
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }
}
}  // namespace panda::es2panda::checker
