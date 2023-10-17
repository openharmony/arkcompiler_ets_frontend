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

#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/base/tsIndexSignature.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/base/tsPropertySignature.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/ts/tsTypeLiteral.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsInterfaceBody.h"
#include "util/helpers.h"
#include "binder/variable.h"
#include "binder/scope.h"

#include "checker/TSchecker.h"
#include "checker/types/ts/indexInfo.h"

namespace panda::es2panda::checker {
void TSChecker::CheckIndexConstraints(Type *type)
{
    if (!type->IsObjectType()) {
        return;
    }

    ObjectType *obj_type = type->AsObjectType();
    ResolveStructuredTypeMembers(obj_type);

    IndexInfo *number_info = obj_type->NumberIndexInfo();
    IndexInfo *string_info = obj_type->StringIndexInfo();
    const ArenaVector<binder::LocalVariable *> &properties = obj_type->Properties();

    if (number_info != nullptr) {
        for (auto *it : properties) {
            if (it->HasFlag(binder::VariableFlags::NUMERIC_NAME)) {
                Type *prop_type = GetTypeOfVariable(it);
                IsTypeAssignableTo(prop_type, number_info->GetType(),
                                   {"Property '", it->Name(), "' of type '", prop_type,
                                    "' is not assignable to numeric index type '", number_info->GetType(), "'."},
                                   it->Declaration()->Node()->Start());
            }
        }
    }

    if (string_info != nullptr) {
        for (auto *it : properties) {
            Type *prop_type = GetTypeOfVariable(it);
            IsTypeAssignableTo(prop_type, string_info->GetType(),
                               {"Property '", it->Name(), "' of type '", prop_type,
                                "' is not assignable to string index type '", string_info->GetType(), "'."},
                               it->Declaration()->Node()->Start());
        }

        if (number_info != nullptr && !IsTypeAssignableTo(number_info->GetType(), string_info->GetType())) {
            ThrowTypeError({"Number index info type ", number_info->GetType(),
                            " is not assignable to string index info type ", string_info->GetType(), "."},
                           number_info->Pos());
        }
    }
}

void TSChecker::ResolveStructuredTypeMembers(Type *type)
{
    if (type->IsObjectType()) {
        ObjectType *obj_type = type->AsObjectType();

        if (obj_type->IsObjectLiteralType()) {
            ResolveObjectTypeMembers(obj_type);
            return;
        }

        if (obj_type->IsInterfaceType()) {
            ResolveInterfaceOrClassTypeMembers(obj_type->AsInterfaceType());
            return;
        }
    }

    if (type->IsUnionType()) {
        ResolveUnionTypeMembers(type->AsUnionType());
        return;
    }
}

void TSChecker::ResolveUnionTypeMembers(UnionType *type)
{
    if (type->MergedObjectType() != nullptr) {
        return;
    }

    ObjectDescriptor *desc = Allocator()->New<ObjectDescriptor>(Allocator());
    ArenaVector<Type *> string_info_types(Allocator()->Adapter());
    ArenaVector<Type *> number_info_types(Allocator()->Adapter());
    ArenaVector<Signature *> call_signatures(Allocator()->Adapter());
    ArenaVector<Signature *> construct_signatures(Allocator()->Adapter());

    for (auto *it : type->AsUnionType()->ConstituentTypes()) {
        if (!it->IsObjectType()) {
            continue;
        }

        ObjectType *obj_type = it->AsObjectType();
        ResolveObjectTypeMembers(obj_type);

        if (!obj_type->CallSignatures().empty()) {
            for (auto *signature : obj_type->CallSignatures()) {
                call_signatures.push_back(signature);
            }
        }

        if (!obj_type->ConstructSignatures().empty()) {
            for (auto *signature : obj_type->ConstructSignatures()) {
                construct_signatures.push_back(signature);
            }
        }

        if (obj_type->StringIndexInfo() != nullptr) {
            string_info_types.push_back(obj_type->StringIndexInfo()->GetType());
        }

        if (obj_type->NumberIndexInfo() != nullptr) {
            number_info_types.push_back(obj_type->NumberIndexInfo()->GetType());
        }
    }

    desc->call_signatures = call_signatures;
    desc->construct_signatures = construct_signatures;

    if (!string_info_types.empty()) {
        desc->string_index_info =
            Allocator()->New<IndexInfo>(CreateUnionType(std::move(string_info_types)), "x", false);
    }

    if (!number_info_types.empty()) {
        desc->number_index_info =
            Allocator()->New<IndexInfo>(CreateUnionType(std::move(number_info_types)), "x", false);
    }

    ObjectType *merged_type = Allocator()->New<ObjectLiteralType>(desc);
    merged_type->AddObjectFlag(ObjectFlags::RESOLVED_MEMBERS);
    type->SetMergedObjectType(merged_type);
}

void TSChecker::ResolveInterfaceOrClassTypeMembers(InterfaceType *type)
{
    if (type->HasObjectFlag(ObjectFlags::RESOLVED_MEMBERS)) {
        return;
    }

    ResolveDeclaredMembers(type);
    GetBaseTypes(type);

    type->AddObjectFlag(ObjectFlags::RESOLVED_MEMBERS);
}

void TSChecker::ResolveObjectTypeMembers(ObjectType *type)
{
    if (!type->IsObjectLiteralType() || type->HasObjectFlag(ObjectFlags::RESOLVED_MEMBERS)) {
        return;
    }

    ASSERT(type->Variable() && type->Variable()->Declaration()->Node()->IsTSTypeLiteral());
    auto *type_literal = type->Variable()->Declaration()->Node()->AsTSTypeLiteral();
    ArenaVector<ir::TSSignatureDeclaration *> signature_declarations(Allocator()->Adapter());
    ArenaVector<ir::TSIndexSignature *> index_declarations(Allocator()->Adapter());

    for (auto *it : type_literal->Members()) {
        ResolvePropertiesOfObjectType(type, it, signature_declarations, index_declarations, false);
    }

    type->AddObjectFlag(ObjectFlags::RESOLVED_MEMBERS);

    ResolveSignaturesOfObjectType(type, signature_declarations);
    ResolveIndexInfosOfObjectType(type, index_declarations);
}

void TSChecker::ResolvePropertiesOfObjectType(ObjectType *type, ir::AstNode *member,
                                              ArenaVector<ir::TSSignatureDeclaration *> &signature_declarations,
                                              ArenaVector<ir::TSIndexSignature *> &index_declarations,
                                              bool is_interface)
{
    if (member->IsTSPropertySignature()) {
        binder::Variable *prop = member->AsTSPropertySignature()->Variable();

        if (!is_interface ||
            ValidateInterfaceMemberRedeclaration(type, prop, member->AsTSPropertySignature()->Key()->Start())) {
            type->AddProperty(prop->AsLocalVariable());
        }

        return;
    }

    if (member->IsTSMethodSignature()) {
        binder::Variable *method = member->AsTSMethodSignature()->Variable();

        if (!is_interface ||
            ValidateInterfaceMemberRedeclaration(type, method, member->AsTSMethodSignature()->Key()->Start())) {
            type->AddProperty(method->AsLocalVariable());
        }

        return;
    }

    if (member->IsTSSignatureDeclaration()) {
        signature_declarations.push_back(member->AsTSSignatureDeclaration());
        return;
    }

    ASSERT(member->IsTSIndexSignature());
    index_declarations.push_back(member->AsTSIndexSignature());
}

void TSChecker::ResolveSignaturesOfObjectType(ObjectType *type,
                                              ArenaVector<ir::TSSignatureDeclaration *> &signature_declarations)
{
    for (auto *it : signature_declarations) {
        Type *placeholder_obj = it->Check(this);

        if (it->AsTSSignatureDeclaration()->Kind() ==
            ir::TSSignatureDeclaration::TSSignatureDeclarationKind::CALL_SIGNATURE) {
            type->AddCallSignature(placeholder_obj->AsObjectType()->CallSignatures()[0]);
            continue;
        }

        type->AddConstructSignature(placeholder_obj->AsObjectType()->ConstructSignatures()[0]);
    }
}
void TSChecker::ResolveIndexInfosOfObjectType(ObjectType *type, ArenaVector<ir::TSIndexSignature *> &index_declarations)
{
    for (auto *it : index_declarations) {
        Type *placeholder_obj = it->Check(this);

        if (it->AsTSIndexSignature()->Kind() == ir::TSIndexSignature::TSIndexSignatureKind::NUMBER) {
            IndexInfo *number_info = placeholder_obj->AsObjectType()->NumberIndexInfo();

            if (type->NumberIndexInfo() != nullptr) {
                ThrowTypeError("Duplicated index signature for type 'number'", it->Start());
            }

            type->Desc()->number_index_info = number_info;
            continue;
        }

        IndexInfo *string_info = placeholder_obj->AsObjectType()->StringIndexInfo();

        if (type->StringIndexInfo() != nullptr) {
            ThrowTypeError("Duplicated index signature for type 'string'", it->Start());
        }

        type->Desc()->string_index_info = string_info;
    }
}

binder::Variable *TSChecker::GetPropertyOfType(Type *type, const util::StringView &name, bool get_partial,
                                               binder::VariableFlags propagate_flags)
{
    if (type->IsObjectType()) {
        ResolveObjectTypeMembers(type->AsObjectType());
        return type->AsObjectType()->GetProperty(name, true);
    }

    if (type->IsUnionType()) {
        return GetPropertyOfUnionType(type->AsUnionType(), name, get_partial, propagate_flags);
    }

    return nullptr;
}

binder::Variable *TSChecker::GetPropertyOfUnionType(UnionType *type, const util::StringView &name, bool get_partial,
                                                    binder::VariableFlags propagate_flags)
{
    auto found = type->CachedSyntheticProperties().find(name);

    if (found != type->CachedSyntheticProperties().end()) {
        return found->second;
    }

    binder::VariableFlags flags = binder::VariableFlags::PROPERTY;
    ArenaVector<Type *> collected_types(Allocator()->Adapter());

    for (auto *it : type->ConstituentTypes()) {
        binder::Variable *prop = GetPropertyOfType(it, name);

        if (prop == nullptr) {
            if (it->IsArrayType()) {
                collected_types.push_back(it->AsArrayType()->ElementType());
                continue;
            }

            if (!it->IsObjectType()) {
                if (get_partial) {
                    continue;
                }

                return nullptr;
            }

            ObjectType *obj_type = it->AsObjectType();

            if (obj_type->StringIndexInfo() == nullptr) {
                if (get_partial) {
                    continue;
                }

                return nullptr;
            }

            collected_types.push_back(obj_type->StringIndexInfo()->GetType());
            continue;
        }

        prop->AddFlag(propagate_flags);

        if (prop->HasFlag(binder::VariableFlags::OPTIONAL)) {
            flags |= binder::VariableFlags::OPTIONAL;
        }

        collected_types.push_back(GetTypeOfVariable(prop));
    }

    if (collected_types.empty()) {
        return nullptr;
    }

    binder::Variable *synthetic_prop = binder::Scope::CreateVar(Allocator(), name, flags, nullptr);
    synthetic_prop->SetTsType(CreateUnionType(std::move(collected_types)));
    type->CachedSyntheticProperties().insert({name, synthetic_prop});
    return synthetic_prop;
}

Type *TSChecker::CheckComputedPropertyName(ir::Expression *key)
{
    if (key->TsType() != nullptr) {
        return key->TsType();
    }

    Type *key_type = key->Check(this);

    if (!key_type->HasTypeFlag(TypeFlag::STRING_LIKE | TypeFlag::NUMBER_LIKE)) {
        ThrowTypeError(
            "A computed property name in a type literal must refer to an expression whose type is a literal "
            "type "
            "or a 'unique symbol' type",
            key->Start());
    }

    key->SetTsType(key_type);
    return key_type;
}

IndexInfo *TSChecker::GetApplicableIndexInfo(Type *type, Type *index_type)
{
    ResolveStructuredTypeMembers(type);
    bool get_number_info = index_type->HasTypeFlag(TypeFlag::NUMBER_LIKE);

    if (type->IsObjectType()) {
        if (get_number_info) {
            return type->AsObjectType()->NumberIndexInfo();
        }

        return type->AsObjectType()->StringIndexInfo();
    }

    if (type->IsUnionType()) {
        ASSERT(type->AsUnionType()->MergedObjectType());

        if (get_number_info) {
            return type->AsUnionType()->MergedObjectType()->NumberIndexInfo();
        }

        return type->AsUnionType()->MergedObjectType()->StringIndexInfo();
    }

    return nullptr;
}

Type *TSChecker::GetPropertyTypeForIndexType(Type *type, Type *index_type)
{
    if (type->IsArrayType()) {
        return type->AsArrayType()->ElementType();
    }

    if (index_type->HasTypeFlag(TypeFlag::STRING_LITERAL | TypeFlag::NUMBER_LITERAL)) {
        binder::Variable *prop = nullptr;

        if (index_type->IsStringLiteralType()) {
            prop = GetPropertyOfType(type, index_type->AsStringLiteralType()->Value());
        } else {
            util::StringView prop_name =
                util::Helpers::ToStringView(Allocator(), index_type->AsNumberLiteralType()->Value());
            prop = GetPropertyOfType(type, prop_name);
        }

        if (prop != nullptr) {
            Type *prop_type = GetTypeOfVariable(prop);

            if (prop->HasFlag(binder::VariableFlags::READONLY)) {
                prop_type->AddTypeFlag(TypeFlag::READONLY);
            }

            return prop_type;
        }
    }

    if (index_type->HasTypeFlag(TypeFlag::STRING_LIKE | TypeFlag::NUMBER_LIKE)) {
        IndexInfo *index_info = GetApplicableIndexInfo(type, index_type);

        if (index_info != nullptr) {
            Type *index_info_type = index_info->GetType();

            if (index_info->Readonly()) {
                index_info_type->AddTypeFlag(TypeFlag::READONLY);
            }

            return index_info_type;
        }
    }

    return nullptr;
}

ArenaVector<ObjectType *> TSChecker::GetBaseTypes(InterfaceType *type)
{
    if (type->HasObjectFlag(ObjectFlags::RESOLVED_BASE_TYPES)) {
        return type->Bases();
    }

    ASSERT(type->Variable() && type->Variable()->Declaration()->IsInterfaceDecl());
    binder::InterfaceDecl *decl = type->Variable()->Declaration()->AsInterfaceDecl();

    TypeStackElement tse(this, type, {"Type ", type->Name(), " recursively references itself as a base type."},
                         decl->Node()->AsTSInterfaceDeclaration()->Id()->Start());

    for (const auto *declaration : decl->Decls()) {
        if (declaration->Extends().empty()) {
            continue;
        }

        for (auto *extends : declaration->Extends()) {
            Type *base_type = extends->Expr()->GetType(this);

            if (!base_type->HasTypeFlag(TypeFlag::OBJECT | TypeFlag::NON_PRIMITIVE | TypeFlag::ANY)) {
                ThrowTypeError(
                    "An interface can only extend an object type or intersection of object types with statically "
                    "known "
                    "members",
                    extends->Start());
            }

            if (!base_type->IsObjectType()) {
                continue;
            }

            ObjectType *base_obj = base_type->AsObjectType();

            if (base_type == type) {
                ThrowTypeError({"Type ", type->Name(), " recursively references itself as a base type."},
                               decl->Node()->AsTSInterfaceDeclaration()->Id()->Start());
            }

            type->AddBase(base_obj);

            if (!base_obj->IsInterfaceType()) {
                continue;
            }

            ArenaVector<ObjectType *> extends_bases = GetBaseTypes(base_obj->AsInterfaceType());
            for (auto *extend_base : extends_bases) {
                if (extend_base == type) {
                    ThrowTypeError({"Type ", type->Name(), " recursively references itself as a base type."},
                                   decl->Node()->AsTSInterfaceDeclaration()->Id()->Start());
                }
            }
        }
    }

    type->AddObjectFlag(ObjectFlags::RESOLVED_BASE_TYPES);
    return type->Bases();
}

void TSChecker::ResolveDeclaredMembers(InterfaceType *type)
{
    if (type->HasObjectFlag(ObjectFlags::RESOLVED_DECLARED_MEMBERS)) {
        return;
    }

    ASSERT(type->Variable() && type->Variable()->Declaration()->IsInterfaceDecl());
    binder::InterfaceDecl *decl = type->Variable()->Declaration()->AsInterfaceDecl();

    ArenaVector<ir::TSSignatureDeclaration *> signature_declarations(Allocator()->Adapter());
    ArenaVector<ir::TSIndexSignature *> index_declarations(Allocator()->Adapter());

    for (const auto *declaration : decl->Decls()) {
        for (auto *member : declaration->Body()->Body()) {
            ResolvePropertiesOfObjectType(type, member, signature_declarations, index_declarations, true);
        }

        type->AddObjectFlag(ObjectFlags::RESOLVED_DECLARED_MEMBERS);

        ResolveSignaturesOfObjectType(type, signature_declarations);
        ResolveIndexInfosOfObjectType(type, index_declarations);
    }
}

bool TSChecker::ValidateInterfaceMemberRedeclaration(ObjectType *type, binder::Variable *prop,
                                                     const lexer::SourcePosition &loc_info)
{
    if (prop->HasFlag(binder::VariableFlags::COMPUTED)) {
        return true;
    }

    binder::Variable *found = type->GetProperty(prop->Name(), false);

    if (found == nullptr) {
        return true;
    }

    Type *target_type = GetTypeOfVariable(prop);
    Type *source_type = GetTypeOfVariable(found);
    IsTypeIdenticalTo(target_type, source_type,
                      {"Subsequent property declarations must have the same type.  Property ", prop->Name(),
                       " must be of type ", source_type, ", but here has type ", target_type, "."},
                      loc_info);
    return false;
}
}  // namespace panda::es2panda::checker
