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

#include "objectExpression.h"

#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"
#include "plugins/ecmascript/es2panda/checker/ts/destructuringContext.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/base/property.h"
#include "plugins/ecmascript/es2panda/ir/base/scriptFunction.h"
#include "plugins/ecmascript/es2panda/ir/base/spreadElement.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsTypeReference.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsTypeReferencePart.h"
#include "plugins/ecmascript/es2panda/ir/ets/etsNewClassInstanceExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/functionExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/nullLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/statements/variableDeclarator.h"
#include "plugins/ecmascript/es2panda/ir/validationInfo.h"
#include "plugins/ecmascript/es2panda/util/bitset.h"

namespace panda::es2panda::ir {
ValidationInfo ObjectExpression::ValidateExpression()
{
    if (optional_) {
        return {"Unexpected token '?'.", Start()};
    }

    if (TypeAnnotation() != nullptr) {
        return {"Unexpected token.", TypeAnnotation()->Start()};
    }

    ValidationInfo info;
    bool found_proto = false;

    for (auto *it : properties_) {
        switch (it->Type()) {
            case AstNodeType::OBJECT_EXPRESSION:
            case AstNodeType::ARRAY_EXPRESSION: {
                return {"Unexpected token.", it->Start()};
            }
            case AstNodeType::SPREAD_ELEMENT: {
                info = it->AsSpreadElement()->ValidateExpression();
                break;
            }
            case AstNodeType::PROPERTY: {
                auto *prop = it->AsProperty();
                info = prop->ValidateExpression();

                if (prop->Kind() == PropertyKind::PROTO) {
                    if (found_proto) {
                        return {"Duplicate __proto__ fields are not allowed in object literals", prop->Key()->Start()};
                    }

                    found_proto = true;
                }

                break;
            }
            default: {
                break;
            }
        }

        if (info.Fail()) {
            break;
        }
    }

    return info;
}

bool ObjectExpression::ConvertibleToObjectPattern()
{
    // TODO(rsipka): throw more precise messages in case of false results
    bool rest_found = false;
    bool conv_result = true;

    for (auto *it : properties_) {
        switch (it->Type()) {
            case AstNodeType::ARRAY_EXPRESSION: {
                conv_result = it->AsArrayExpression()->ConvertibleToArrayPattern();
                break;
            }
            case AstNodeType::SPREAD_ELEMENT: {
                if (!rest_found && it == properties_.back() && !trailing_comma_) {
                    conv_result = it->AsSpreadElement()->ConvertibleToRest(is_declaration_, false);
                } else {
                    conv_result = false;
                }

                rest_found = true;
                break;
            }
            case AstNodeType::OBJECT_EXPRESSION: {
                conv_result = it->AsObjectExpression()->ConvertibleToObjectPattern();
                break;
            }
            case AstNodeType::ASSIGNMENT_EXPRESSION: {
                conv_result = it->AsAssignmentExpression()->ConvertibleToAssignmentPattern();
                break;
            }
            case AstNodeType::META_PROPERTY_EXPRESSION:
            case AstNodeType::CHAIN_EXPRESSION:
            case AstNodeType::SEQUENCE_EXPRESSION: {
                conv_result = false;
                break;
            }
            case AstNodeType::PROPERTY: {
                conv_result = it->AsProperty()->ConvertibleToPatternProperty();
                break;
            }
            default: {
                break;
            }
        }

        if (!conv_result) {
            break;
        }
    }

    SetType(AstNodeType::OBJECT_PATTERN);
    return conv_result;
}

void ObjectExpression::SetDeclaration()
{
    is_declaration_ = true;
}

void ObjectExpression::SetOptional(bool optional)
{
    optional_ = optional;
}

void ObjectExpression::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    for (auto *it : properties_) {
        cb(it);
    }

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void ObjectExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", (type_ == AstNodeType::OBJECT_EXPRESSION) ? "ObjectExpression" : "ObjectPattern"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"properties", properties_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())},
                 {"optional", AstDumper::Optional(optional_)}});
}

static compiler::Literal CreateLiteral(const ir::Property *prop, util::BitSet *compiled, size_t prop_index)
{
    compiler::Literal lit = util::Helpers::ToConstantLiteral(prop->Value());
    if (!lit.IsInvalid()) {
        compiled->Set(prop_index);
        return lit;
    }

    if (prop->Kind() != ir::PropertyKind::INIT) {
        ASSERT(prop->IsAccessor());
        return compiler::Literal::AccessorLiteral();
    }

    if (!prop->Value()->IsFunctionExpression()) {
        return compiler::Literal::NullLiteral();
    }

    const ir::ScriptFunction *method = prop->Value()->AsFunctionExpression()->Function();

    compiler::LiteralTag tag = compiler::LiteralTag::METHOD;

    if (method->IsGenerator()) {
        tag = compiler::LiteralTag::GENERATOR_METHOD;

        if (method->IsAsyncFunc()) {
            tag = compiler::LiteralTag::ASYNC_GENERATOR_METHOD;
        }
    }

    compiled->Set(prop_index);
    return compiler::Literal(tag, method->Scope()->InternalName());
}

static bool IsLiteralBufferCompatible(const Expression *expr)
{
    if (expr->IsSpreadElement()) {
        return false;
    }

    const ir::Property *prop = expr->AsProperty();
    if (prop->Value()->IsFunctionExpression() && !prop->Value()->AsFunctionExpression()->Function()->IsMethod()) {
        return false;
    }

    return util::Helpers::IsConstantPropertyKey(prop->Key(), prop->IsComputed()) &&
           prop->Kind() != ir::PropertyKind::PROTO;
}

void ObjectExpression::CompileStaticProperties(compiler::PandaGen *pg, util::BitSet *compiled) const
{
    bool has_method = false;
    bool seen_computed = false;
    compiler::LiteralBuffer buf;
    std::unordered_map<util::StringView, size_t> prop_name_map;

    for (size_t i = 0; i < properties_.size(); i++) {
        if (!IsLiteralBufferCompatible(properties_[i])) {
            seen_computed = true;
            continue;
        }

        const ir::Property *prop = properties_[i]->AsProperty();

        util::StringView name = util::Helpers::LiteralToPropName(prop->Key());
        size_t buffer_pos = buf.size();
        auto res = prop_name_map.insert({name, buffer_pos});
        if (res.second) {
            if (seen_computed) {
                break;
            }

            buf.emplace_back(name);
            buf.emplace_back();
        } else {
            buffer_pos = res.first->second;
        }

        compiler::Literal lit = CreateLiteral(prop, compiled, i);
        if (lit.IsTagMethod()) {
            has_method = true;
        }

        buf[buffer_pos + 1] = std::move(lit);
    }

    if (buf.empty()) {
        pg->CreateEmptyObject(this);
        return;
    }

    uint32_t buf_idx = pg->AddLiteralBuffer(std::move(buf));

    if (has_method) {
        pg->CreateObjectHavingMethod(this, buf_idx);
    } else {
        pg->CreateObjectWithBuffer(this, buf_idx);
    }
}

void ObjectExpression::CompileRemainingProperties(compiler::PandaGen *pg, const util::BitSet *compiled) const
{
    compiler::RegScope rs(pg);
    compiler::VReg obj_reg = pg->AllocReg();

    pg->StoreAccumulator(this, obj_reg);

    for (size_t i = 0; i < properties_.size(); i++) {
        if (compiled->Test(i)) {
            continue;
        }

        compiler::RegScope prs(pg);

        if (properties_[i]->IsSpreadElement()) {
            compiler::VReg src_obj = pg->AllocReg();
            const ir::SpreadElement *spread = properties_[i]->AsSpreadElement();

            spread->Argument()->Compile(pg);
            pg->StoreAccumulator(spread, src_obj);

            pg->CopyDataProperties(spread, obj_reg, src_obj);
            continue;
        }

        const ir::Property *prop = properties_[i]->AsProperty();

        switch (prop->Kind()) {
            case ir::PropertyKind::GET:
            case ir::PropertyKind::SET: {
                compiler::VReg key = pg->LoadPropertyKey(prop->Key(), prop->IsComputed());

                compiler::VReg undef = pg->AllocReg();
                pg->LoadConst(this, compiler::Constant::JS_UNDEFINED);
                pg->StoreAccumulator(this, undef);

                compiler::VReg getter = undef;
                compiler::VReg setter = undef;

                compiler::VReg accessor = pg->AllocReg();
                pg->LoadAccumulator(prop->Value(), obj_reg);
                prop->Value()->Compile(pg);
                pg->StoreAccumulator(prop->Value(), accessor);

                if (prop->Kind() == ir::PropertyKind::GET) {
                    getter = accessor;
                } else {
                    setter = accessor;
                }

                pg->DefineGetterSetterByValue(this, obj_reg, key, getter, setter, prop->IsComputed());
                break;
            }
            case ir::PropertyKind::INIT: {
                compiler::Operand key = pg->ToOwnPropertyKey(prop->Key(), prop->IsComputed());

                if (prop->IsMethod()) {
                    pg->LoadAccumulator(prop->Value(), obj_reg);
                }

                prop->Value()->Compile(pg);
                pg->StoreOwnProperty(this, obj_reg, key);
                break;
            }
            case ir::PropertyKind::PROTO: {
                prop->Value()->Compile(pg);
                compiler::VReg proto = pg->AllocReg();
                pg->StoreAccumulator(this, proto);

                pg->SetObjectWithProto(this, proto, obj_reg);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }
    }

    pg->LoadAccumulator(this, obj_reg);
}

void ObjectExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    if (properties_.empty()) {
        pg->CreateEmptyObject(this);
        return;
    }

    util::BitSet compiled(properties_.size());
    CompileStaticProperties(pg, &compiled);

    if (compiled.Any(false)) {
        CompileRemainingProperties(pg, &compiled);
    }
}

checker::Type *ObjectExpression::CheckPattern(checker::TSChecker *checker)
{
    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());

    bool is_optional = false;

    for (auto it = properties_.rbegin(); it != properties_.rend(); it++) {
        if ((*it)->IsRestElement()) {
            ASSERT((*it)->AsRestElement()->Argument()->IsIdentifier());
            util::StringView index_info_name("x");
            auto *new_index_info =
                checker->Allocator()->New<checker::IndexInfo>(checker->GlobalAnyType(), index_info_name, false);
            desc->string_index_info = new_index_info;
            continue;
        }

        ASSERT((*it)->IsProperty());
        auto *prop = (*it)->AsProperty();

        if (prop->IsComputed()) {
            continue;
        }

        binder::LocalVariable *found_var = desc->FindProperty(prop->Key()->AsIdentifier()->Name());
        checker::Type *pattern_param_type = checker->GlobalAnyType();
        binder::Variable *binding_var = nullptr;

        if (prop->IsShorthand()) {
            switch (prop->Value()->Type()) {
                case ir::AstNodeType::IDENTIFIER: {
                    const ir::Identifier *ident = prop->Value()->AsIdentifier();
                    ASSERT(ident->Variable());
                    binding_var = ident->Variable();
                    break;
                }
                case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                    auto *assignment_pattern = prop->Value()->AsAssignmentPattern();
                    pattern_param_type = assignment_pattern->Right()->Check(checker);
                    ASSERT(assignment_pattern->Left()->AsIdentifier()->Variable());
                    binding_var = assignment_pattern->Left()->AsIdentifier()->Variable();
                    is_optional = true;
                    break;
                }
                default: {
                    UNREACHABLE();
                }
            }
        } else {
            switch (prop->Value()->Type()) {
                case ir::AstNodeType::IDENTIFIER: {
                    binding_var = prop->Value()->AsIdentifier()->Variable();
                    break;
                }
                case ir::AstNodeType::ARRAY_PATTERN: {
                    pattern_param_type = prop->Value()->AsArrayPattern()->CheckPattern(checker);
                    break;
                }
                case ir::AstNodeType::OBJECT_PATTERN: {
                    pattern_param_type = prop->Value()->AsObjectPattern()->CheckPattern(checker);
                    break;
                }
                case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                    auto *assignment_pattern = prop->Value()->AsAssignmentPattern();

                    if (assignment_pattern->Left()->IsIdentifier()) {
                        binding_var = assignment_pattern->Left()->AsIdentifier()->Variable();
                        pattern_param_type =
                            checker->GetBaseTypeOfLiteralType(assignment_pattern->Right()->Check(checker));
                        is_optional = true;
                        break;
                    }

                    if (assignment_pattern->Left()->IsArrayPattern()) {
                        auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
                        auto destructuring_context =
                            checker::ArrayDestructuringContext(checker, assignment_pattern->Left()->AsArrayPattern(),
                                                               false, true, nullptr, assignment_pattern->Right());

                        if (found_var != nullptr) {
                            destructuring_context.SetInferredType(
                                checker->CreateUnionType({found_var->TsType(), destructuring_context.InferredType()}));
                        }

                        destructuring_context.Start();
                        pattern_param_type = destructuring_context.InferredType();
                        is_optional = true;
                        break;
                    }

                    ASSERT(assignment_pattern->Left()->IsObjectPattern());
                    auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
                    auto destructuring_context =
                        checker::ObjectDestructuringContext(checker, assignment_pattern->Left()->AsObjectPattern(),
                                                            false, true, nullptr, assignment_pattern->Right());

                    if (found_var != nullptr) {
                        destructuring_context.SetInferredType(
                            checker->CreateUnionType({found_var->TsType(), destructuring_context.InferredType()}));
                    }

                    destructuring_context.Start();
                    pattern_param_type = destructuring_context.InferredType();
                    is_optional = true;
                    break;
                }
                default: {
                    UNREACHABLE();
                }
            }
        }

        if (binding_var != nullptr) {
            binding_var->SetTsType(pattern_param_type);
        }

        if (found_var != nullptr) {
            continue;
        }

        binder::LocalVariable *pattern_var = binder::Scope::CreateVar(
            checker->Allocator(), prop->Key()->AsIdentifier()->Name(), binder::VariableFlags::PROPERTY, *it);
        pattern_var->SetTsType(pattern_param_type);

        if (is_optional) {
            pattern_var->AddFlag(binder::VariableFlags::OPTIONAL);
        }

        desc->properties.insert(desc->properties.begin(), pattern_var);
    }

    checker::Type *return_type = checker->Allocator()->New<checker::ObjectLiteralType>(desc);
    return_type->AsObjectType()->AddObjectFlag(checker::ObjectFlags::RESOLVED_MEMBERS);
    return return_type;
}

const util::StringView &GetPropertyName(const ir::Expression *key)
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

binder::VariableFlags GetFlagsForProperty(const ir::Property *prop)
{
    if (!prop->IsMethod()) {
        return binder::VariableFlags::PROPERTY;
    }

    binder::VariableFlags prop_flags = binder::VariableFlags::METHOD;

    if (prop->IsAccessor() && prop->Kind() == PropertyKind::GET) {
        prop_flags |= binder::VariableFlags::READONLY;
    }

    return prop_flags;
}

checker::Type *GetTypeForProperty(ir::Property *prop, checker::TSChecker *checker)
{
    if (prop->IsAccessor()) {
        checker::Type *func_type = prop->Value()->Check(checker);

        if (prop->Kind() == PropertyKind::SET) {
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

checker::Type *ObjectExpression::Check(checker::TSChecker *checker)
{
    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
    std::unordered_map<util::StringView, lexer::SourcePosition> all_properties_map;
    bool in_const_context = checker->HasStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    ArenaVector<checker::Type *> computed_number_prop_types(checker->Allocator()->Adapter());
    ArenaVector<checker::Type *> computed_string_prop_types(checker->Allocator()->Adapter());
    bool has_computed_number_property = false;
    bool has_computed_string_property = false;
    bool seen_spread = false;

    for (auto *it : properties_) {
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
            binder::VariableFlags flags = GetFlagsForProperty(prop);
            const util::StringView &prop_name = GetPropertyName(prop->Key());

            auto *member_var = binder::Scope::CreateVar(checker->Allocator(), prop_name, flags, it);

            if (in_const_context) {
                member_var->AddFlag(binder::VariableFlags::READONLY);
            } else {
                prop_type = checker->GetBaseTypeOfLiteralType(prop_type);
            }

            member_var->SetTsType(prop_type);

            if (prop->Key()->IsNumberLiteral()) {
                member_var->AddFlag(binder::VariableFlags::NUMERIC_NAME);
            }

            binder::LocalVariable *found_member = desc->FindProperty(prop_name);
            all_properties_map.insert({prop_name, it->Start()});

            if (found_member != nullptr) {
                found_member->SetTsType(prop_type);
                continue;
            }

            desc->properties.push_back(member_var);
            continue;
        }

        ASSERT(it->IsSpreadElement());

        checker::Type *spread_type = it->AsSpreadElement()->Argument()->Check(checker);
        seen_spread = true;

        // TODO(aszilagyi): handle union of object types
        if (!spread_type->IsObjectType()) {
            checker->ThrowTypeError("Spread types may only be created from object types.", it->Start());
        }

        for (auto *spread_prop : spread_type->AsObjectType()->Properties()) {
            auto found = all_properties_map.find(spread_prop->Name());
            if (found != all_properties_map.end()) {
                checker->ThrowTypeError(
                    {found->first, " is specified more than once, so this usage will be overwritten."}, found->second);
            }

            binder::LocalVariable *found_member = desc->FindProperty(spread_prop->Name());

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

            if (has_computed_number_property && it->HasFlag(binder::VariableFlags::NUMERIC_NAME)) {
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

void ObjectExpression::Compile(compiler::ETSGen *etsg) const
{
    compiler::RegScope rs {etsg};
    checker::ETSObjectType const *obj_type = TsType()->AsETSObjectType();
    compiler::VReg obj_reg = etsg->AllocReg();
    if (TsType()->IsETSDynamicType()) {
        auto *signature_info = etsg->Allocator()->New<checker::SignatureInfo>(etsg->Allocator());
        auto *create_obj_sig = etsg->Allocator()->New<checker::Signature>(
            signature_info, nullptr, compiler::Signatures::BUILTIN_JSRUNTIME_CREATE_OBJECT);
        compiler::VReg dummy_reg = compiler::VReg::RegStart();
        etsg->CallDynamic(this, dummy_reg, dummy_reg, create_obj_sig,
                          ArenaVector<Expression *>(etsg->Allocator()->Adapter()));
    } else {
        checker::Signature *empty_sig = nullptr;
        for (checker::Signature *sig : obj_type->ConstructSignatures()) {
            if (sig->Params().empty()) {
                empty_sig = sig;
                break;
            }
        }
        if (empty_sig == nullptr) {  // Would have already thrown in the checker.
            UNREACHABLE();
        }
        etsg->InitObject(this, empty_sig, ArenaVector<Expression *>(etsg->Allocator()->Adapter()));
    }
    etsg->SetAccumulatorType(TsType());
    etsg->StoreAccumulator(this, obj_reg);

    for (Expression *prop_expr : Properties()) {
        ASSERT(prop_expr->IsProperty());
        Property *prop = prop_expr->AsProperty();
        Expression *key = prop->Key();
        Expression *value = prop->Value();

        util::StringView pname;
        if (key->IsStringLiteral()) {
            pname = key->AsStringLiteral()->Str();
        } else if (key->IsIdentifier()) {
            pname = key->AsIdentifier()->Name();
        } else {
            UNREACHABLE();
        }

        value->Compile(etsg);
        etsg->ApplyConversion(value, key->TsType());
        if (TsType()->IsETSDynamicType()) {
            etsg->StorePropertyDynamic(this, value->TsType(), obj_reg, pname, TsType()->AsETSDynamicType()->Language());
        } else {
            etsg->StoreProperty(this, key->TsType(), obj_reg, pname);
        }
    }

    etsg->LoadAccumulator(this, obj_reg);
}

checker::Type *ObjectExpression::Check(checker::ETSChecker *checker)
{
    if (PreferredType() == nullptr) {
        checker->ThrowTypeError({"need to specify target type for class composite"}, Start());
    }
    if (!PreferredType()->IsETSObjectType()) {
        checker->ThrowTypeError({"target type for class composite needs to be an object type"}, Start());
    }

    if (PreferredType()->IsETSDynamicType()) {
        for (Expression *prop_expr : Properties()) {
            ASSERT(prop_expr->IsProperty());
            Property *prop = prop_expr->AsProperty();
            Expression *value = prop->Value();
            value->Check(checker);
            ASSERT(value->TsType());
        }

        SetTsType(PreferredType());
        return PreferredType();
    }

    checker::ETSObjectType *obj_type = PreferredType()->AsETSObjectType();
    if (obj_type->HasObjectFlag(checker::ETSObjectFlags::ABSTRACT | checker::ETSObjectFlags::INTERFACE)) {
        checker->ThrowTypeError({"target type for class composite ", obj_type->Name(), " is not instantiable"},
                                Start());
    }

    bool have_empty_constructor = false;
    for (checker::Signature *sig : obj_type->ConstructSignatures()) {
        if (sig->Params().empty()) {
            have_empty_constructor = true;
            checker->ValidateSignatureAccessibility(obj_type, sig, Start());
            break;
        }
    }
    if (!have_empty_constructor) {
        checker->ThrowTypeError({"type ", obj_type->Name(), " has no parameterless constructor"}, Start());
    }

    for (Expression *prop_expr : Properties()) {
        ASSERT(prop_expr->IsProperty());
        Property *prop = prop_expr->AsProperty();
        Expression *key = prop->Key();
        Expression *value = prop->Value();

        util::StringView pname;
        if (key->IsStringLiteral()) {
            pname = key->AsStringLiteral()->Str();
        } else if (key->IsIdentifier()) {
            pname = key->AsIdentifier()->Name();
        } else {
            checker->ThrowTypeError({"key in class composite should be either identifier or string literal"}, Start());
        }
        binder::LocalVariable *lv = obj_type->GetProperty(pname, checker::PropertySearchFlags::SEARCH_INSTANCE_FIELD |
                                                                     checker::PropertySearchFlags::SEARCH_IN_BASE);
        if (lv == nullptr) {
            checker->ThrowTypeError({"type ", obj_type->Name(), " has no property named ", pname}, prop_expr->Start());
        }
        checker->ValidatePropertyAccess(lv, obj_type, prop_expr->Start());
        if (lv->HasFlag(binder::VariableFlags::READONLY)) {
            checker->ThrowTypeError({"cannot assign to readonly property ", pname}, prop_expr->Start());
        }

        auto *prop_type = checker->GetTypeOfVariable(lv);
        key->SetTsType(prop_type);

        if (value->IsObjectExpression()) {
            value->AsObjectExpression()->SetPreferredType(prop_type);
        }
        value->SetTsType(value->Check(checker));
        checker::AssignmentContext(checker->Relation(), value, value->TsType(), prop_type, value->Start(),
                                   {"value type is not assignable to the property type"});
    }

    SetTsType(obj_type);
    return obj_type;
}
}  // namespace panda::es2panda::ir
