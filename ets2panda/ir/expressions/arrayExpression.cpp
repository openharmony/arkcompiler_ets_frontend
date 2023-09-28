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

#include "arrayExpression.h"

#include "plugins/ecmascript/es2panda/ir/base/decorator.h"
#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/checker/TSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ETSchecker.h"
#include "plugins/ecmascript/es2panda/checker/ets/typeRelationContext.h"
#include "plugins/ecmascript/es2panda/checker/ts/destructuringContext.h"
#include "plugins/ecmascript/es2panda/compiler/base/literals.h"
#include "plugins/ecmascript/es2panda/compiler/core/pandagen.h"
#include "plugins/ecmascript/es2panda/compiler/core/ETSGen.h"
#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/base/spreadElement.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/assignmentExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"

namespace panda::es2panda::ir {
bool ArrayExpression::ConvertibleToArrayPattern()
{
    bool rest_found = false;
    bool conv_result = true;
    for (auto *it : elements_) {
        switch (it->Type()) {
            case AstNodeType::ARRAY_EXPRESSION: {
                conv_result = it->AsArrayExpression()->ConvertibleToArrayPattern();
                break;
            }
            case AstNodeType::SPREAD_ELEMENT: {
                if (!rest_found && it == elements_.back() && !trailing_comma_) {
                    conv_result = it->AsSpreadElement()->ConvertibleToRest(is_declaration_);
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
            case AstNodeType::MEMBER_EXPRESSION:
            case AstNodeType::OMITTED_EXPRESSION:
            case AstNodeType::IDENTIFIER:
            case AstNodeType::ARRAY_PATTERN:
            case AstNodeType::OBJECT_PATTERN:
            case AstNodeType::ASSIGNMENT_PATTERN:
            case AstNodeType::REST_ELEMENT: {
                break;
            }
            default: {
                conv_result = false;
                break;
            }
        }

        if (!conv_result) {
            break;
        }
    }

    SetType(AstNodeType::ARRAY_PATTERN);
    return conv_result;
}

ValidationInfo ArrayExpression::ValidateExpression()
{
    if (optional_) {
        return {"Unexpected token '?'.", Start()};
    }

    if (TypeAnnotation() != nullptr) {
        return {"Unexpected token.", TypeAnnotation()->Start()};
    }

    ValidationInfo info;

    for (auto *it : elements_) {
        switch (it->Type()) {
            case AstNodeType::OBJECT_EXPRESSION: {
                info = it->AsObjectExpression()->ValidateExpression();
                break;
            }
            case AstNodeType::ARRAY_EXPRESSION: {
                info = it->AsArrayExpression()->ValidateExpression();
                break;
            }
            case AstNodeType::ASSIGNMENT_EXPRESSION: {
                auto *assignment_expr = it->AsAssignmentExpression();

                if (assignment_expr->Left()->IsArrayExpression()) {
                    info = assignment_expr->Left()->AsArrayExpression()->ValidateExpression();
                } else if (assignment_expr->Left()->IsObjectExpression()) {
                    info = assignment_expr->Left()->AsObjectExpression()->ValidateExpression();
                }

                break;
            }
            case AstNodeType::SPREAD_ELEMENT: {
                info = it->AsSpreadElement()->ValidateExpression();
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

void ArrayExpression::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    for (auto *it : elements_) {
        cb(it);
    }

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void ArrayExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", type_ == AstNodeType::ARRAY_EXPRESSION ? "ArrayExpression" : "ArrayPattern"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"elements", elements_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())},
                 {"optional", AstDumper::Optional(optional_)}});
}

void ArrayExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg array_obj = pg->AllocReg();

    pg->CreateArray(this, elements_, array_obj);
}

void ArrayExpression::Compile(compiler::ETSGen *const etsg) const
{
    const compiler::RegScope rs(etsg);

    const auto arr = etsg->AllocReg();
    const auto dim = etsg->AllocReg();

    const compiler::TargetTypeContext ttctx(etsg, etsg->Checker()->GlobalIntType());
    etsg->LoadAccumulatorInt(this, static_cast<std::int32_t>(elements_.size()));
    etsg->StoreAccumulator(this, dim);
    etsg->NewArray(this, arr, dim, TsType());

    const auto index_reg = etsg->AllocReg();
    for (std::uint32_t i = 0; i < elements_.size(); ++i) {
        const auto *const expr = elements_[i];
        etsg->LoadAccumulatorInt(this, i);
        etsg->StoreAccumulator(this, index_reg);

        const compiler::TargetTypeContext ttctx2(etsg, preferred_type_);
        if (!etsg->TryLoadConstantExpression(expr)) {
            expr->Compile(etsg);
        }

        etsg->ApplyConversion(expr, nullptr);
        etsg->ApplyConversion(expr);
        etsg->StoreArrayElement(this, arr, index_reg, TsType()->AsETSArrayType()->ElementType());
    }

    etsg->LoadAccumulator(this, arr);
}

void GetSpreadElementType(checker::TSChecker *checker, checker::Type *spread_type,
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

checker::Type *ArrayExpression::Check(checker::TSChecker *checker)
{
    ArenaVector<checker::Type *> element_types(checker->Allocator()->Adapter());
    ArenaVector<checker::ElementFlags> element_flags(checker->Allocator()->Adapter());
    bool in_const_context = checker->HasStatus(checker::CheckerStatus::IN_CONST_CONTEXT);
    bool create_tuple = checker->HasStatus(checker::CheckerStatus::FORCE_TUPLE);

    for (auto *it : elements_) {
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
            binder::LocalVariable *tuple_member =
                binder::Scope::CreateVar(checker->Allocator(), member_index, binder::VariableFlags::PROPERTY, nullptr);

            if (in_const_context) {
                tuple_member->AddFlag(binder::VariableFlags::READONLY);
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

checker::Type *ArrayExpression::CheckPattern(checker::TSChecker *checker)
{
    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
    ArenaVector<checker::ElementFlags> element_flags(checker->Allocator()->Adapter());
    checker::ElementFlags combined_flags = checker::ElementFlags::NO_OPTS;
    uint32_t min_length = 0;
    uint32_t index = elements_.size();
    bool add_optional = true;

    for (auto it = elements_.rbegin(); it != elements_.rend(); it++) {
        checker::Type *element_type = nullptr;
        checker::ElementFlags member_flag = checker::ElementFlags::NO_OPTS;

        switch ((*it)->Type()) {
            case ir::AstNodeType::REST_ELEMENT: {
                element_type = checker->Allocator()->New<checker::ArrayType>(checker->GlobalAnyType());
                member_flag = checker::ElementFlags::REST;
                add_optional = false;
                break;
            }
            case ir::AstNodeType::OBJECT_PATTERN: {
                element_type = (*it)->AsObjectPattern()->CheckPattern(checker);
                member_flag = checker::ElementFlags::REQUIRED;
                add_optional = false;
                break;
            }
            case ir::AstNodeType::ARRAY_PATTERN: {
                element_type = (*it)->AsArrayPattern()->CheckPattern(checker);
                member_flag = checker::ElementFlags::REQUIRED;
                add_optional = false;
                break;
            }
            case ir::AstNodeType::ASSIGNMENT_PATTERN: {
                auto *assignment_pattern = (*it)->AsAssignmentPattern();

                if (assignment_pattern->Left()->IsIdentifier()) {
                    const ir::Identifier *ident = assignment_pattern->Left()->AsIdentifier();
                    ASSERT(ident->Variable());
                    binder::Variable *binding_var = ident->Variable();
                    checker::Type *initializer_type =
                        checker->GetBaseTypeOfLiteralType(assignment_pattern->Right()->Check(checker));
                    binding_var->SetTsType(initializer_type);
                    element_type = initializer_type;
                } else if (assignment_pattern->Left()->IsArrayPattern()) {
                    auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
                    auto destructuring_context =
                        checker::ArrayDestructuringContext(checker, assignment_pattern->Left()->AsArrayPattern(), false,
                                                           true, nullptr, assignment_pattern->Right());
                    destructuring_context.Start();
                    element_type = destructuring_context.InferredType();
                } else {
                    ASSERT(assignment_pattern->Left()->IsObjectPattern());
                    auto saved_context = checker::SavedCheckerContext(checker, checker::CheckerStatus::FORCE_TUPLE);
                    auto destructuring_context =
                        checker::ObjectDestructuringContext(checker, assignment_pattern->Left()->AsObjectPattern(),
                                                            false, true, nullptr, assignment_pattern->Right());
                    destructuring_context.Start();
                    element_type = destructuring_context.InferredType();
                }

                if (add_optional) {
                    member_flag = checker::ElementFlags::OPTIONAL;
                } else {
                    member_flag = checker::ElementFlags::REQUIRED;
                }

                break;
            }
            case ir::AstNodeType::OMITTED_EXPRESSION: {
                element_type = checker->GlobalAnyType();
                member_flag = checker::ElementFlags::REQUIRED;
                add_optional = false;
                break;
            }
            case ir::AstNodeType::IDENTIFIER: {
                const ir::Identifier *ident = (*it)->AsIdentifier();
                ASSERT(ident->Variable());
                element_type = checker->GlobalAnyType();
                ident->Variable()->SetTsType(element_type);
                member_flag = checker::ElementFlags::REQUIRED;
                add_optional = false;
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        util::StringView member_index = util::Helpers::ToStringView(checker->Allocator(), index - 1);

        auto *member_var =
            binder::Scope::CreateVar(checker->Allocator(), member_index, binder::VariableFlags::PROPERTY, *it);

        if (member_flag == checker::ElementFlags::OPTIONAL) {
            member_var->AddFlag(binder::VariableFlags::OPTIONAL);
        } else {
            min_length++;
        }

        member_var->SetTsType(element_type);
        element_flags.push_back(member_flag);
        desc->properties.insert(desc->properties.begin(), member_var);

        combined_flags |= member_flag;
        index--;
    }

    return checker->CreateTupleType(desc, std::move(element_flags), combined_flags, min_length, desc->properties.size(),
                                    false);
}

checker::Type *ArrayExpression::Check(checker::ETSChecker *checker)
{
    if (!elements_.empty()) {
        if (preferred_type_ == nullptr) {
            preferred_type_ = elements_[0]->Check(checker);
        }

        for (auto *element : elements_) {
            if (element->IsArrayExpression() && preferred_type_->IsETSArrayType()) {
                element->AsArrayExpression()->SetPreferredType(preferred_type_->AsETSArrayType()->ElementType());
            }
            if (element->IsObjectExpression()) {
                element->AsObjectExpression()->SetPreferredType(preferred_type_);
            }

            checker::Type *element_type = element->Check(checker);
            checker::AssignmentContext(checker->Relation(), element, element_type, preferred_type_, element->Start(),
                                       {"Array element type '", element_type, "' is not assignable to explicit type '",
                                        GetPreferredType(), "'"});
        }
    }

    if (preferred_type_ == nullptr) {
        checker->ThrowTypeError("Can't resolve array type", Start());
    }

    SetTsType(checker->CreateETSArrayType(preferred_type_));
    auto array_type = TsType()->AsETSArrayType();
    checker->CreateBuiltinArraySignature(array_type, array_type->Rank());
    return TsType();
}
}  // namespace panda::es2panda::ir
