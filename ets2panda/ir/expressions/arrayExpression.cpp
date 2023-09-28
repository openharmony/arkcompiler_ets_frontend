/**
 * Copyright (c) 2021 2023 Huawei Device Co., Ltd.
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

#include "checker/ETSchecker.h"
#include "checker/TSchecker.h"
#include "checker/ets/castingContext.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/ts/destructuringContext.h"
#include "compiler/core/ETSGen.h"
#include "compiler/core/pandagen.h"
#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/typeNode.h"
#include "util/helpers.h"

namespace panda::es2panda::ir {
ArrayExpression::ArrayExpression([[maybe_unused]] Tag const tag, ArrayExpression const &other,
                                 ArenaAllocator *const allocator)
    : AnnotatedExpression(static_cast<AnnotatedExpression const &>(other), allocator),
      decorators_(allocator->Adapter()),
      elements_(allocator->Adapter())
{
    preferred_type_ = other.preferred_type_;
    is_declaration_ = other.is_declaration_;
    trailing_comma_ = other.trailing_comma_;
    optional_ = other.optional_;

    for (auto *element : other.elements_) {
        elements_.emplace_back(element->Clone(allocator, this)->AsExpression());
    }

    for (auto *decorator : other.decorators_) {
        decorators_.emplace_back(decorator->Clone(allocator, this));
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ArrayExpression *ArrayExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<ArrayExpression>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

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

void ArrayExpression::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : decorators_) {
        it = cb(it)->AsDecorator();
    }

    for (auto *&it : elements_) {
        it = cb(it)->AsExpression();
    }

    if (TypeAnnotation() != nullptr) {
        SetTsTypeAnnotation(static_cast<TypeNode *>(cb(TypeAnnotation())));
    }
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
    pg->GetAstCompiler()->Compile(this);
}

void ArrayExpression::Compile(compiler::ETSGen *const etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ArrayExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
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
                    varbinder::Variable *binding_var = ident->Variable();
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
            varbinder::Scope::CreateVar(checker->Allocator(), member_index, varbinder::VariableFlags::PROPERTY, *it);

        if (member_flag == checker::ElementFlags::OPTIONAL) {
            member_var->AddFlag(varbinder::VariableFlags::OPTIONAL);
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

void ArrayExpression::HandleNestedArrayExpression(checker::ETSChecker *const checker,
                                                  ArrayExpression *const current_element, const bool is_array,
                                                  const bool is_preferred_tuple, const std::size_t idx)
{
    if (is_preferred_tuple) {
        current_element->SetPreferredType(is_array ? preferred_type_
                                                   : preferred_type_->AsETSTupleType()->GetTypeAtIndex(idx));

        if (current_element->GetPreferredType()->IsETSTupleType()) {
            checker->ValidateTupleMinElementSize(current_element,
                                                 current_element->GetPreferredType()->AsETSTupleType());
        }

        return;
    }

    if (preferred_type_->IsETSArrayType()) {
        if (preferred_type_->AsETSArrayType()->ElementType()->IsETSTupleType()) {
            checker->ValidateTupleMinElementSize(current_element,
                                                 preferred_type_->AsETSArrayType()->ElementType()->AsETSTupleType());
        }

        current_element->SetPreferredType(is_array ? preferred_type_
                                                   : preferred_type_->AsETSArrayType()->ElementType());
        return;
    }

    if (current_element->GetPreferredType() == nullptr) {
        current_element->SetPreferredType(preferred_type_);
    }
}

checker::Type *ArrayExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
