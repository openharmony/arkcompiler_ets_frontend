/**
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

#include "objectExpression.h"

#include "ir/base/decorator.h"
#include "util/helpers.h"
#include "compiler/base/literals.h"
#include "compiler/core/pandagen.h"
#include "compiler/core/ETSGen.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "checker/ets/typeRelationContext.h"
#include "checker/ts/destructuringContext.h"
#include "ir/astDump.h"
#include "ir/typeNode.h"
#include "ir/base/property.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNewClassInstanceExpression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/validationInfo.h"
#include "util/bitset.h"

namespace panda::es2panda::ir {
ObjectExpression::ObjectExpression([[maybe_unused]] Tag const tag, ObjectExpression const &other,
                                   ArenaAllocator *const allocator)
    : AnnotatedExpression(static_cast<AnnotatedExpression const &>(other), allocator),
      decorators_(allocator->Adapter()),
      properties_(allocator->Adapter())
{
    preferred_type_ = other.preferred_type_;
    is_declaration_ = other.is_declaration_;
    trailing_comma_ = other.trailing_comma_;
    optional_ = other.optional_;

    for (auto *property : other.properties_) {
        properties_.emplace_back(property->Clone(allocator, this)->AsExpression());
    }

    for (auto *decorator : other.decorators_) {
        decorators_.emplace_back(decorator->Clone(allocator, this));
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ObjectExpression *ObjectExpression::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<ObjectExpression>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

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
    // NOTE: rsipka. throw more precise messages in case of false results
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

void ObjectExpression::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : decorators_) {
        it = cb(it)->AsDecorator();
    }

    for (auto *&it : properties_) {
        it = cb(it)->AsExpression();
    }

    if (TypeAnnotation() != nullptr) {
        SetTsTypeAnnotation(static_cast<TypeNode *>(cb(TypeAnnotation())));
    }
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

void ObjectExpression::Compile([[maybe_unused]] compiler::PandaGen *pg) const
{
    pg->GetAstCompiler()->Compile(this);
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

        varbinder::LocalVariable *found_var = desc->FindProperty(prop->Key()->AsIdentifier()->Name());
        checker::Type *pattern_param_type = checker->GlobalAnyType();
        varbinder::Variable *binding_var = nullptr;

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

        varbinder::LocalVariable *pattern_var = varbinder::Scope::CreateVar(
            checker->Allocator(), prop->Key()->AsIdentifier()->Name(), varbinder::VariableFlags::PROPERTY, *it);
        pattern_var->SetTsType(pattern_param_type);

        if (is_optional) {
            pattern_var->AddFlag(varbinder::VariableFlags::OPTIONAL);
        }

        desc->properties.insert(desc->properties.begin(), pattern_var);
    }

    checker::Type *return_type = checker->Allocator()->New<checker::ObjectLiteralType>(desc);
    return_type->AsObjectType()->AddObjectFlag(checker::ObjectFlags::RESOLVED_MEMBERS);
    return return_type;
}

checker::Type *ObjectExpression::Check(checker::TSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}

void ObjectExpression::Compile(compiler::ETSGen *etsg) const
{
    etsg->GetAstCompiler()->Compile(this);
}

checker::Type *ObjectExpression::Check(checker::ETSChecker *checker)
{
    return checker->GetAnalyzer()->Check(this);
}
}  // namespace panda::es2panda::ir
