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

#include "spreadElement.h"
#include "es2panda.h"

#include "ir/astDump.h"
#include "ir/base/decorator.h"
#include "ir/typeNode.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/objectExpression.h"

namespace panda::es2panda::ir {
SpreadElement::SpreadElement([[maybe_unused]] Tag const tag, SpreadElement const &other,
                             ArenaAllocator *const allocator)
    : AnnotatedExpression(static_cast<AnnotatedExpression const &>(other)), decorators_(allocator->Adapter())
{
    CloneTypeAnnotation(allocator);
    optional_ = other.optional_;

    if (other.argument_ != nullptr) {
        argument_ = other.argument_->Clone(allocator, this);
    }

    for (auto *decorator : other.decorators_) {
        decorators_.emplace_back(decorator->Clone(allocator, this)->AsDecorator());
    }
}

// NOLINTNEXTLINE(google-default-arguments)
Expression *SpreadElement::Clone(ArenaAllocator *const allocator, AstNode *const parent)
{
    if (auto *const clone = allocator->New<SpreadElement>(Tag {}, *this, allocator); clone != nullptr) {
        if (parent != nullptr) {
            clone->SetParent(parent);
        }
        return clone;
    }
    throw Error(ErrorType::GENERIC, "", CLONE_ALLOCATION_ERROR);
}

ValidationInfo SpreadElement::ValidateExpression()
{
    ValidationInfo info;

    switch (argument_->Type()) {
        case AstNodeType::OBJECT_EXPRESSION: {
            info = argument_->AsObjectExpression()->ValidateExpression();
            break;
        }
        case AstNodeType::ARRAY_EXPRESSION: {
            info = argument_->AsArrayExpression()->ValidateExpression();
            break;
        }
        default: {
            break;
        }
    }

    return info;
}

bool SpreadElement::ConvertibleToRest(bool is_declaration, bool allow_pattern)
{
    bool conv_result = true;

    switch (argument_->Type()) {
        case AstNodeType::ARRAY_EXPRESSION: {
            conv_result = allow_pattern && argument_->AsArrayExpression()->ConvertibleToArrayPattern();
            break;
        }
        case AstNodeType::OBJECT_EXPRESSION: {
            conv_result = allow_pattern && argument_->AsObjectExpression()->ConvertibleToObjectPattern();
            break;
        }
        case AstNodeType::META_PROPERTY_EXPRESSION:
        case AstNodeType::CHAIN_EXPRESSION:
        case AstNodeType::ASSIGNMENT_EXPRESSION: {
            conv_result = false;
            break;
        }
        case AstNodeType::MEMBER_EXPRESSION: {
            conv_result = !is_declaration;
            break;
        }
        default: {
            break;
        }
    }

    SetType(AstNodeType::REST_ELEMENT);
    return conv_result;
}

void SpreadElement::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : decorators_) {
        it = cb(it)->AsDecorator();
    }

    argument_ = cb(argument_)->AsExpression();

    if (TypeAnnotation() != nullptr) {
        SetTsTypeAnnotation(static_cast<TypeNode *>(cb(TypeAnnotation())));
    }
}

void SpreadElement::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : decorators_) {
        cb(it);
    }

    cb(argument_);

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void SpreadElement::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", (type_ == AstNodeType::SPREAD_ELEMENT) ? "SpreadElement" : "RestElement"},
                 {"decorators", AstDumper::Optional(decorators_)},
                 {"argument", argument_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())}});
}

void SpreadElement::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *SpreadElement::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *SpreadElement::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
