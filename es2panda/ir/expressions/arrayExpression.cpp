/**
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <compiler/core/pandagen.h>
#include <ir/astDump.h>
#include <ir/base/spreadElement.h>
#include <ir/expressions/assignmentExpression.h>
#include <ir/expressions/objectExpression.h>
#include <ir/expressions/identifier.h>

namespace panda::es2panda::ir {

bool ArrayExpression::ConvertibleToArrayPattern()
{
    bool restFound = false;
    bool convResult = true;
    for (auto *it : elements_) {
        switch (it->Type()) {
            case AstNodeType::ARRAY_EXPRESSION: {
                convResult = it->AsArrayExpression()->ConvertibleToArrayPattern();
                break;
            }
            case AstNodeType::SPREAD_ELEMENT: {
                if (!restFound && it == elements_.back() && !trailingComma_) {
                    convResult = it->AsSpreadElement()->ConvertibleToRest(isDeclaration_);
                } else {
                    convResult = false;
                }
                restFound = true;
                break;
            }
            case AstNodeType::OBJECT_EXPRESSION: {
                convResult = it->AsObjectExpression()->ConvertibleToObjectPattern();
                break;
            }
            case AstNodeType::ASSIGNMENT_EXPRESSION: {
                convResult = it->AsAssignmentExpression()->ConvertibleToAssignmentPattern();
                break;
            }
            case AstNodeType::META_PROPERTY_EXPRESSION:
            case AstNodeType::CHAIN_EXPRESSION:
            case AstNodeType::SEQUENCE_EXPRESSION:
            case AstNodeType::NUMBER_LITERAL:
            case AstNodeType::STRING_LITERAL:
            case AstNodeType::BOOLEAN_LITERAL:
            case AstNodeType::NULL_LITERAL:
            case AstNodeType::BIGINT_LITERAL: {
                convResult = false;
                break;
            }
            default: {
                break;
            }
        }

        if (!convResult) {
            break;
        }
    }

    SetType(AstNodeType::ARRAY_PATTERN);
    return convResult;
}

ValidationInfo ArrayExpression::ValidateExpression()
{
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
                auto *assignmentExpr = it->AsAssignmentExpression();

                if (assignmentExpr->Left()->IsArrayExpression()) {
                    info = assignmentExpr->Left()->AsArrayExpression()->ValidateExpression();
                } else if (assignmentExpr->Left()->IsObjectExpression()) {
                    info = assignmentExpr->Left()->AsObjectExpression()->ValidateExpression();
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
    for (auto *it : elements_) {
        cb(it);
    }

    if (typeAnnotation_) {
        cb(typeAnnotation_);
    }
}

void ArrayExpression::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", type_ == AstNodeType::ARRAY_EXPRESSION ? "ArrayExpression" : "ArrayPattern"},
                 {"elements", elements_},
                 {"typeAnnotation", AstDumper::Optional(typeAnnotation_)},
                 {"optional", AstDumper::Optional(optional_)}});
}

void ArrayExpression::Compile(compiler::PandaGen *pg) const
{
    compiler::RegScope rs(pg);
    compiler::VReg arrayObj = pg->AllocReg();

    pg->CreateArray(this, elements_, arrayObj);
}

void ArrayExpression::UpdateSelf(const NodeUpdater &cb, [[maybe_unused]] binder::Binder *binder)
{
    for (auto iter = elements_.begin(); iter != elements_.end(); iter++) {
        *iter = std::get<ir::AstNode *>(cb(*iter))->AsExpression();
    }
}

}  // namespace panda::es2panda::ir
