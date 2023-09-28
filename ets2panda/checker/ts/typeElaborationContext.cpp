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

#include "typeElaborationContext.h"

#include "plugins/ecmascript/es2panda/util/helpers.h"
#include "plugins/ecmascript/es2panda/binder/scope.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/expressions/objectExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/arrayExpression.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/numberLiteral.h"
#include "plugins/ecmascript/es2panda/ir/expressions/literals/stringLiteral.h"
#include "plugins/ecmascript/es2panda/ir/base/spreadElement.h"
#include "plugins/ecmascript/es2panda/ir/base/property.h"

namespace panda::es2panda::checker {
Type *ElaborationContext::GetBestMatchingType(Type *index_type, ir::Expression *source_node)
{
    ArenaVector<Type *> best_matching_type(checker_->Allocator()->Adapter());
    Type *source_type = source_node != nullptr ? checker_->CheckTypeCached(source_node) : checker_->GlobalAnyType();

    for (auto it = potential_types_.begin(); it != potential_types_.end();) {
        Type *current_type = checker_->GetPropertyTypeForIndexType(*it, index_type);

        if (current_type == nullptr) {
            it = potential_types_.erase(it);
            continue;
        }

        if (!checker_->IsTypeAssignableTo(source_type, current_type)) {
            it = potential_types_.erase(it);
        } else {
            it++;
        }

        best_matching_type.push_back(current_type);
    }

    return checker_->CreateUnionType(std::move(best_matching_type));
}

void ArrayElaborationContext::Start()
{
    ASSERT(source_node_->IsArrayExpression());
    RemoveUnnecessaryTypes();

    for (auto *it : source_node_->AsArrayExpression()->Elements()) {
        if (it->IsOmittedExpression()) {
            index_++;
            continue;
        }

        util::StringView member_index = util::Helpers::ToStringView(checker_->Allocator(), index_);

        Type *target_element_type = nullptr;

        if (target_type_->IsUnionType()) {
            target_element_type = GetBestMatchingType(checker_->CreateStringLiteralType(member_index), it);
        } else {
            target_element_type =
                checker_->GetPropertyTypeForIndexType(target_type_, checker_->CreateStringLiteralType(member_index));
        }

        if (target_element_type == nullptr) {
            return;
        }

        checker_->ElaborateElementwise(target_element_type, it, it->Start());
        index_++;
    }
}

void ArrayElaborationContext::RemoveUnnecessaryTypes()
{
    if (!target_type_->IsUnionType()) {
        return;
    }

    for (auto *it : target_type_->AsUnionType()->ConstituentTypes()) {
        if (it->IsArrayType() || it->IsObjectType()) {
            potential_types_.push_back(it);
        }
    }
}

void ObjectElaborationContext::Start()
{
    ASSERT(source_node_->IsObjectExpression());
    RemoveUnnecessaryTypes();

    for (auto *it : source_node_->AsObjectExpression()->Properties()) {
        if (it->IsSpreadElement()) {
            continue;
        }

        ir::Property *prop = it->AsProperty();

        Type *prop_key_type = nullptr;
        if (prop->IsComputed()) {
            prop_key_type = checker_->CheckComputedPropertyName(prop->Key());
        } else {
            switch (prop->Key()->Type()) {
                case ir::AstNodeType::IDENTIFIER: {
                    prop_key_type = checker_->Allocator()->New<StringLiteralType>(prop->Key()->AsIdentifier()->Name());
                    break;
                }
                case ir::AstNodeType::NUMBER_LITERAL: {
                    prop_key_type = checker_->Allocator()->New<NumberLiteralType>(
                        prop->Key()->AsNumberLiteral()->Number().GetDouble());
                    break;
                }
                case ir::AstNodeType::STRING_LITERAL: {
                    prop_key_type =
                        checker_->Allocator()->New<StringLiteralType>(prop->Key()->AsStringLiteral()->Str());
                    break;
                }
                default: {
                    UNREACHABLE();
                    break;
                }
            }
        }

        Type *target_element_type = nullptr;

        if (target_type_->IsUnionType()) {
            target_element_type = GetBestMatchingType(prop_key_type, prop->IsShorthand() ? nullptr : prop->Value());
        } else {
            target_element_type = checker_->GetPropertyTypeForIndexType(target_type_, prop_key_type);
        }

        if (target_element_type == nullptr) {
            if (prop_key_type->HasTypeFlag(TypeFlag::LITERAL)) {
                checker_->ThrowTypeError({"Object literal may only specify known properties, and ", prop_key_type,
                                          " does not exist in type '", target_type_, "'."},
                                         it->Start());
            }

            return;
        }

        if (prop->IsShorthand()) {
            continue;
        }

        checker_->ElaborateElementwise(target_element_type, prop->Value(), it->Start());
    }
}

void ObjectElaborationContext::RemoveUnnecessaryTypes()
{
    if (!target_type_->IsUnionType()) {
        return;
    }

    for (auto *it : target_type_->AsUnionType()->ConstituentTypes()) {
        if (it->IsObjectType()) {
            potential_types_.push_back(it);
        }
    }
}
}  // namespace panda::es2panda::checker
