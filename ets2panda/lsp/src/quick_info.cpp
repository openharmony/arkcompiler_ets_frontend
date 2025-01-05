/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "quick_info.h"
#include "internal_api.h"
#include "ir/astNode.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

bool IsIncludedToken(const ir::AstNode *node)
{
    auto type = node->Type();
    static const std::unordered_set<ir::AstNodeType> INCLUDED_TOKEN_TYPES = {
        ir::AstNodeType::IDENTIFIER,
        ir::AstNodeType::METHOD_DEFINITION,
        ir::AstNodeType::ETS_NEW_CLASS_INSTANCE_EXPRESSION,
        ir::AstNodeType::CLASS_DECLARATION,
        ir::AstNodeType::ETS_TUPLE,
        ir::AstNodeType::STRING_LITERAL,
        ir::AstNodeType::NUMBER_LITERAL,
        ir::AstNodeType::TEMPLATE_LITERAL,
        ir::AstNodeType::TEMPLATE_ELEMENT,
    };
    return INCLUDED_TOKEN_TYPES.find(type) != INCLUDED_TOKEN_TYPES.end();
}

ir::AstNode *GetTokenForQuickInfo(es2panda_Context *context, size_t position)
{
    auto node = GetTouchingToken(context, position, false);
    if (node == nullptr) {
        return nullptr;
    }
    if (!IsIncludedToken(node)) {
        return nullptr;
    }
    return node;
}

bool IsObjectLiteralElement(ir::AstNode *node)
{
    auto type = node->Type();
    static const std::unordered_set<ir::AstNodeType> INCLUDED_OBJECT_LITERAL_ELEMENT_TYPES = {
        ir::AstNodeType::PROPERTY,
    };
    return INCLUDED_OBJECT_LITERAL_ELEMENT_TYPES.find(type) != INCLUDED_OBJECT_LITERAL_ELEMENT_TYPES.end();
}

ir::AstNode *GetContainingObjectLiteralNode(ir::AstNode *node)
{
    auto type = node->Type();
    if (type == ir::AstNodeType::STRING_LITERAL || type == ir::AstNodeType::NUMBER_LITERAL ||
        type == ir::AstNodeType::TEMPLATE_LITERAL || type == ir::AstNodeType::IDENTIFIER) {
        if (IsObjectLiteralElement(node->Parent())) {
            return node->Parent();
        }
    } else if (type == ir::AstNodeType::TEMPLATE_ELEMENT) {
        if (IsObjectLiteralElement(node->Parent()->Parent())) {
            return node->Parent()->Parent();
        }
    }
    return nullptr;
}

ir::AstNode *GetContextualTypeNode(ir::AstNode *node)
{
    if (node->Type() == ir::AstNodeType::OBJECT_EXPRESSION) {
        if (node->Parent()->Type() == ir::AstNodeType::CLASS_PROPERTY) {
            auto propertyObj = node->Parent()->AsClassElement();
            auto type = propertyObj->TsType();
            auto contextualTypeNode = type->Variable()->Declaration()->Node();
            return contextualTypeNode;
        }
        if (node->Parent()->Type() == ir::AstNodeType::ASSIGNMENT_EXPRESSION) {
            auto propertyObj = node->Parent()->AsAssignmentExpression();
            auto type = propertyObj->TsType();
            auto contextualTypeNode = type->Variable()->Declaration()->Node();
            return contextualTypeNode;
        }
    }
    return nullptr;
}

ir::AstNode *GetPropertyNodeFromContextualType(ir::AstNode *node, ir::AstNode *contextualTypeNode)
{
    auto type = contextualTypeNode->Type();
    auto property = node->AsProperty()->Key();
    ark::es2panda::util::StringView propertyName;
    if (property->Type() == ir::AstNodeType::STRING_LITERAL) {
        propertyName = property->AsStringLiteral()->Str();
    } else if (property->Type() == ir::AstNodeType::IDENTIFIER) {
        propertyName = property->AsIdentifier()->Name();
    }
    if (type == ir::AstNodeType::CLASS_DEFINITION) {
        auto def = contextualTypeNode->AsClassDefinition();
        auto bodies = def->Body();
        for (auto it : bodies) {
            auto methodDef = it->AsMethodDefinition();
            auto name = methodDef->Key()->AsIdentifier()->Name();
            if (name == propertyName) {
                return it;
            }
        }
    }
    if (type == ir::AstNodeType::TS_INTERFACE_DECLARATION) {
        auto def = contextualTypeNode->AsTSInterfaceDeclaration();
        auto bodies = def->Body()->Body();
        for (auto it : bodies) {
            auto methodDef = it->AsMethodDefinition();
            auto name = methodDef->Key()->AsIdentifier()->Name();
            if (name == propertyName) {
                return it;
            }
        }
    }
    return node;
}

}  // namespace ark::es2panda::lsp