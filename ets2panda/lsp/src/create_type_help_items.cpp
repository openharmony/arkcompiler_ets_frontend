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

#include "create_type_help_items.h"
#include <iostream>
#include <string>
#include "utils/arena_containers.h"

namespace ark::es2panda::lsp {

using Type = checker::Type;

SignatureHelpItems CreateTypeHelpItems(ArenaAllocator *allocator, ir::AstNode *node, lexer::SourceRange location,
                                       lexer::SourcePosition applicableSpan)
{
    ArenaVector<Type *> result = ark::ArenaVector<Type *>(allocator->Adapter());
    SignatureHelpItems items(allocator);
    SignatureHelpItem item(allocator);
    if (node == nullptr) {
        return items;
    }
    GetLocalTypeParametersOfClassOrInterfaceOrTypeAlias(node, result);
    GetTypeHelpItem(&result, node, allocator, item);
    items.SetItems(item);
    items.SetApplicableSpan(applicableSpan.index, applicableSpan.line);
    items.SetSelectedItemIndex(location.start.index);
    items.SetArgumentIndex(location.start.index);
    items.SetArgumentCount(location.end.index - location.start.index);
    return items;
}

void GetLocalTypeParametersOfClassOrInterfaceOrTypeAlias(const ir::AstNode *node, ArenaVector<Type *> &result)
{
    if (node == nullptr) {
        return;
    }
    if (node->IsTSInterfaceDeclaration() || node->IsClassDefinition() || node->IsClassExpression() ||
        node->IsTSTypeAliasDeclaration()) {
        auto typeParams = GetEffectiveTypeParameterDeclarations(node, result);
        for (auto *param : typeParams) {
            result.push_back(param);
        }
    }
}

ArenaVector<Type *> GetEffectiveTypeParameterDeclarations(const ir::AstNode *node, ArenaVector<Type *> &result)
{
    if (node == nullptr) {
        return result;
    }
    const ir::TSTypeParameterDeclaration *typeParams = nullptr;
    if (node->IsClassDefinition()) {
        typeParams = node->AsClassDefinition()->TypeParams();
    } else if (node->IsTSInterfaceDeclaration()) {
        typeParams = node->AsTSInterfaceDeclaration()->TypeParams();
    } else if (node->IsTSTypeAliasDeclaration()) {
        typeParams = node->AsTSTypeAliasDeclaration()->TypeParams();
    } else if (node->IsETSStructDeclaration()) {
        typeParams = node->AsETSStructDeclaration()->Definition()->TypeParams();
    } else if (node->IsTSEnumDeclaration()) {
        auto members = node->AsTSEnumDeclaration()->Members();
        for (auto member : members) {
            result.push_back(reinterpret_cast<Type *>(member->AsTSEnumMember()->Type()));
        }
    }
    if (typeParams != nullptr) {
        for (auto *param : typeParams->Params()) {
            result.push_back(reinterpret_cast<Type *>(param));
        }
    }
    return result;
}

void GetTypeHelpItem(ArenaVector<Type *> *typeParameters, const ir::AstNode *node, ArenaAllocator *allocator,
                     SignatureHelpItem &result)
{
    const ir::TSTypeParameterDeclaration *typeParams = nullptr;
    if (node->IsClassDeclaration()) {
        result.SetPrefixDisplayParts(
            CreateClassName(std::string(node->AsClassDeclaration()->Definition()->Ident()->Name())));
        typeParams = node->AsClassDeclaration()->Definition()->TypeParams();
    } else if (node->IsTSInterfaceDeclaration()) {
        result.SetPrefixDisplayParts(CreateClassName(node->AsTSInterfaceDeclaration()->Id()->ToString()));
        typeParams = node->AsTSInterfaceDeclaration()->TypeParams();
    } else if (node->IsETSStructDeclaration()) {
        result.SetPrefixDisplayParts(
            CreateStructName(std::string(node->AsETSStructDeclaration()->Definition()->Ident()->Name())));
        typeParams = node->AsETSStructDeclaration()->Definition()->TypeParams();
    } else if (node->IsTSEnumDeclaration()) {
        result.SetPrefixDisplayParts(CreateEnumName(std::string(node->AsTSEnumDeclaration()->Key()->Name())));
        auto members = node->AsTSEnumDeclaration()->Members();
        for (auto member : members) {
            typeParameters->push_back(reinterpret_cast<Type *>(member->AsTSEnumMember()->Type()));
        }
    }
    result.SetPrefixDisplayParts(CreatePunctuation("<"));

    if (typeParams != nullptr) {
        for (auto *param : typeParams->Params()) {
            typeParameters->push_back(reinterpret_cast<Type *>(param));
        }
    }
    bool isFirst = true;
    for (auto *typeParam : *typeParameters) {
        if (!isFirst) {
            result.SetSeparatorDisplayParts(CreatePunctuation(", "));
        }

        SignatureHelpParameter signatureHelpParameter(allocator);
        auto *typeParamNode = reinterpret_cast<ir::TSTypeParameter *>(typeParam);
        signatureHelpParameter.SetName(typeParamNode->Name()->ToString());
        if (auto *constraint = typeParamNode->Constraint()) {
            auto name = signatureHelpParameter.GetName();
            std::string constraintStr = constraint->ToString();
            signatureHelpParameter.SetDisplayParts(CreateTypeName(name));
            signatureHelpParameter.SetDisplayParts(CreateKeyword(" extends "));
            signatureHelpParameter.SetDisplayParts(CreateTypeName(constraintStr));
        } else {
            std::string name = signatureHelpParameter.GetName();
            signatureHelpParameter.SetDisplayParts(CreateTypeName(name));
        }
        result.SetParameters(signatureHelpParameter);
        isFirst = false;
    }
    result.SetSuffixDisplayParts(CreatePunctuation(">"));
}

}  // namespace ark::es2panda::lsp