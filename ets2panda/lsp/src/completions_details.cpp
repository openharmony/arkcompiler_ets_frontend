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

#include "completions_details.h"
#include "internal_api.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "public/public.h"
#include <algorithm>
#include <cstddef>
#include <string>
#include "generated/tokenType.h"
#include <cstdio>
#include "public/es2panda_lib.h"
#include "lexer/token/letters.h"
#include "api.h"
#include "quick_info.h"
#include "suggestion_diagnostics.h"

namespace ark::es2panda::lsp::details {

void GetDisplayPartAndKind(ir::AstNode *node, std::vector<SymbolDisplayPart> &displayParts, std::string &kind,
                           std::string &kindModifiers)
{
    if (IsClass(node)) {
        displayParts = ark::es2panda::lsp::CreateDisplayForClass(node);
        kind = "class";
    } else if (node->Type() == ir::AstNodeType::ETS_PARAMETER_EXPRESSION) {
        displayParts = ark::es2panda::lsp::CreateDisplayForETSParameterExpression(node);
        kind = "parameter";
    } else if (node->Type() == ir::AstNodeType::CLASS_PROPERTY) {
        // After enum refactoring, enum declaration is transformed to a class declaration
        if (compiler::ClassDefinitionIsEnumTransformed(node->Parent())) {
            auto enumDecl = node->Parent()->AsClassDefinition()->OrigEnumDecl()->AsTSEnumDeclaration();
            auto enumMember = GetEnumMemberByName(enumDecl, node->AsClassProperty()->Key()->AsIdentifier()->Name());
            displayParts = ark::es2panda::lsp::CreateDisplayForEnumMember(enumMember);
            kind = "enum member";
        } else {
            displayParts = ark::es2panda::lsp::CreateDisplayForClassProperty(node, kindModifiers);
            kind = "property";
        }
    } else if (node->Type() == ir::AstNodeType::TS_INTERFACE_DECLARATION) {
        displayParts = ark::es2panda::lsp::CreateDisplayForInterface(node);
        kind = "interface";
    } else if (node->Type() == ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION) {
        displayParts = ark::es2panda::lsp::CreateDisplayForTypeAlias(node);
        kind = "type alias";
    } else if (node->Type() == ir::AstNodeType::TS_ENUM_DECLARATION) {
        displayParts = ark::es2panda::lsp::CreateDisplayForEnum(node);
        kind = "enum";
    } else if (node->Type() == ir::AstNodeType::IMPORT_DECLARATION) {
        displayParts = CreateDisplayForImportDeclaration(node);
        kind = "import";
    } else if (node->Type() == ir::AstNodeType::TS_TYPE_PARAMETER) {
        displayParts = ark::es2panda::lsp::CreateDisplayForTypeParameter(node);
        kind = "type parameter";
    } else if (node->Type() == ir::AstNodeType::METHOD_DEFINITION) {
        displayParts = ark::es2panda::lsp::CreateDisplayForMethodDefinition(node, kindModifiers);
        kind = "function";
        if (node->Parent() != nullptr && node->Parent()->Type() == ir::AstNodeType::TS_INTERFACE_BODY) {
            kind = "property";
        }
    }
}

CompletionEntryDetails GetCompletionEntryDetails(ir::AstNode *node, const std::string &entryName,
                                                 const std::string &fileName)
{
    if (node == nullptr) {
        return CompletionEntryDetails();
    }
    auto kindModifiers = GetKindModifiers(node);
    std::vector<SymbolDisplayPart> displayParts;

    std::string kind;
    std::vector<SymbolDisplayPart> document;
    std::vector<SymbolDisplayPart> source;
    std::vector<SymbolDisplayPart> sourceDisplay;

    GetDisplayPartAndKind(node, displayParts, kind, kindModifiers);

    return CompletionEntryDetails(entryName, kind, kindModifiers, displayParts, document, source, sourceDisplay,
                                  fileName);
}

CompletionEntryDetails GetCompletionEntryDetailsImpl(es2panda_Context *context, size_t position, const char *fileName,
                                                     const char *entryName)
{
    if (context == nullptr) {
        return CompletionEntryDetails();
    }
    auto touchingToken = GetTouchingToken(context, position, false);
    if (touchingToken == nullptr || touchingToken->IsProgram()) {
        return CompletionEntryDetails();
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = ctx->parserProgram->Ast();
    auto leIdentifier =
        ast->FindChild([entryName](ir::AstNode *node) { return HasPropertyAccessExpressionWithName(node, entryName); });
    if (leIdentifier == nullptr || !leIdentifier->IsIdentifier()) {
        return CompletionEntryDetails();
    }
    auto targetNode = compiler::DeclarationFromIdentifier(leIdentifier->AsIdentifier());
    if (targetNode == nullptr) {
        return CompletionEntryDetails();
    }
    return GetCompletionEntryDetails(targetNode, entryName, fileName);
}

}  // namespace ark::es2panda::lsp::details