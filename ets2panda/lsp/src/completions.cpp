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

#include "completions.h"
#include "internal_api.h"
#include "compiler/lowering/util.h"
#include "ir/astNode.h"
#include "public/public.h"
#include <algorithm>
#include "generated/tokenType.h"

namespace ark::es2panda::lsp {

std::string ToLowerCase(const std::string &str)
{
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

std::vector<CompletionEntry> AllKeywordsCompletions()
{
    std::vector<CompletionEntry> keywords;
    for (int i = static_cast<int>(lexer::TokenType::FIRST_KEYW); i <= static_cast<int>(lexer::TokenType::KEYW_YIELD);
         i++) {
        keywords.emplace_back(lsp::CompletionEntry(TokenToString(static_cast<lexer::TokenType>(i)),
                                                   CompletionEntryKind::KEYWORD,
                                                   std::string(sort_text::GLOBALS_OR_KEYWORDS)));
    }
    return keywords;
}

std::vector<CompletionEntry> GetKeywordCompletions(const std::string &input)
{
    std::vector<CompletionEntry> allKeywords = AllKeywordsCompletions();
    std::vector<CompletionEntry> completions;

    for (const auto &entry : allKeywords) {
        if (entry.GetName().find(ToLowerCase(input)) == 0) {
            completions.push_back(entry);
        }
    }
    return completions;
}

Request KeywordCompletionData(const std::string &input)
{
    return {
        CompletionDataKind::KEYWORDS,
        GetKeywordCompletions(input),
    };
}

std::string GetDeclName(const ir::AstNode *decl)
{
    switch (decl->Type()) {
        case ir::AstNodeType::IDENTIFIER:
            return decl->AsIdentifier()->ToString();
        case ir::AstNodeType::METHOD_DEFINITION:
            return decl->AsMethodDefinition()->Key()->AsIdentifier()->ToString();
        case ir::AstNodeType::CLASS_PROPERTY:
            return decl->AsClassProperty()->Key()->AsIdentifier()->ToString();
        default:
            return "";
    }
}

bool IsGlobalVar(const ir::AstNode *node)
{
    return node->IsClassProperty() && node->Parent()->IsClassDefinition() &&
           node->Parent()->AsClassDefinition()->Ident()->AsIdentifier()->Name() == compiler::Signatures::ETS_GLOBAL;
}

bool IsVariableOfKind(const ir::Identifier *node, ir::VariableDeclaration::VariableDeclarationKind kind)
{
    /** A VariableDeclaration statement:
     *  - type: VariableDeclaration
     *      - type: VariableDeclarator
     *      - id
     *          - type: Identifier
     *  - Declaration kind
     */
    return node->Parent() != nullptr &&  // try to get the VariableDeclarator
           node->Parent()->IsVariableDeclarator() &&
           node->Parent()->Parent() != nullptr &&  // try to get the VariableDeclaration
           node->Parent()->Parent()->IsVariableDeclaration() &&
           node->Parent()->Parent()->AsVariableDeclaration()->Kind() == kind;
}

bool IsConstVar(const ir::AstNode *node)
{
    if (!node->IsIdentifier()) {
        return false;
    }
    return IsVariableOfKind(node->AsIdentifier(), ir::VariableDeclaration::VariableDeclarationKind::CONST);
}

bool IsLetVar(const ir::AstNode *node)
{
    if (!node->IsIdentifier()) {
        return false;
    }
    return IsVariableOfKind(node->AsIdentifier(), ir::VariableDeclaration::VariableDeclarationKind::LET);
}

bool IsValidDecl(const ir::AstNode *decl)
{
    return decl != nullptr && NodeHasTokens(decl) &&
           (decl->IsMethodDefinition() || IsLetVar(decl) || IsConstVar(decl) || IsGlobalVar(decl));
}

CompletionEntry InitEntry(const ir::AstNode *decl)
{
    auto name = GetDeclName(decl);
    auto sortText = sort_text::GLOBALS_OR_KEYWORDS;
    auto kind = CompletionEntryKind::KEYWORD;
    if (IsLetVar(decl)) {
        kind = CompletionEntryKind::VARIABLE;
    } else if (IsConstVar(decl)) {
        kind = CompletionEntryKind::CONSTANT;
    } else if (IsGlobalVar(decl)) {
        auto globalDefiniton = decl->Parent()->AsClassDefinition();
        auto initMethod = globalDefiniton->FindChild([](ir::AstNode *child) {
            return child->IsMethodDefinition() &&
                   child->AsMethodDefinition()->Key()->AsIdentifier()->Name() == compiler::Signatures::INIT_METHOD;
        });
        auto found = initMethod->FindChild([&name](ir::AstNode *child) {
            return child->IsAssignmentExpression() && child->AsAssignmentExpression()->Left()->IsIdentifier() &&
                   child->AsAssignmentExpression()->Left()->AsIdentifier()->ToString() == name;
        });
        if (found != nullptr) {
            // let variable in global definition need to be assigned in _$init$_ method
            kind = CompletionEntryKind::VARIABLE;
        } else {
            kind = CompletionEntryKind::CONSTANT;
        }
    } else if (decl->IsMethodDefinition()) {
        kind = CompletionEntryKind::FUNCTION;
    }
    return CompletionEntry(name, kind, std::string(sortText));
}

void GetIdentifiersInScope(const varbinder::Scope *scope, size_t position, ArenaVector<ir::AstNode *> &results)
{
    if (scope->Node() == nullptr) {
        return;
    }
    auto checkFunc = [scope, position](ir::AstNode *child) -> bool {
        return child->End().index < position && NodeHasTokens(child) && compiler::NearestScope(child) == scope &&
               child->IsIdentifier();
    };
    FindAllChild(scope->Node(), checkFunc, results);
}

auto GetDeclByScopePath(ArenaVector<varbinder::Scope *> &scopePath, size_t position, ArenaAllocator *allocator)
{
    auto hashFunc = [](const ir::AstNode *node) {
        static std::hash<std::string> strHasher;
        return strHasher(GetDeclName(node));
    };
    auto equalFunc = [](const ir::AstNode *lhs, const ir::AstNode *rhs) {
        return GetDeclName(lhs) == GetDeclName(rhs);
    };
    auto decls = ArenaUnorderedSet<ir::AstNode *, decltype(hashFunc), decltype(equalFunc)>(0, hashFunc, equalFunc,
                                                                                           allocator->Adapter());
    for (auto scope : scopePath) {
        auto nodes = ArenaVector<ir::AstNode *>(allocator->Adapter());
        GetIdentifiersInScope(scope, position, nodes);
        for (auto node : nodes) {
            auto decl = compiler::DeclarationFromIdentifier(node->AsIdentifier());
            if (IsValidDecl(decl)) {
                decls.insert(decl);
            }
        }
    }
    return decls;
}

// Support: global variables, local variables, functions, keywords
std::vector<CompletionEntry> GetGlobalCompletions(es2panda_Context *context, size_t position)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto allocator = ctx->allocator;
    auto precedingToken = FindPrecedingToken(position, ctx->parserProgram->Ast(), allocator);
    if (precedingToken == nullptr) {
        return {};
    }
    auto currentScope = compiler::NearestScope(precedingToken);
    auto scopePath = ArenaVector<varbinder::Scope *>(allocator->Adapter());
    while (currentScope != nullptr) {
        scopePath.push_back(currentScope);
        currentScope = currentScope->Parent();
    }
    auto prefix = GetCurrentTokenValueImpl(context, position);
    auto decls = GetDeclByScopePath(scopePath, position, allocator);
    std::vector<CompletionEntry> completions;
    auto keywordCompletions = GetKeywordCompletions(prefix);
    completions.insert(completions.end(), keywordCompletions.begin(), keywordCompletions.end());
    for (auto decl : decls) {
        auto entry = InitEntry(decl);
        if (entry.GetName().find(prefix) == 0) {
            completions.push_back(entry);
        }
    }
    return completions;
}

std::vector<CompletionEntry> GetCompletionsAtPositionImpl(es2panda_Context *context, size_t position)
{
    return GetGlobalCompletions(context, position);
}

}  // namespace ark::es2panda::lsp
