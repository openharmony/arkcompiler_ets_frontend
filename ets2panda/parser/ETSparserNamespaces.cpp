/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "ETSparser.h"
#include "ETSNolintParser.h"
#include <utility>

#include "macros.h"
#include "parser/parserFlags.h"
#include "parser/parserStatusContext.h"
#include "util/helpers.h"
#include "util/language.h"
#include "utils/arena_containers.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "lexer/lexer.h"
#include "lexer/ETSLexer.h"
#include "ir/astNode.h"

#include "ir/statements/namespaceDeclaration.h"

namespace ark::es2panda::parser {
class FunctionContext;

using namespace std::literals::string_literals;

ir::NamespaceDeclaration *ETSParser::ParseNamespaceDeclaration(ir::ModifierFlags flags)
{
    if ((GetContext().Status() & ParserStatus::IN_NAMESPACE) == 0) {
        LogSyntaxError("Namespace not enabled in here.");
    }

    const lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    auto modifiers = ir::ClassDefinitionModifiers::NONE;
    if (IsExternal()) {
        modifiers |= ir::ClassDefinitionModifiers::FROM_EXTERNAL;
    }

    ir::NamespaceDefinition *namespaceDefinition = ParseNamespaceDefinition(modifiers, flags);

    auto *namespaceDecl = AllocNode<ir::NamespaceDeclaration>(namespaceDefinition);

    namespaceDecl->SetRange({startLoc, Lexer()->GetToken().End()});
    return namespaceDecl;
}

ir::NamespaceDefinition *ETSParser::ParseNamespaceDefinition(ir::ClassDefinitionModifiers modifiers,
                                                             ir::ModifierFlags flags)
{
    Lexer()->NextToken();
    flags |= ir::ModifierFlags::DECLARE;
    ir::Identifier *identNode = ParseClassIdent(modifiers);

    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());
    ir::MethodDefinition *ctor = nullptr;
    lexer::SourceRange bodyRange;

    std::tie(ctor, properties, bodyRange) = ParseNamespaceBody(modifiers, flags);

    auto def =
        AllocNode<ir::NamespaceDefinition>(identNode, std::move(properties), ctor, flags, GetContext().GetLanguage());
    def->SetRange(bodyRange);
    return def;
}

ETSParser::NamespaceBody ETSParser::ParseNamespaceBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    auto savedCtx = SavedStatusContext<ParserStatus::IN_CLASS_BODY>(&GetContext());

    lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    ir::MethodDefinition *ctor = nullptr;
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    SavedClassPrivateContext classContext(this);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT &&
        Lexer()->Lookahead() == static_cast<char32_t>(ARRAY_FORMAT_NODE)) {
        properties = std::move(ParseAstNodesArrayFormatPlaceholder());
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            LogSyntaxError("Expected a '}'");
            UNREACHABLE();
        }
    } else {
        while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
                Lexer()->NextToken();
                continue;
            }

            ir::AstNode *property = ParseClassElement(properties, modifiers, flags);

            if (CheckClassElement(property, ctor, properties)) {
                continue;
            }

            properties.push_back(property);
        }
    }

    lexer::SourcePosition endLoc = Lexer()->GetToken().End();
    Lexer()->NextToken();

    return {ctor, std::move(properties), lexer::SourceRange {startLoc, endLoc}};
}

}  // namespace ark::es2panda::parser
