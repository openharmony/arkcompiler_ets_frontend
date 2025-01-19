/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "ir/base/decorator.h"
#include "ir/base/catchClause.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/dummyNode.h"
#include "ir/module/importDeclaration.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/importSpecifier.h"
#include "ir/module/exportSpecifier.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/ets/etsPrimitiveType.h"
#include "ir/ets/etsPackageDeclaration.h"
#include "ir/ets/etsReExportDeclaration.h"
#include "ir/ets/etsWildcardType.h"
#include "ir/ets/etsTuple.h"
#include "ir/ets/etsFunctionType.h"
#include "ir/ets/etsModule.h"
#include "ir/ets/etsStringLiteralType.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsNullishTypes.h"
#include "ir/ets/etsUnionType.h"
#include "ir/ets/etsImportSource.h"
#include "ir/ets/etsImportDeclaration.h"
#include "ir/ets/etsStructDeclaration.h"
#include "ir/module/importNamespaceSpecifier.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsInterfaceBody.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypeParameter.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsTypeParameterDeclaration.h"
#include "ir/ts/tsThisType.h"
#include "generated/signatures.h"
#include "util/errorRecovery.h"

namespace ark::es2panda::parser {
class FunctionContext;

using namespace std::literals::string_literals;

ir::TypeNode *ETSParser::ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        return nullptr;
    }
    if ((status & ParserStatus::CONSTRUCTOR_FUNCTION) != 0U) {
        LogSyntaxError("Type annotation isn't allowed for constructor.");
    }
    Lexer()->NextToken();  // eat ':'
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR |
                                           TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE |
                                           TypeAnnotationParsingOptions::RETURN_TYPE;
    return ParseTypeAnnotation(&options);
}

ir::TypeNode *ETSParser::ParsePrimitiveType(TypeAnnotationParsingOptions *options, ir::PrimitiveType type)
{
    if (((*options) & TypeAnnotationParsingOptions::DISALLOW_PRIMARY_TYPE) != 0) {
        LogSyntaxError("Primitive type is not allowed here.");
    }

    auto *const typeAnnotation = AllocNode<ir::ETSPrimitiveType>(type);
    typeAnnotation->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();
    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseUnionType(ir::TypeNode *const firstType)
{
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());
    types.push_back(firstType->AsTypeNode());

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        Lexer()->NextToken();  // eat '|'

        auto options = TypeAnnotationParsingOptions::REPORT_ERROR | TypeAnnotationParsingOptions::DISALLOW_UNION;
        auto typeAnnotation = ParseTypeAnnotation(&options);
        if (!typeAnnotation->IsErrorTypeNode()) {
            types.push_back(typeAnnotation);
        }
    }

    auto const endLoc = types.back()->End();
    auto *const unionType = AllocNode<ir::ETSUnionType>(std::move(types));
    unionType->SetRange({firstType->Start(), endLoc});
    return unionType;
}

ir::TypeNode *ETSParser::GetTypeAnnotationOfPrimitiveType([[maybe_unused]] lexer::TokenType tokenType,
                                                          TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *typeAnnotation = nullptr;
    switch (tokenType) {
        case lexer::TokenType::KEYW_BOOLEAN:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BOOLEAN);
            break;
        case lexer::TokenType::KEYW_DOUBLE:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::DOUBLE);
            break;
        case lexer::TokenType::KEYW_BYTE:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::BYTE);
            break;
        case lexer::TokenType::KEYW_FLOAT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::FLOAT);
            break;
        case lexer::TokenType::KEYW_SHORT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::SHORT);
            break;
        case lexer::TokenType::KEYW_INT:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::INT);
            break;
        case lexer::TokenType::KEYW_CHAR:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::CHAR);
            break;
        case lexer::TokenType::KEYW_LONG:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::LONG);
            break;
        case lexer::TokenType::KEYW_VOID:
            typeAnnotation = ParsePrimitiveType(options, ir::PrimitiveType::VOID);
            break;
        default:
            typeAnnotation = ParseTypeReference(options);
            break;
    }
    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseWildcardType(TypeAnnotationParsingOptions *options)
{
    const auto varianceStartLoc = Lexer()->GetToken().Start();
    const auto varianceEndLoc = Lexer()->GetToken().End();
    const auto varianceModifier = ParseTypeVarianceModifier(options);

    bool isUnboundOut = varianceModifier == ir::ModifierFlags::OUT &&
                        (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_GREATER_THAN ||
                         Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA);
    ir::ETSTypeReference *typeReference = nullptr;
    if (!isUnboundOut) {
        auto reference = ParseTypeReference(options);
        typeReference = reference->AsETSTypeReference();
    }

    auto *wildcardType = AllocNode<ir::ETSWildcardType>(typeReference, varianceModifier);
    wildcardType->SetRange({varianceStartLoc, typeReference == nullptr ? varianceEndLoc : typeReference->End()});

    return wildcardType;
}

ir::TypeNode *ETSParser::ParseFunctionType()
{
    auto startLoc = Lexer()->GetToken().Start();

    auto params = ParseFunctionParams();

    ExpectToken(lexer::TokenType::PUNCTUATOR_ARROW);
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    auto *const returnTypeAnnotation = ParseTypeAnnotation(&options);
    if (returnTypeAnnotation == nullptr) {
        return nullptr;
    }

    ir::ScriptFunctionFlags throwMarker = ParseFunctionThrowMarker(false);

    auto *funcType = AllocNode<ir::ETSFunctionType>(
        ir::FunctionSignature(nullptr, std::move(params), returnTypeAnnotation), throwMarker);
    funcType->SetRange({startLoc, returnTypeAnnotation->End()});

    return funcType;
}

bool ETSParser::ParseTriplePeriod(bool spreadTypePresent)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        if (spreadTypePresent) {
            LogSyntaxError("Only one spread type declaration allowed, at the last index");
        }

        spreadTypePresent = true;
        Lexer()->NextToken();  // eat '...'
    } else if (spreadTypePresent) {
        // This can't be implemented to any index, with type consistency. If a spread type is in the middle of
        // the tuple, then bounds check can't be made for element access, so the type of elements after the
        // spread can't be determined in compile time.
        LogSyntaxError("Spread type must be at the last index in the tuple type");
    }

    return spreadTypePresent;
}

ir::TypeNode *ETSParser::ParseETSTupleType(TypeAnnotationParsingOptions *const options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

    const auto startLoc = Lexer()->GetToken().Start();
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);

    ArenaVector<ir::TypeNode *> tupleTypeList(Allocator()->Adapter());
    auto *const tupleType = AllocNode<ir::ETSTuple>(Allocator());

    bool spreadTypePresent = false;

    lexer::SourcePosition endLoc;
    auto parseElem = [this, options, &tupleTypeList, &tupleType, &spreadTypePresent]() {
        // Parse named parameter if name presents
        if ((Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) &&
            (Lexer()->Lookahead() == lexer::LEX_CHAR_COLON)) {
            ExpectIdentifier();
            Lexer()->NextToken();  // eat ':'
        }

        spreadTypePresent = ParseTriplePeriod(spreadTypePresent);

        auto *const currentTypeAnnotation = ParseTypeAnnotation(options);
        if (currentTypeAnnotation == nullptr) {  // Error processing.
            Lexer()->NextToken();
            return false;
        }
        currentTypeAnnotation->SetParent(tupleType);
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
            // NOTE(mmartin): implement optional types for tuples
            LogSyntaxError("Optional types in tuples are not yet implemented.");
            Lexer()->NextToken();  // eat '?'
        }

        if (spreadTypePresent && !currentTypeAnnotation->IsTSArrayType()) {
            LogSyntaxError("Spread type must be an array type");
        }

        if (spreadTypePresent) {
            tupleType->SetSpreadType(currentTypeAnnotation);
        } else {
            tupleTypeList.push_back(currentTypeAnnotation);
        }
        return true;
    };
    ParseList(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET, lexer::NextTokenFlags::NONE, parseElem, &endLoc, true);

    tupleType->SetTypeAnnotationsList(std::move(tupleTypeList));
    tupleType->SetRange({startLoc, endLoc});

    return tupleType;
}

// Helper function for  ETSParser::GetTypeAnnotationFromToken(...) method
ir::TypeNode *ETSParser::ParsePotentialFunctionalType(TypeAnnotationParsingOptions *options)
{
    auto savePos = Lexer()->Save();
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    if (((*options) & TypeAnnotationParsingOptions::IGNORE_FUNCTION_TYPE) == 0 &&
        (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS ||
         Lexer()->Lookahead() == lexer::LEX_CHAR_COLON || Lexer()->Lookahead() == lexer::LEX_CHAR_QUESTION)) {
        GetContext().Status() |= ParserStatus::ALLOW_DEFAULT_VALUE;
        // '(' is consumed in `ParseFunctionType`
        Lexer()->Rewind(savePos);
        auto typeAnnotation = ParseFunctionType();
        GetContext().Status() ^= ParserStatus::ALLOW_DEFAULT_VALUE;
        return typeAnnotation;
    }
    Lexer()->Rewind(savePos);
    return nullptr;
}

// Just to reduce the size of ParseTypeAnnotation(...) method
std::pair<ir::TypeNode *, bool> ETSParser::GetTypeAnnotationFromToken(TypeAnnotationParsingOptions *options)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            auto typeAnnotation = ParseLiteralIdent(options);
            if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_CLASS_LITERAL) != 0 &&
                (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_CLASS || IsStructKeyword())) {
                return std::make_pair(typeAnnotation, false);
            }
            return std::make_pair(typeAnnotation, true);
        }
        case lexer::TokenType::LITERAL_NULL: {
            auto typeAnnotation = AllocNode<ir::ETSNullType>();
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            return std::make_pair(typeAnnotation, true);
        }
        case lexer::TokenType::KEYW_UNDEFINED: {
            auto typeAnnotation = AllocNode<ir::ETSUndefinedType>();
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            return std::make_pair(typeAnnotation, true);
        }
        case lexer::TokenType::LITERAL_STRING: {
            auto typeAnnotation = AllocNode<ir::ETSStringLiteralType>(Lexer()->GetToken().String());
            typeAnnotation->SetRange(Lexer()->GetToken().Loc());
            Lexer()->NextToken();
            return std::make_pair(typeAnnotation, true);
        }
        case lexer::TokenType::PUNCTUATOR_BACK_TICK: {
            return std::make_pair(ParseMultilineString(), true);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            return GetTypeAnnotationFromParentheses(options);
        }
        case lexer::TokenType::PUNCTUATOR_FORMAT:
            return std::make_pair(ParseTypeFormatPlaceholder(), true);
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET:
            return std::make_pair(ParseETSTupleType(options), true);
        case lexer::TokenType::KEYW_THIS:
            return std::make_pair(ParseThisType(options), true);
        default: {
            return {nullptr, true};
        }
    }
}

std::pair<ir::TypeNode *, bool> ETSParser::GetTypeAnnotationFromParentheses(TypeAnnotationParsingOptions *options)
{
    auto startLoc = Lexer()->GetToken().Start();

    ir::TypeNode *typeAnnotation = ParsePotentialFunctionalType(options);
    if (typeAnnotation != nullptr) {
        typeAnnotation->SetStart(startLoc);
        return std::make_pair(typeAnnotation, true);
    }

    lexer::LexerPosition savedPos = Lexer()->Save();
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);

    typeAnnotation = ParseTypeAnnotation(options);
    if (typeAnnotation == nullptr) {
        return std::make_pair(typeAnnotation, true);
    }

    typeAnnotation->SetStart(startLoc);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        typeAnnotation = ParseUnionType(typeAnnotation);
    }

    ParseRightParenthesis(options, typeAnnotation, savedPos);

    return std::make_pair(typeAnnotation, true);
}

ir::TypeNode *ETSParser::ParseThisType(TypeAnnotationParsingOptions *options)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    // A syntax error should be thrown if
    // - the usage of 'this' as a type is not allowed in the current context, or
    // - 'this' is not used as a return type, or
    // - the current context is an arrow function (might be inside a method of a class where 'this' is allowed).
    bool reportErr = (*options & TypeAnnotationParsingOptions::REPORT_ERROR) != 0;
    bool allowThisType = (GetContext().Status() & ParserStatus::ALLOW_THIS_TYPE) != 0;
    bool parseReturnType = (*options & TypeAnnotationParsingOptions::RETURN_TYPE) != 0;
    bool isArrowFunc = (GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0;
    bool notSimpleReturnThisType =
        (allowThisType && parseReturnType && (Lexer()->Lookahead() != lexer::LEX_CHAR_LEFT_BRACE));
    if (reportErr && (!allowThisType || !parseReturnType || isArrowFunc || notSimpleReturnThisType)) {
        LogSyntaxError(
            "A 'this' type is available only as return type in a non-static method of a class or struct and extension "
            "functions.");
    }

    auto *const thisType = AllocNode<ir::TSThisType>();
    thisType->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();  // eat 'this'

    return thisType;
}

ir::TypeNode *ETSParser::ParseTsArrayType(ir::TypeNode *typeNode, TypeAnnotationParsingOptions *options)
{
    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        if (((*options) & TypeAnnotationParsingOptions::POTENTIAL_NEW_ARRAY) != 0) {
            return typeNode;
        }

        lexer::SourcePosition startPos = Lexer()->GetToken().Start();

        Lexer()->NextToken();  // eat '['

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            if ((*options & TypeAnnotationParsingOptions::REPORT_ERROR) != 0) {
                LogExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
            }
            return nullptr;
        }

        typeNode = AllocNode<ir::TSArrayType>(typeNode);
        typeNode->SetRange({startPos, Lexer()->GetToken().End()});

        Lexer()->NextToken();  // eat ']'
    }

    return typeNode;
}

ir::TypeNode *ETSParser::ParseTypeAnnotationNoPreferParam(TypeAnnotationParsingOptions *options)
{
    bool const reportError = ((*options) & TypeAnnotationParsingOptions::REPORT_ERROR) != 0;

    auto [typeAnnotation, needFurtherProcessing] = GetTypeAnnotationFromToken(options);

    if (typeAnnotation == nullptr) {
        if (reportError) {
            LogSyntaxError("Invalid Type");
            auto typeNode = AllocErrorType();
            typeNode->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});
            return typeNode;
        }
        return nullptr;
    }

    if (!needFurtherProcessing) {
        return typeAnnotation;
    }

    typeAnnotation = ParseTsArrayType(typeAnnotation, options);

    if (((*options) & TypeAnnotationParsingOptions::DISALLOW_UNION) == 0 &&
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
        return ParseUnionType(typeAnnotation);
    }

    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseTypeAnnotation(TypeAnnotationParsingOptions *options)
{
    ArenaVector<ir::AnnotationUsage *> annotations {Allocator()->Adapter()};
    if (Lexer()->TryEatTokenType(lexer::TokenType::PUNCTUATOR_AT)) {
        annotations = ParseAnnotations(false);
    }
    ir::TypeNode *typeAnnotation = nullptr;
    auto startPos = Lexer()->GetToken().Start();
    // if there is prefix readonly parameter type, change the return result to ETSTypeReference, like Readonly<>
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY) {
        Lexer()->NextToken();  // eat 'readonly'
        typeAnnotation = ParseTypeAnnotationNoPreferParam(options);
        if (!typeAnnotation->IsTSArrayType() && !typeAnnotation->IsETSTuple()) {
            LogSyntaxError("'readonly' type modifier is only permitted on array and tuple types.");
        }
        typeAnnotation->SetStart(startPos);
        typeAnnotation->AddModifier(ir::ModifierFlags::READONLY_PARAMETER);
    } else {
        typeAnnotation = ParseTypeAnnotationNoPreferParam(options);
    }
    ApplyAnnotationsToNode(typeAnnotation, std::move(annotations), startPos);
    return typeAnnotation;
}

ir::TypeNode *ETSParser::ParseMultilineString()
{
    const auto startPos = Lexer()->GetToken().Start();
    const auto multilineStr = Lexer()->ScanMultilineString();
    Lexer()->ScanTemplateStringEnd();

    auto typeAnnotation = AllocNode<ir::ETSStringLiteralType>(multilineStr);
    typeAnnotation->SetRange({startPos, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    return typeAnnotation;
}

}  // namespace ark::es2panda::parser
