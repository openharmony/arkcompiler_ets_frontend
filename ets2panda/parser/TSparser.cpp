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

#include "TSparser.h"

#include "util/helpers.h"
#include "binder/privateBinding.h"
#include "binder/scope.h"
#include "binder/tsBinding.h"
#include "lexer/TSLexer.h"
#include "ir/base/spreadElement.h"
#include "ir/base/decorator.h"
#include "ir/base/classElement.h"
#include "ir/base/classDefinition.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/module/importDefaultSpecifier.h"
#include "ir/module/exportDefaultDeclaration.h"
#include "ir/module/exportAllDeclaration.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/importDeclaration.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/templateLiteral.h"
#include "ir/expressions/taggedTemplateExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/arrowFunctionExpression.h"
#include "ir/expressions/yieldExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/booleanLiteral.h"
#include "ir/expressions/literals/nullLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/statements/emptyStatement.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/ifStatement.h"
#include "ir/statements/doWhileStatement.h"
#include "ir/statements/whileStatement.h"
#include "ir/statements/tryStatement.h"
#include "ir/statements/breakStatement.h"
#include "ir/statements/continueStatement.h"
#include "ir/statements/throwStatement.h"
#include "ir/statements/switchStatement.h"
#include "ir/statements/returnStatement.h"
#include "ir/statements/debuggerStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/labelledStatement.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/ts/tsLiteralType.h"
#include "ir/ts/tsMappedType.h"
#include "ir/ts/tsImportType.h"
#include "ir/ts/tsThisType.h"
#include "ir/ts/tsConditionalType.h"
#include "ir/ts/tsTypeOperator.h"
#include "ir/ts/tsInferType.h"
#include "ir/ts/tsTupleType.h"
#include "ir/ts/tsNamedTupleMember.h"
#include "ir/ts/tsQualifiedName.h"
#include "ir/ts/tsIndexedAccessType.h"
#include "ir/ts/tsTypeQuery.h"
#include "ir/ts/tsTypeReference.h"
#include "ir/ts/tsTypePredicate.h"
#include "ir/ts/tsTypeLiteral.h"
#include "ir/ts/tsArrayType.h"
#include "ir/ts/tsUnionType.h"
#include "ir/ts/tsIntersectionType.h"
#include "ir/ts/tsAnyKeyword.h"
#include "ir/ts/tsUndefinedKeyword.h"
#include "ir/ts/tsVoidKeyword.h"
#include "ir/ts/tsNumberKeyword.h"
#include "ir/ts/tsStringKeyword.h"
#include "ir/ts/tsBooleanKeyword.h"
#include "ir/ts/tsBigintKeyword.h"
#include "ir/ts/tsUnknownKeyword.h"
#include "ir/ts/tsNullKeyword.h"
#include "ir/ts/tsNeverKeyword.h"
#include "ir/ts/tsObjectKeyword.h"
#include "ir/ts/tsFunctionType.h"
#include "ir/ts/tsConstructorType.h"
#include "ir/ts/tsParenthesizedType.h"
#include "ir/ts/tsTypeAssertion.h"
#include "ir/ts/tsAsExpression.h"
#include "ir/ts/tsNonNullExpression.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "ir/ts/tsTypeAliasDeclaration.h"
#include "ir/ts/tsModuleDeclaration.h"
#include "ir/ts/tsTypeParameterInstantiation.h"
#include "ir/ts/tsInterfaceHeritage.h"
#include "ir/base/tsSignatureDeclaration.h"
#include "ir/base/tsIndexSignature.h"
#include "ir/base/tsMethodSignature.h"
#include "ir/base/tsPropertySignature.h"
#include "ir/ts/tsParameterProperty.h"
#include "ir/ts/tsClassImplements.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsExternalModuleReference.h"

namespace panda::es2panda::parser {
std::unique_ptr<lexer::Lexer> TSParser::InitLexer(const SourceFile &source_file)
{
    GetProgram()->SetSource(source_file);
    auto lexer = std::make_unique<lexer::TSLexer>(&GetContext());
    SetLexer(lexer.get());
    return lexer;
}

ir::Decorator *TSParser::ParseDecorator()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT);

    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat '@'

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    ir::Expression *expr = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    expr->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Identifier expected");
        }

        auto *ident_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        ident_node->SetRange(Lexer()->GetToken().Loc());

        expr =
            AllocNode<ir::MemberExpression>(expr, ident_node, ir::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        expr = ParseCallExpression(expr);
    }

    auto *result = AllocNode<ir::Decorator>(expr);
    result->SetRange({start, expr->End()});

    return result;
}

void TSParser::AddDecorators(ir::AstNode *node, ArenaVector<ir::Decorator *> &decorators)
{
    if (decorators.empty()) {
        return;
    }

    if (!node->CanHaveDecorator(true)) {
        ThrowSyntaxError("Decorators are not valid here", decorators.front()->Start());
    }

    node->AddDecorators(std::move(decorators));
}

ir::TSTypeAliasDeclaration *TSParser::ParseTypeAliasDeclaration()
{
    ASSERT(Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_TYPE);
    lexer::SourcePosition type_start = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat type keyword

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Identifier expected");
    }

    if (Lexer()->GetToken().IsReservedTypeName()) {
        std::string err_msg("Type alias name cannot be '");
        err_msg.append(TokenToString(Lexer()->GetToken().KeywordType()));
        err_msg.append("'");
        ThrowSyntaxError(err_msg.c_str());
    }

    const util::StringView &ident = Lexer()->GetToken().Ident();
    binder::TSBinding ts_binding(Allocator(), ident);
    auto *decl = Binder()->AddTsDecl<binder::TypeAliasDecl>(Lexer()->GetToken().Start(), ts_binding.View());

    auto *id = AllocNode<ir::Identifier>(ident, Allocator());
    id->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_decl = ParseTypeParameterDeclaration(&options);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("'=' expected");
    }

    Lexer()->NextToken();  // eat '='

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    auto *type_alias_decl =
        AllocNode<ir::TSTypeAliasDeclaration>(Allocator(), id, type_param_decl, type_annotation, InAmbientContext());
    type_alias_decl->SetRange({type_start, Lexer()->GetToken().End()});
    decl->BindNode(type_alias_decl);

    return type_alias_decl;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Statement *TSParser::ParseStatement(StatementParsingFlags flags)
{
    return ParseDeclareAndDecorators(flags);
}

ir::Expression *TSParser::ParsePotentialAsExpression(ir::Expression *expr)
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_AS) {
        return nullptr;
    }

    Lexer()->NextToken();  // eat 'as'
    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::ALLOW_CONST;
    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    bool is_const = false;
    if (type_annotation->IsTSTypeReference() && type_annotation->AsTSTypeReference()->TypeName()->IsIdentifier()) {
        const util::StringView &ref_name = type_annotation->AsTSTypeReference()->TypeName()->AsIdentifier()->Name();
        if (ref_name.Is("const")) {
            is_const = true;
        }
    }

    lexer::SourcePosition start_loc = expr->Start();
    auto *as_expr = AllocNode<ir::TSAsExpression>(expr, type_annotation, is_const);
    as_expr->SetRange({start_loc, Lexer()->GetToken().End()});

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_AS) {
        return ParsePotentialAsExpression(as_expr);
    }

    return as_expr;
}

void TSParser::ParseOptionalFunctionParameter(ir::AnnotatedExpression *return_node, bool is_rest)
{
    bool is_optional = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        if (is_rest) {
            ThrowSyntaxError("A rest parameter cannot be optional");
        }

        switch (return_node->Type()) {
            case ir::AstNodeType::IDENTIFIER: {
                return_node->AsIdentifier()->SetOptional(true);
                break;
            }
            case ir::AstNodeType::OBJECT_PATTERN:
            case ir::AstNodeType::ARRAY_PATTERN: {
                if (!InAmbientContext() && ((GetContext().Status() & ParserStatus::FUNCTION) != 0)) {
                    ThrowSyntaxError("A binding pattern parameter cannot be optional in an implementation signature.");
                }

                if (return_node->IsObjectPattern()) {
                    return_node->AsObjectPattern()->SetOptional(true);
                    break;
                }

                return_node->AsArrayPattern()->SetOptional(true);
                break;
            }
            case ir::AstNodeType::REST_ELEMENT: {
                return_node->AsRestElement()->SetOptional(true);
                break;
            }
            default: {
                UNREACHABLE();
            }
        }

        is_optional = true;
        Lexer()->NextToken();  // eat '?'
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        return_node->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return;
    }

    if (is_rest) {
        ThrowSyntaxError("A rest parameter cannot have an initializer");
    }

    if (return_node->IsIdentifier() && is_optional) {
        ThrowSyntaxError("Parameter cannot have question mark and initializer");
    }
}

// NOLINTNEXTLINE(google-default-arguments)
ir::Expression *TSParser::ParsePatternElement(ExpressionParseFlags flags, bool allow_default)
{
    ir::AnnotatedExpression *return_node = nullptr;
    bool is_optional = false;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            return_node = ParseArrayExpression(ExpressionParseFlags::MUST_BE_PATTERN);
            is_optional = return_node->AsArrayPattern()->IsOptional();
            break;
        }
        case lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD: {
            if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                ThrowSyntaxError("Unexpected token");
            }

            return_node = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return_node =
                ParseObjectExpression(ExpressionParseFlags::MUST_BE_PATTERN | ExpressionParseFlags::OBJECT_PATTERN);
            is_optional = return_node->AsObjectPattern()->IsOptional();
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            return_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
            return_node->AsIdentifier()->SetReference();

            if (return_node->AsIdentifier()->Decorators().empty()) {
                return_node->SetRange(Lexer()->GetToken().Loc());
            } else {
                return_node->SetRange(
                    {return_node->AsIdentifier()->Decorators().front()->Start(), Lexer()->GetToken().End()});
            }

            Lexer()->NextToken();

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
                is_optional = true;

                if ((flags & ExpressionParseFlags::IN_REST) != 0) {
                    ThrowSyntaxError("A rest parameter cannot be optional");
                }

                return_node->AsIdentifier()->SetOptional(true);
                Lexer()->NextToken();
            }

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
                Lexer()->NextToken();  // eat ':'
                TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
                return_node->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
            }
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token, expected an identifier.");
        }
    }

    if ((return_node->IsObjectPattern() || return_node->IsArrayPattern()) && !InAmbientContext() &&
        ((GetContext().Status() & ParserStatus::FUNCTION) != 0) && is_optional) {
        ThrowSyntaxError("A binding pattern parameter cannot be optional in an implementation signature.");
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        return return_node;
    }

    if ((flags & ExpressionParseFlags::IN_REST) != 0) {
        ThrowSyntaxError("A rest parameter cannot have an initializer.");
    }

    if (!allow_default) {
        ThrowSyntaxError("Invalid destructuring assignment target");
    }

    if (is_optional) {
        ThrowSyntaxError("Parameter cannot have question mark and initializer");
    }

    Lexer()->NextToken();

    if (((GetContext().Status() & ParserStatus::GENERATOR_FUNCTION) != 0) &&
        Lexer()->GetToken().Type() == lexer::TokenType::KEYW_YIELD) {
        ThrowSyntaxError("Yield is not allowed in generator parameters");
    }

    ir::Expression *right_node = ParseExpression();

    auto *assignment_expression = AllocNode<ir::AssignmentExpression>(
        ir::AstNodeType::ASSIGNMENT_PATTERN, return_node, right_node, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    assignment_expression->SetRange({return_node->Start(), right_node->End()});

    return assignment_expression;
}

bool TSParser::CurrentLiteralIsBasicType() const
{
    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_ANY:
        case lexer::TokenType::KEYW_BOOLEAN:
        case lexer::TokenType::KEYW_NUMBER:
        case lexer::TokenType::KEYW_STRING:
        case lexer::TokenType::KEYW_UNKNOWN:
        case lexer::TokenType::KEYW_UNDEFINED:
        case lexer::TokenType::KEYW_NEVER:
        case lexer::TokenType::KEYW_OBJECT:
        case lexer::TokenType::KEYW_BIGINT: {
            return true;
        }
        default: {
            break;
        }
    }

    return false;
}

bool TSParser::CurrentIsBasicType()
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_NUMBER:
        case lexer::TokenType::LITERAL_STRING:
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_NULL:
        case lexer::TokenType::KEYW_THIS:
        case lexer::TokenType::KEYW_VOID: {
            return true;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            return CurrentLiteralIsBasicType();
        }
        default: {
            break;
        }
    }

    return false;
}

ir::TypeNode *TSParser::ParseTypeAnnotation(TypeAnnotationParsingOptions *options)
{
    ir::TypeNode *type_annotation = nullptr;

    while (true) {
        ir::TypeNode *element = ParseTypeAnnotationElement(type_annotation, options);

        *options &= ~TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;

        if (element == nullptr) {
            break;
        }

        type_annotation = element;

        if ((((*options) & TypeAnnotationParsingOptions::BREAK_AT_NEW_LINE) != 0) && Lexer()->GetToken().NewLine()) {
            break;
        }
    }

    return type_annotation;
}

ir::TypeNode *TSParser::ParseIdentifierReference()
{
    if (CurrentLiteralIsBasicType() && Lexer()->Lookahead() != lexer::LEX_CHAR_DOT) {
        return ParseBasicType();
    }

    return ParseTypeReferenceOrQuery();
}

bool TSParser::IsStartOfMappedType() const
{
    auto pos = Lexer()->Save();
    Lexer()->NextToken();
    bool result = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PLUS) {
        Lexer()->NextToken();
        result = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY;
        Lexer()->Rewind(pos);
        return result;
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY) {
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        Lexer()->Rewind(pos);
        return false;
    }

    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        Lexer()->Rewind(pos);
        return false;
    }

    Lexer()->NextToken();

    result = Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IN;

    Lexer()->Rewind(pos);
    return result;
}

bool TSParser::IsStartOfTypePredicate() const
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT ||
           Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    auto pos = Lexer()->Save();
    bool is_asserts = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ASSERTS;
    if (is_asserts) {
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT &&
        Lexer()->GetToken().Type() != lexer::TokenType::KEYW_THIS) {
        Lexer()->Rewind(pos);
        return false;
    }

    if (is_asserts) {
        Lexer()->Rewind(pos);
        return true;
    }

    Lexer()->NextToken();

    bool result = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_IS;
    Lexer()->Rewind(pos);
    return result;
}

bool TSParser::IsStartOfAbstractConstructorType() const
{
    if (Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_ABSTRACT) {
        return false;
    }

    lexer::LexerPosition pos = Lexer()->Save();
    Lexer()->NextToken();  // eat 'abstract'
    bool result = Lexer()->GetToken().Type() == lexer::TokenType::KEYW_NEW;

    Lexer()->Rewind(pos);

    return result;
}

ir::TSImportType *TSParser::ParseImportType(const lexer::SourcePosition &start_loc, bool is_typeof)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT);

    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        ThrowSyntaxError("'(' expected");
    }

    Lexer()->NextToken();

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *param = ParseTypeAnnotation(&options);

    if (!param->IsTSLiteralType() || !param->AsTSLiteralType()->Literal()->IsStringLiteral()) {
        ThrowSyntaxError("String literal expected");
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }

    Lexer()->NextToken();

    ir::Expression *qualifier = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        Lexer()->NextToken();
        qualifier = ParseQualifiedName();
    }

    ir::TSTypeParameterInstantiation *type_params = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
            Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
        }

        type_params = ParseTypeParameterInstantiation(&options);
    }

    auto *import_type = AllocNode<ir::TSImportType>(param, type_params, qualifier, is_typeof);

    import_type->SetRange({start_loc, Lexer()->GetToken().End()});

    return import_type;
}

ir::TypeNode *TSParser::ParseThisType(bool throw_error)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS);

    if (throw_error && ((GetContext().Status() & ParserStatus::ALLOW_THIS_TYPE) == 0)) {
        ThrowSyntaxError(
            "A 'this' type is available only in a non-static member "
            "of a class or interface.");
    }

    auto *return_type = AllocNode<ir::TSThisType>();
    return_type->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    return return_type;
}

ir::TypeNode *TSParser::ParseConditionalType(ir::Expression *check_type, bool restrict_extends)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS);
    if (restrict_extends) {
        ThrowSyntaxError("'?' expected.");
    }

    lexer::SourcePosition start_loc = check_type->Start();

    Lexer()->NextToken();  // eat 'extends'

    ParserStatus saved_status = GetContext().Status();
    GetContext().Status() |= ParserStatus::IN_EXTENDS;

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::RESTRICT_EXTENDS;
    auto *extends_type = ParseTypeAnnotation(&options);

    GetContext().Status() = saved_status;

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        ThrowSyntaxError("'?' expected.");
    }

    Lexer()->NextToken();  // eat '?'

    options &= ~TypeAnnotationParsingOptions::RESTRICT_EXTENDS;
    auto *true_type = ParseTypeAnnotation(&options);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("':' expected.");
    }

    Lexer()->NextToken();  // eat ':'

    auto *false_type = ParseTypeAnnotation(&options);

    lexer::SourcePosition end_loc = false_type->End();

    auto *conditional_type = AllocNode<ir::TSConditionalType>(check_type, extends_type, true_type, false_type);

    conditional_type->SetRange({start_loc, end_loc});

    return conditional_type;
}

ir::TypeNode *TSParser::ParseTypeOperatorOrTypeReference()
{
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY) {
        lexer::SourcePosition type_operator_start = Lexer()->GetToken().Start();
        Lexer()->NextToken();

        ir::TypeNode *type = ParseTypeAnnotation(&options);

        if (!type->IsTSArrayType() && !type->IsTSTupleType()) {
            ThrowSyntaxError(
                "'readonly' type modifier is only permitted on array "
                "and tuple literal types.");
        }

        auto *type_operator = AllocNode<ir::TSTypeOperator>(type, ir::TSOperatorType::READONLY);

        type_operator->SetRange({type_operator_start, type->End()});

        return type_operator;
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_KEYOF) {
        lexer::SourcePosition type_operator_start = Lexer()->GetToken().Start();
        Lexer()->NextToken();

        ir::TypeNode *type = ParseTypeAnnotation(&options);

        auto *type_operator = AllocNode<ir::TSTypeOperator>(type, ir::TSOperatorType::KEYOF);

        type_operator->SetRange({type_operator_start, type->End()});

        return type_operator;
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_INFER) {
        if ((GetContext().Status() & ParserStatus::IN_EXTENDS) == 0) {
            ThrowSyntaxError(
                "'infer' declarations are only permitted in the "
                "'extends' clause of a conditional type.");
        }

        lexer::SourcePosition infer_start = Lexer()->GetToken().Start();
        Lexer()->NextToken();

        ir::TSTypeParameter *type_param = ParseTypeParameter(&options);

        auto *infer_type = AllocNode<ir::TSInferType>(type_param);

        infer_type->SetRange({infer_start, Lexer()->GetToken().End()});

        return infer_type;
    }

    return ParseIdentifierReference();
}

ir::TypeNode *TSParser::ParseTupleElement(ir::TSTupleKind *kind, bool *seen_optional)
{
    lexer::SourcePosition element_start = Lexer()->GetToken().Start();
    ir::TypeNode *element = nullptr;
    bool is_optional = false;
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT && !CurrentLiteralIsBasicType()) {
        auto *element_ident = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        element_ident->SetRange(Lexer()->GetToken().Loc());

        if (Lexer()->Lookahead() == lexer::LEX_CHAR_COLON || Lexer()->Lookahead() == lexer::LEX_CHAR_QUESTION) {
            if (*kind == ir::TSTupleKind::DEFAULT) {
                ThrowSyntaxError("Tuple members must all have names or all not have names");
            }

            Lexer()->NextToken();  // eat ident

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
                Lexer()->NextToken();  // eat '?'
                is_optional = true;
                *seen_optional = true;
            } else if (*seen_optional) {
                ThrowSyntaxError("A required element cannot follow an optional element");
            }

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
                ThrowSyntaxError("':' expected");
            }

            Lexer()->NextToken();  // eat ':'
            auto *element_type = ParseTypeAnnotation(&options);
            *kind = ir::TSTupleKind::NAMED;

            element = AllocNode<ir::TSNamedTupleMember>(element_ident, element_type, is_optional);
        } else {
            element = ParseTypeReferenceOrQuery();
        }
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            element = ParseTypeAnnotationElement(element, &options);
        }
    } else {
        if (*kind == ir::TSTupleKind::NAMED) {
            ThrowSyntaxError("Tuple members must all have names or all not have names");
        }

        *kind = ir::TSTupleKind::DEFAULT;
        element = ParseTypeAnnotation(&options);
    }

    if (element != nullptr) {
        element->SetRange({element_start, Lexer()->GetToken().End()});
    }
    return element;
}

ir::TSTupleType *TSParser::ParseTupleType()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);
    lexer::SourcePosition tuple_start = Lexer()->GetToken().Start();
    ArenaVector<ir::TypeNode *> elements(Allocator()->Adapter());
    ir::TSTupleKind kind = ir::TSTupleKind::NONE;
    bool seen_optional = false;

    Lexer()->NextToken();  // eat '['

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ir::TypeNode *element = ParseTupleElement(&kind, &seen_optional);
        elements.push_back(element);

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            break;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA) {
            ThrowSyntaxError("',' expected.");
        }

        Lexer()->NextToken();  // eat ','
    }

    lexer::SourcePosition tuple_end = Lexer()->GetToken().End();
    Lexer()->NextToken();  // eat ']'

    auto *tuple_type = AllocNode<ir::TSTupleType>(std::move(elements));
    tuple_type->SetRange({tuple_start, tuple_end});
    return tuple_type;
}

ir::TypeNode *TSParser::ParseIndexAccessType(ir::TypeNode *type_name)
{
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    do {
        Lexer()->NextToken();  // eat '['

        ir::TypeNode *index_type = ParseTypeAnnotation(&options);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("']' expected");
        }

        Lexer()->NextToken();  // eat ']'

        type_name = AllocNode<ir::TSIndexedAccessType>(type_name, index_type);
        type_name->SetRange({type_name->AsTSIndexedAccessType()->ObjectType()->Start(), Lexer()->GetToken().End()});
    } while (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET &&
             Lexer()->Lookahead() != lexer::LEX_CHAR_RIGHT_SQUARE);

    return type_name;
}

ir::TypeNode *TSParser::ParseTypeReferenceOrQuery(bool parse_query)
{
    lexer::SourcePosition reference_start_loc = Lexer()->GetToken().Start();

    if (parse_query) {
        ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_TYPEOF);
        Lexer()->NextToken();  // eat 'typeof'

        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT) {
            lexer::SourcePosition &start_loc = reference_start_loc;
            return ParseImportType(start_loc, true);
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("Identifier expected.");
        }
    }

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT ||
           Lexer()->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS);

    ir::Expression *type_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    type_name->SetRange(Lexer()->GetToken().Loc());
    type_name->AsIdentifier()->SetReference();

    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
        Lexer()->ForwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    } else {
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
        type_name = ParseQualifiedReference(type_name);
    }

    ir::TSTypeParameterInstantiation *type_param_inst = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        if (parse_query) {
            ThrowSyntaxError("Unexpected token.");
        }

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_inst = ParseTypeParameterInstantiation(&options);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET &&
        Lexer()->Lookahead() != lexer::LEX_CHAR_RIGHT_SQUARE) {
        ir::TypeNode *type_ref {};
        if (parse_query) {
            type_ref = AllocNode<ir::TSTypeQuery>(type_name);
        } else {
            type_ref = AllocNode<ir::TSTypeReference>(type_name, type_param_inst);
        }

        type_ref->SetRange({reference_start_loc, Lexer()->GetToken().End()});

        return ParseIndexAccessType(type_ref);
    }

    ir::TypeNode *return_node = nullptr;

    lexer::SourcePosition reference_end_loc = type_name->End();

    if (parse_query) {
        return_node = AllocNode<ir::TSTypeQuery>(type_name);
    } else {
        return_node = AllocNode<ir::TSTypeReference>(type_name, type_param_inst);
    }

    return_node->SetRange({reference_start_loc, reference_end_loc});

    return return_node;
}

ir::TSTypeParameter *TSParser::ParseMappedTypeParameter()
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();

    auto *param_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    param_name->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});

    Lexer()->NextToken();

    Lexer()->NextToken();  // eat 'in'

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *constraint = ParseTypeAnnotation(&options);

    lexer::SourcePosition end_loc = constraint->End();

    auto *type_parameter = AllocNode<ir::TSTypeParameter>(param_name, constraint, nullptr);

    type_parameter->SetRange({start_loc, end_loc});

    return type_parameter;
}

ir::MappedOption TSParser::ParseMappedOption(lexer::TokenType token_type)
{
    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_MINUS &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_PLUS &&
        Lexer()->GetToken().KeywordType() != token_type && Lexer()->GetToken().Type() != token_type) {
        return ir::MappedOption::NO_OPTS;
    }

    auto result = Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS ? ir::MappedOption::MINUS
                                                                                   : ir::MappedOption::PLUS;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PLUS) {
        Lexer()->NextToken();
    }

    if (Lexer()->GetToken().KeywordType() != token_type && Lexer()->GetToken().Type() != token_type) {
        ThrowSyntaxError({"'", TokenToString(token_type), "' expected."});
    }

    Lexer()->NextToken();

    return result;
}

ir::TSMappedType *TSParser::ParseMappedType()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE);

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);  // eat '{'

    ir::MappedOption readonly = ParseMappedOption(lexer::TokenType::KEYW_READONLY);

    Lexer()->NextToken();  // eat '['

    ir::TSTypeParameter *type_parameter = ParseMappedTypeParameter();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("']' expected");
    }

    Lexer()->NextToken();  // eat ']'

    ir::MappedOption optional = ParseMappedOption(lexer::TokenType::PUNCTUATOR_QUESTION_MARK);

    ir::TypeNode *type_annotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_annotation = ParseTypeAnnotation(&options);
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("';' expected");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        Lexer()->NextToken();  // eat ';'
    }

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        ThrowSyntaxError("'}' expected");
    }

    auto *mapped_type = AllocNode<ir::TSMappedType>(type_parameter, type_annotation, readonly, optional);

    mapped_type->SetRange({start_loc, Lexer()->GetToken().End()});

    Lexer()->NextToken();  // eat '}'

    return mapped_type;
}

ir::TSTypePredicate *TSParser::ParseTypePredicate()
{
    auto pos = Lexer()->Save();
    lexer::SourcePosition start_pos = Lexer()->GetToken().Start();
    bool is_asserts = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ASSERTS;
    if (is_asserts) {
        Lexer()->NextToken();  // eat 'asserts'
        if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_IS) {
            is_asserts = false;
            Lexer()->Rewind(pos);
        }
    }

    ir::Expression *parameter_name = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        parameter_name = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    } else {
        parameter_name = AllocNode<ir::TSThisType>();
    }

    parameter_name->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});

    Lexer()->NextToken();

    ir::TypeNode *type_annotation = nullptr;
    lexer::SourcePosition end_pos;
    ir::TSTypePredicate *result = nullptr;

    if (is_asserts && Lexer()->GetToken().KeywordType() != lexer::TokenType::KEYW_IS) {
        end_pos = parameter_name->End();
        result = AllocNode<ir::TSTypePredicate>(parameter_name, type_annotation, is_asserts);
        result->SetRange({start_pos, end_pos});
        return result;
    }

    Lexer()->NextToken();  // eat 'is'

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    type_annotation = ParseTypeAnnotation(&options);
    end_pos = type_annotation->End();

    result = AllocNode<ir::TSTypePredicate>(parameter_name, type_annotation, is_asserts);

    result->SetRange({start_pos, end_pos});

    return result;
}

ir::TypeNode *TSParser::ParseTypeLiteralOrMappedType(ir::TypeNode *type_annotation)
{
    if (type_annotation != nullptr) {
        return nullptr;
    }

    if (IsStartOfMappedType()) {
        return ParseMappedType();
    }

    lexer::SourcePosition body_start = Lexer()->GetToken().Start();
    auto members = ParseTypeLiteralOrInterface();
    lexer::SourcePosition body_end = Lexer()->GetToken().End();
    Lexer()->NextToken();

    auto *literal_type = AllocNode<ir::TSTypeLiteral>(std::move(members));
    auto *type_var = binder::Scope::CreateVar(Allocator(), "__type", binder::VariableFlags::TYPE, literal_type);
    literal_type->SetVariable(type_var);
    literal_type->SetRange({body_start, body_end});
    return literal_type;
}

ir::TypeNode *TSParser::ParseTypeReferenceOrTypePredicate(ir::TypeNode *type_annotation, bool can_be_ts_type_predicate)
{
    if (type_annotation != nullptr) {
        return nullptr;
    }

    if (can_be_ts_type_predicate && IsStartOfTypePredicate()) {
        return ParseTypePredicate();
    }

    return ParseTypeOperatorOrTypeReference();
}

ir::TypeNode *TSParser::ParseThisTypeOrTypePredicate(ir::TypeNode *type_annotation, bool can_be_ts_type_predicate,
                                                     bool throw_error)
{
    if (type_annotation != nullptr) {
        return nullptr;
    }

    if (can_be_ts_type_predicate && IsStartOfTypePredicate()) {
        return ParseTypePredicate();
    }

    return ParseThisType(throw_error);
}

ir::TSArrayType *TSParser::ParseArrayType(ir::TypeNode *element_type)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET);
    Lexer()->NextToken();  // eat '['

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("']' expected");
    }

    lexer::SourcePosition end_loc = Lexer()->GetToken().End();
    Lexer()->NextToken();  // eat ']'

    lexer::SourcePosition start_loc = element_type->Start();
    auto *array_type = AllocNode<ir::TSArrayType>(element_type);
    array_type->SetRange({start_loc, end_loc});

    return array_type;
}

ir::TSUnionType *TSParser::ParseUnionType(ir::TypeNode *type, bool restrict_extends)
{
    ArenaVector<ir::TypeNode *> types(Allocator()->Adapter());
    lexer::SourcePosition start_loc;

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::IN_UNION;

    if (restrict_extends) {
        options |= TypeAnnotationParsingOptions::RESTRICT_EXTENDS;
    }

    if (type != nullptr) {
        start_loc = type->Start();
        types.push_back(type);
    } else {
        start_loc = Lexer()->GetToken().Start();
    }

    while (true) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_BITWISE_OR) {
            break;
        }

        Lexer()->NextToken();  // eat '|'

        types.push_back(ParseTypeAnnotation(&options));
    }

    lexer::SourcePosition end_loc = types.back()->End();

    auto *union_type = AllocNode<ir::TSUnionType>(std::move(types));
    auto *type_var = binder::Scope::CreateVar(Allocator(), "__type", binder::VariableFlags::TYPE, union_type);
    union_type->SetVariable(type_var);
    union_type->SetRange({start_loc, end_loc});

    return union_type;
}

ir::TSIntersectionType *TSParser::ParseIntersectionType(ir::Expression *type, bool in_union, bool restrict_extends)
{
    ArenaVector<ir::Expression *> types(Allocator()->Adapter());
    lexer::SourcePosition start_loc;

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::IN_INTERSECTION;

    if (restrict_extends) {
        options |= TypeAnnotationParsingOptions::RESTRICT_EXTENDS;
    }

    if (in_union) {
        options |= TypeAnnotationParsingOptions::IN_UNION;
    }

    if (type != nullptr) {
        start_loc = type->Start();
        types.push_back(type);
    } else {
        start_loc = Lexer()->GetToken().Start();
    }

    while (true) {
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_BITWISE_AND) {
            break;
        }

        Lexer()->NextToken();  // eat '&'

        types.push_back(ParseTypeAnnotation(&options));
    }

    lexer::SourcePosition end_loc = types.back()->End();

    auto *intersection_type = AllocNode<ir::TSIntersectionType>(std::move(types));
    auto *type_var = binder::Scope::CreateVar(Allocator(), "__type", binder::VariableFlags::TYPE, intersection_type);
    intersection_type->SetVariable(type_var);
    intersection_type->SetRange({start_loc, end_loc});

    return intersection_type;
}

ir::TypeNode *TSParser::ParseBasicType()
{
    ir::TypeNode *type_annotation = nullptr;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_MINUS) {
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_NUMBER) {
            ThrowSyntaxError("Type expected");
        }
    }
    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::LITERAL_NUMBER: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                auto *bigint_node = AllocNode<ir::BigIntLiteral>(Lexer()->GetToken().BigInt());
                bigint_node->SetRange(Lexer()->GetToken().Loc());

                type_annotation = AllocNode<ir::TSLiteralType>(bigint_node);
            } else {
                auto *number_node = AllocNode<ir::NumberLiteral>(Lexer()->GetToken().GetNumber());
                number_node->SetRange(Lexer()->GetToken().Loc());

                type_annotation = AllocNode<ir::TSLiteralType>(number_node);
            }
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            auto *string_node = AllocNode<ir::StringLiteral>(Lexer()->GetToken().String());
            string_node->SetRange(Lexer()->GetToken().Loc());

            type_annotation = AllocNode<ir::TSLiteralType>(string_node);
            break;
        }
        case lexer::TokenType::LITERAL_TRUE: {
            auto *boolean_literal = AllocNode<ir::BooleanLiteral>(true);
            boolean_literal->SetRange(Lexer()->GetToken().Loc());

            type_annotation = AllocNode<ir::TSLiteralType>(boolean_literal);
            break;
        }
        case lexer::TokenType::LITERAL_FALSE: {
            auto *boolean_literal = AllocNode<ir::BooleanLiteral>(false);
            boolean_literal->SetRange(Lexer()->GetToken().Loc());

            type_annotation = AllocNode<ir::TSLiteralType>(boolean_literal);
            break;
        }
        case lexer::TokenType::KEYW_ANY: {
            type_annotation = AllocNode<ir::TSAnyKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_BOOLEAN: {
            type_annotation = AllocNode<ir::TSBooleanKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_NUMBER: {
            type_annotation = AllocNode<ir::TSNumberKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_STRING: {
            type_annotation = AllocNode<ir::TSStringKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_UNKNOWN: {
            type_annotation = AllocNode<ir::TSUnknownKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_VOID: {
            type_annotation = AllocNode<ir::TSVoidKeyword>();
            break;
        }
        case lexer::TokenType::LITERAL_NULL: {
            type_annotation = AllocNode<ir::TSNullKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_UNDEFINED: {
            type_annotation = AllocNode<ir::TSUndefinedKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_NEVER: {
            type_annotation = AllocNode<ir::TSNeverKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_OBJECT: {
            type_annotation = AllocNode<ir::TSObjectKeyword>();
            break;
        }
        case lexer::TokenType::KEYW_BIGINT: {
            type_annotation = AllocNode<ir::TSBigintKeyword>();
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected type");
        }
    }

    type_annotation->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();
    return type_annotation;
}

ir::TSTypeReference *TSParser::ParseConstExpression()
{
    auto *ident_ref = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    ident_ref->SetReference();
    ident_ref->SetRange(Lexer()->GetToken().Loc());

    auto *type_reference = AllocNode<ir::TSTypeReference>(ident_ref, nullptr);
    type_reference->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
        Lexer()->GetToken().Type() != lexer::TokenType::EOS &&
        Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET &&
        ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NEW_LINE) == 0)) {
        ThrowSyntaxError("Unexpected token.");
    }

    return type_reference;
}

ir::TypeNode *TSParser::ParseParenthesizedOrFunctionType(ir::TypeNode *type_annotation, bool throw_error)
{
    if (type_annotation != nullptr) {
        return nullptr;
    }

    lexer::SourcePosition type_start = Lexer()->GetToken().Start();

    bool abstract_constructor = false;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ABSTRACT) {
        abstract_constructor = true;
        Lexer()->NextToken();  // eat 'abstract'
    }

    bool is_construction_type = false;

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_NEW) {
        Lexer()->NextToken();  // eat 'new'
        is_construction_type = true;

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LESS_THAN) {
            ThrowSyntaxError("'(' expected");
        }
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN || is_construction_type) {
        return ParseFunctionType(type_start, is_construction_type, throw_error, abstract_constructor);
    }

    const auto start_pos = Lexer()->Save();
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();  // eat '('

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::NO_OPTS;
    ir::TypeNode *type = ParseTypeAnnotation(&options);

    if (type == nullptr) {
        Lexer()->Rewind(start_pos);
        return ParseFunctionType(type_start, false, throw_error);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->Rewind(start_pos);
        return ParseFunctionType(type_start, false, throw_error);
    }

    if (throw_error && Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }

    lexer::SourcePosition end_loc = Lexer()->GetToken().End();
    Lexer()->NextToken();  // eat ')'

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
        Lexer()->Rewind(start_pos);

        return ParseFunctionType(type_start, false, throw_error);
    }

    auto *result = AllocNode<ir::TSParenthesizedType>(type);
    result->SetRange({type_start, end_loc});

    return result;
}

ir::TypeNode *TSParser::ParseFunctionType(lexer::SourcePosition start_loc, bool is_construction_type, bool throw_error,
                                          bool abstract_constructor)
{
    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());

    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = throw_error ? TypeAnnotationParsingOptions::THROW_ERROR : TypeAnnotationParsingOptions::NO_OPTS;
        type_param_decl = ParseTypeParameterDeclaration(&options);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            if (!throw_error) {
                return nullptr;
            }

            ThrowSyntaxError("'(' expected");
        }
    }

    FunctionParameterContext func_param_context(&GetContext(), Binder());
    auto *func_param_scope = func_param_context.LexicalScope().GetScope();
    auto params = ParseFunctionParams();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
        ThrowSyntaxError("'=>' expected");
    }

    Lexer()->NextToken();  // eat '=>'

    TypeAnnotationParsingOptions options =
        TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
    ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

    ir::TypeNode *func_type = nullptr;

    if (is_construction_type) {
        func_type = AllocNode<ir::TSConstructorType>(func_param_scope, std::move(params), type_param_decl,
                                                     return_type_annotation, abstract_constructor);
    } else {
        func_type =
            AllocNode<ir::TSFunctionType>(func_param_scope, std::move(params), type_param_decl, return_type_annotation);
    }

    func_type->SetRange({start_loc, return_type_annotation->End()});
    func_param_scope->BindNode(func_type);

    return func_type;
}

ir::TypeNode *TSParser::ParseTypeAnnotationElement(ir::TypeNode *type_annotation, TypeAnnotationParsingOptions *options)
{
    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::PUNCTUATOR_BITWISE_OR: {
            if (((*options) &
                 (TypeAnnotationParsingOptions::IN_UNION | TypeAnnotationParsingOptions::IN_INTERSECTION)) != 0) {
                break;
            }

            return ParseUnionType(type_annotation, ((*options) & TypeAnnotationParsingOptions::RESTRICT_EXTENDS) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_BITWISE_AND: {
            if (((*options) & TypeAnnotationParsingOptions::IN_INTERSECTION) != 0) {
                break;
            }

            return ParseIntersectionType(type_annotation, ((*options) & TypeAnnotationParsingOptions::IN_UNION) != 0,
                                         ((*options) & TypeAnnotationParsingOptions::RESTRICT_EXTENDS) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN:
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS:
        case lexer::TokenType::KEYW_NEW: {
            return ParseParenthesizedOrFunctionType(type_annotation,
                                                    ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            if (type_annotation != nullptr) {
                if (Lexer()->Lookahead() == lexer::LEX_CHAR_RIGHT_SQUARE) {
                    return ParseArrayType(type_annotation);
                }

                return ParseIndexAccessType(type_annotation);
            }

            return ParseTupleType();
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseTypeLiteralOrMappedType(type_annotation);
        }
        case lexer::TokenType::PUNCTUATOR_MINUS:
        case lexer::TokenType::LITERAL_NUMBER:
        case lexer::TokenType::LITERAL_STRING:
        case lexer::TokenType::LITERAL_FALSE:
        case lexer::TokenType::LITERAL_TRUE:
        case lexer::TokenType::LITERAL_NULL:
        case lexer::TokenType::KEYW_VOID: {
            if (type_annotation != nullptr) {
                break;
            }

            return ParseBasicType();
        }
        case lexer::TokenType::KEYW_TYPEOF: {
            if (type_annotation != nullptr) {
                break;
            }

            return ParseTypeReferenceOrQuery(true);
        }
        case lexer::TokenType::KEYW_IMPORT: {
            if (type_annotation != nullptr) {
                break;
            }

            lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
            return ParseImportType(start_loc);
        }
        case lexer::TokenType::KEYW_CONST: {
            if (((*options) & TypeAnnotationParsingOptions::ALLOW_CONST) == 0) {
                break;
            }

            (*options) &= ~TypeAnnotationParsingOptions::ALLOW_CONST;
            return ParseConstExpression();
        }
        case lexer::TokenType::LITERAL_IDENT: {
            if (IsStartOfAbstractConstructorType()) {
                return ParseParenthesizedOrFunctionType(type_annotation,
                                                        ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0);
            }

            return ParseTypeReferenceOrTypePredicate(
                type_annotation, ((*options) & TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE) != 0);
        }
        case lexer::TokenType::KEYW_EXTENDS: {
            if (((*options) &
                 (TypeAnnotationParsingOptions::IN_UNION | TypeAnnotationParsingOptions::IN_INTERSECTION)) != 0) {
                break;
            }

            if (type_annotation == nullptr) {
                return ParseIdentifierReference();
            }

            return ParseConditionalType(type_annotation,
                                        ((*options) & TypeAnnotationParsingOptions::RESTRICT_EXTENDS) != 0);
        }
        case lexer::TokenType::KEYW_THIS: {
            return ParseThisTypeOrTypePredicate(
                type_annotation, ((*options) & TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE) != 0,
                ((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0);
        }
        default: {
            break;
        }
    }

    if (type_annotation == nullptr && (((*options) & TypeAnnotationParsingOptions::THROW_ERROR) != 0)) {
        ThrowSyntaxError("Type expected");
    }

    return nullptr;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ObjectExpression *TSParser::ParseObjectExpression(ExpressionParseFlags flags)
{
    ir::ObjectExpression *obj_expression = ParserImpl::ParseObjectExpression(flags);
    ParsePotentialOptionalFunctionParameter(obj_expression);
    return obj_expression;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ArrayExpression *TSParser::ParseArrayExpression(ExpressionParseFlags flags)
{
    ir::ArrayExpression *array_expression = ParserImpl::ParseArrayExpression(flags);
    ParsePotentialOptionalFunctionParameter(array_expression);
    return array_expression;
}

ir::ArrowFunctionExpression *TSParser::ParsePotentialArrowExpression(ir::Expression **return_expression,
                                                                     const lexer::SourcePosition &start_loc)
{
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            *return_expression = ParseFunctionExpression(ParserStatus::ASYNC_FUNCTION);
            (*return_expression)->SetStart(start_loc);
            break;
        }
        case lexer::TokenType::LITERAL_IDENT: {
            ir::Expression *ident_ref = ParsePrimaryExpression();
            ASSERT(ident_ref->IsIdentifier());

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
                ThrowSyntaxError("Unexpected token, expected '=>'");
            }

            ir::ArrowFunctionExpression *arrow_func_expr =
                ParseArrowFunctionExpression(ident_ref, nullptr, nullptr, true);
            arrow_func_expr->SetStart(start_loc);

            return arrow_func_expr;
        }
        case lexer::TokenType::PUNCTUATOR_ARROW: {
            ir::ArrowFunctionExpression *arrow_func_expr =
                ParseArrowFunctionExpression(*return_expression, nullptr, nullptr, true);
            arrow_func_expr->SetStart(start_loc);
            return arrow_func_expr;
        }
        case lexer::TokenType::PUNCTUATOR_LESS_THAN: {
            const auto saved_pos = Lexer()->Save();

            auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
            auto options = TypeAnnotationParsingOptions::NO_OPTS;
            type_param_decl = ParseTypeParameterDeclaration(&options);
            if (type_param_decl == nullptr) {
                Lexer()->Rewind(saved_pos);
                return nullptr;
            }

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
                ThrowSyntaxError("'(' expected");
            }

            [[fallthrough]];
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS: {
            ir::CallExpression *call_expression = ParseCallExpression(*return_expression, false);

            ir::TypeNode *return_type_annotation = nullptr;
            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
                Lexer()->NextToken();  // eat ':'
                TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
                return_type_annotation = ParseTypeAnnotation(&options);
            }

            if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_ARROW) {
                ir::ArrowFunctionExpression *arrow_func_expr =
                    ParseArrowFunctionExpression(call_expression, type_param_decl, return_type_annotation, true);
                arrow_func_expr->SetStart(start_loc);

                return arrow_func_expr;
            }

            if (return_type_annotation != nullptr || type_param_decl != nullptr) {
                ThrowSyntaxError("'=>' expected");
            }

            *return_expression = call_expression;
            break;
        }
        default: {
            break;
        }
    }

    return nullptr;
}

bool TSParser::ParsePotentialGenericFunctionCall(ir::Expression *primary_expr, ir::Expression **return_expression,
                                                 const lexer::SourcePosition &start_loc, bool ignore_call_expression)
{
    if (Lexer()->Lookahead() == lexer::LEX_CHAR_LESS_THAN ||
        (!primary_expr->IsIdentifier() && !primary_expr->IsMemberExpression())) {
        return true;
    }

    const auto saved_pos = Lexer()->Save();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SHIFT) {
        Lexer()->BackwardToken(lexer::TokenType::PUNCTUATOR_LESS_THAN, 1);
    }

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::NO_OPTS;
    ir::TSTypeParameterInstantiation *type_params = ParseTypeParameterInstantiation(&options);

    if (type_params == nullptr) {
        Lexer()->Rewind(saved_pos);
        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::EOS) {
        ThrowSyntaxError("'(' or '`' expected");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        if (!ignore_call_expression) {
            *return_expression = ParseCallExpression(*return_expression, false);
            (*return_expression)->AsCallExpression()->SetTypeParams(type_params);
            return false;
        }

        return true;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_BACK_TICK) {
        ir::TemplateLiteral *property_node = ParseTemplateLiteral();
        lexer::SourcePosition end_loc = property_node->End();

        *return_expression = AllocNode<ir::TaggedTemplateExpression>(*return_expression, property_node, type_params);
        (*return_expression)->SetRange({start_loc, end_loc});
        return false;
    }

    Lexer()->Rewind(saved_pos);
    return true;
}

bool TSParser::ParsePotentialNonNullExpression(ir::Expression **return_expression, lexer::SourcePosition start_loc)
{
    if (return_expression == nullptr || Lexer()->GetToken().NewLine()) {
        return true;
    }

    *return_expression = AllocNode<ir::TSNonNullExpression>(*return_expression);
    (*return_expression)->SetRange({start_loc, Lexer()->GetToken().End()});
    Lexer()->NextToken();
    return false;
}

bool TSParser::IsNamedFunctionExpression()
{
    return Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
           Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LESS_THAN;
}

ir::Identifier *TSParser::ParsePrimaryExpressionIdent([[maybe_unused]] ExpressionParseFlags flags)
{
    auto *ident_node = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    ident_node->SetReference();
    ident_node->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();

    ParsePotentialOptionalFunctionParameter(ident_node);

    return ident_node;
}

void TSParser::ValidateArrowFunctionRestParameter(ir::SpreadElement *rest_element)
{
    ParseOptionalFunctionParameter(rest_element, true);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("')' expected");
    }
}

ir::TSSignatureDeclaration *TSParser::ParseSignatureMember(bool is_call_signature)
{
    lexer::SourcePosition member_start_loc = Lexer()->GetToken().Start();

    if (!is_call_signature) {
        Lexer()->NextToken();  // eat 'new' keyword
    }

    auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
    ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        auto options = TypeAnnotationParsingOptions::THROW_ERROR;
        type_param_decl = ParseTypeParameterDeclaration(&options);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            ThrowSyntaxError("'(' expected");
        }
    }

    FunctionParameterContext func_param_context(&GetContext(), Binder());
    auto *func_param_scope = func_param_context.LexicalScope().GetScope();
    auto params = ParseFunctionParams();

    ir::TypeNode *type_annotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
        type_annotation = ParseTypeAnnotation(&options);
    }

    auto kind = is_call_signature ? ir::TSSignatureDeclaration::TSSignatureDeclarationKind::CALL_SIGNATURE
                                  : ir::TSSignatureDeclaration::TSSignatureDeclarationKind::CONSTRUCT_SIGNATURE;
    auto *signature_member = AllocNode<ir::TSSignatureDeclaration>(func_param_scope, kind, type_param_decl,
                                                                   std::move(params), type_annotation);
    func_param_scope->BindNode(signature_member);

    signature_member->SetRange({member_start_loc, Lexer()->GetToken().End()});

    return signature_member;
}

bool TSParser::IsPotentiallyIndexSignature()
{
    const auto saved_pos = Lexer()->Save();

    Lexer()->NextToken();  // eat '['

    bool is_index_signature =
        Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT && Lexer()->Lookahead() == lexer::LEX_CHAR_COLON;

    Lexer()->Rewind(saved_pos);

    return is_index_signature;
}

// NOLINTNEXTLINE(google-default-arguments)
ir::TSIndexSignature *TSParser::ParseIndexSignature(const lexer::SourcePosition &start_loc, bool is_readonly)
{
    Lexer()->NextToken();  // eat '['

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    auto *key = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    key->SetRange(Lexer()->GetToken().Loc());

    Lexer()->NextToken();  // eat key

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON);

    Lexer()->NextToken();  // eat ':'

    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
    ir::TypeNode *key_type = ParseTypeAnnotation(&options);

    if (!key_type->IsTSNumberKeyword() && !key_type->IsTSStringKeyword()) {
        ThrowSyntaxError(
            "An index signature parameter type must be either "
            "'string' or 'number'");
    }

    key->SetTsTypeAnnotation(key_type);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("']' expected.");
    }

    Lexer()->NextToken();  // eat ']'

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
        ThrowSyntaxError("An index signature must have a type annotation.");
    }

    Lexer()->NextToken();  // eat ':'

    ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

    auto *index_signature = AllocNode<ir::TSIndexSignature>(key, type_annotation, is_readonly);
    index_signature->SetRange({start_loc, Lexer()->GetToken().End()});
    return index_signature;
}

std::tuple<ir::Expression *, bool> TSParser::ParseInterfacePropertyKey()
{
    ir::Expression *key = nullptr;
    bool is_computed = false;

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            const util::StringView &ident = Lexer()->GetToken().Ident();
            key = AllocNode<ir::Identifier>(ident, Allocator());
            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            const util::StringView &string = Lexer()->GetToken().String();
            key = AllocNode<ir::StringLiteral>(string);
            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                key = AllocNode<ir::BigIntLiteral>(Lexer()->GetToken().BigInt());
            } else {
                key = AllocNode<ir::NumberLiteral>(Lexer()->GetToken().GetNumber());
            }

            key->SetRange(Lexer()->GetToken().Loc());
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            Lexer()->NextToken();  // eat left square bracket

            key = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);
            is_computed = true;

            if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
                ThrowSyntaxError("Unexpected token, expected ']'");
            }
            break;
        }
        default: {
            ThrowSyntaxError("Unexpected token in property key");
        }
    }

    Lexer()->NextToken();
    return {key, is_computed};
}

void TSParser::CreateTSVariableForProperty(ir::AstNode *node, const ir::Expression *key, binder::VariableFlags flags)
{
    binder::Variable *prop_var = nullptr;
    bool is_method = (flags & binder::VariableFlags::METHOD) != 0;
    util::StringView prop_name = "__computed";

    switch (key->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            prop_name = key->AsIdentifier()->Name();
            break;
        }
        case ir::AstNodeType::NUMBER_LITERAL: {
            prop_name = key->AsNumberLiteral()->Str();
            flags |= binder::VariableFlags::NUMERIC_NAME;
            break;
        }
        case ir::AstNodeType::STRING_LITERAL: {
            prop_name = key->AsStringLiteral()->Str();
            break;
        }
        default: {
            flags |= binder::VariableFlags::COMPUTED;
            break;
        }
    }

    prop_var = is_method ? binder::Scope::CreateVar<binder::MethodDecl>(Allocator(), prop_name, flags, node)
                         : binder::Scope::CreateVar<binder::PropertyDecl>(Allocator(), prop_name, flags, node);

    node->SetVariable(prop_var);
}

ir::AstNode *TSParser::ParsePropertyOrMethodSignature(const lexer::SourcePosition &start_loc, bool is_readonly)
{
    auto [key, isComputed] = ParseInterfacePropertyKey();

    bool is_optional = false;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_QUESTION_MARK) {
        is_optional = true;
        Lexer()->NextToken();  // eat '?'
    }

    binder::VariableFlags flags = binder::VariableFlags::NONE;

    if (is_optional) {
        flags |= binder::VariableFlags::OPTIONAL;
    }

    if (is_readonly) {
        flags |= binder::VariableFlags::READONLY;
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        if (is_readonly) {
            ThrowSyntaxError("'readonly' modifier can only appear on a property declaration or index signature.",
                             start_loc);
        }

        auto type_params_ctx = binder::LexicalScope<binder::LocalScope>(Binder());
        ir::TSTypeParameterDeclaration *type_param_decl = nullptr;
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
            auto options = TypeAnnotationParsingOptions::THROW_ERROR;
            type_param_decl = ParseTypeParameterDeclaration(&options);
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
            ThrowExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
        }

        FunctionParameterContext func_param_context(&GetContext(), Binder());
        auto *func_param_scope = func_param_context.LexicalScope().GetScope();
        auto params = ParseFunctionParams();

        ir::TypeNode *return_type = nullptr;
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
            Lexer()->NextToken();  // eat ':'
            TypeAnnotationParsingOptions options =
                TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
            return_type = ParseTypeAnnotation(&options);
        }

        auto *method_signature = AllocNode<ir::TSMethodSignature>(
            func_param_scope, key, type_param_decl, std::move(params), return_type, isComputed, is_optional);
        func_param_scope->BindNode(method_signature);
        CreateTSVariableForProperty(method_signature, key, flags | binder::VariableFlags::METHOD);
        method_signature->SetRange({start_loc, Lexer()->GetToken().End()});
        return method_signature;
    }

    ir::TypeNode *type_annotation = nullptr;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::BREAK_AT_NEW_LINE;
        type_annotation = ParseTypeAnnotation(&options);
    }

    auto *property_signature =
        AllocNode<ir::TSPropertySignature>(key, type_annotation, isComputed, is_optional, is_readonly);
    CreateTSVariableForProperty(property_signature, key, flags | binder::VariableFlags::PROPERTY);
    property_signature->SetRange({start_loc, Lexer()->GetToken().End()});
    return property_signature;
}

ir::AstNode *TSParser::ParseTypeLiteralOrInterfaceMember()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_AT) {
        ThrowSyntaxError("Decorators are not allowed here");
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        return ParseSignatureMember(true);
    }

    char32_t next_cp = Lexer()->Lookahead();
    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_NEW &&
        (next_cp == lexer::LEX_CHAR_LEFT_PAREN || next_cp == lexer::LEX_CHAR_LESS_THAN)) {
        return ParseSignatureMember(false);
    }

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    bool is_readonly = Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_READONLY &&
                       next_cp != lexer::LEX_CHAR_LEFT_PAREN && next_cp != lexer::LEX_CHAR_COLON &&
                       next_cp != lexer::LEX_CHAR_COMMA;

    if (is_readonly) {
        Lexer()->NextToken();  // eat 'readonly"
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET &&
        IsPotentiallyIndexSignature()) {
        return ParseIndexSignature(start_loc, is_readonly);
    }

    return ParsePropertyOrMethodSignature(start_loc, is_readonly);
}

void TSParser::ValidateFunctionParam(const ArenaVector<ir::Expression *> &params, const ir::Expression *parameter,
                                     bool *seen_optional)
{
    if (!parameter->IsIdentifier()) {
        GetContext().Status() |= ParserStatus::HAS_COMPLEX_PARAM;
        if (!parameter->IsRestElement()) {
            return;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("A rest parameter must be last in parameter list");
        }
        return;
    }

    bool current_is_optional = parameter->AsIdentifier()->IsOptional();
    if (*seen_optional && !current_is_optional) {
        ThrowSyntaxError("A required parameter cannot follow an optional parameter");
    }

    *seen_optional |= current_is_optional;
    const util::StringView &param_name = parameter->AsIdentifier()->Name();

    if (param_name.Is("this")) {
        if (!params.empty()) {
            ThrowSyntaxError("A 'this' parameter must be the first parameter");
        }

        if ((GetContext().Status() & ParserStatus::CONSTRUCTOR_FUNCTION) != 0) {
            ThrowSyntaxError("A constructor cannot have a 'this' parameter");
        }

        if ((GetContext().Status() & ParserStatus::ARROW_FUNCTION) != 0) {
            ThrowSyntaxError("An arrow function cannot have a 'this' parameter");
        }

        if ((GetContext().Status() & ParserStatus::ACCESSOR_FUNCTION) != 0) {
            ThrowSyntaxError("'get' and 'set' accessors cannot declare 'this' parameters");
        }
    }

    if (param_name.Is("constructor") && ((GetContext().Status() & ParserStatus::CONSTRUCTOR_FUNCTION) != 0)) {
        ThrowSyntaxError("'constructor' cannot be used as a parameter property name");
    }
}

ArenaVector<ir::Expression *> TSParser::ParseFunctionParams()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    Lexer()->NextToken();

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    bool seen_optional = false;

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ArenaVector<ir::Decorator *> decorators(Allocator()->Adapter());

        ParseDecorators(decorators);

        if (!decorators.empty() && ((GetContext().Status() & ParserStatus::IN_CLASS_BODY) == 0)) {
            ThrowSyntaxError("Decorators are not valid here", decorators.front()->Start());
        }

        ir::Expression *parameter = ParseFunctionParameter();
        ValidateFunctionParam(params, parameter, &seen_optional);

        if (!decorators.empty()) {
            parameter->AddDecorators(std::move(decorators));
        }

        params.push_back(parameter);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COMMA &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError(", expected");
        }

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
            Lexer()->NextToken();
        }
    }

    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
    Lexer()->NextToken();

    return params;
}

ir::TSParameterProperty *TSParser::CreateParameterProperty(ir::Expression *parameter, ir::ModifierFlags modifiers)
{
    auto accessibility = ir::AccessibilityOption::NO_OPTS;
    bool readonly = false;
    bool is_static = false;
    bool is_export = false;

    if ((modifiers & ir::ModifierFlags::PRIVATE) != 0) {
        accessibility = ir::AccessibilityOption::PRIVATE;
    } else if ((modifiers & ir::ModifierFlags::PUBLIC) != 0) {
        accessibility = ir::AccessibilityOption::PUBLIC;
    } else if ((modifiers & ir::ModifierFlags::PROTECTED) != 0) {
        accessibility = ir::AccessibilityOption::PROTECTED;
    }

    if ((modifiers & ir::ModifierFlags::READONLY) != 0) {
        readonly = true;
    }

    if ((modifiers & ir::ModifierFlags::STATIC) != 0) {
        is_static = true;
    }

    // TODO(Csaba Repasi): Handle export property of TSParameterProperty

    return AllocNode<ir::TSParameterProperty>(accessibility, parameter, readonly, is_static, is_export);
}

ir::Expression *TSParser::ParseFunctionParameter()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_THIS) {
        Lexer()->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
    }

    lexer::SourcePosition parameter_start = Lexer()->GetToken().Start();
    ir::ModifierFlags modifiers = ParseModifiers();
    // TODO(Csaba Repasi): throw error if using strick mode reserved keyword here
    if (((GetContext().Status() & ParserStatus::CONSTRUCTOR_FUNCTION) == 0) && modifiers != ir::ModifierFlags::NONE) {
        ThrowSyntaxError("A parameter property is only allowed in a constructor implementation.", parameter_start);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        CheckRestrictedBinding();
    }

    ir::Expression *function_parameter = ParsePatternElement(ExpressionParseFlags::NO_OPTS, true);

    if (modifiers != ir::ModifierFlags::NONE && function_parameter->IsRestElement()) {
        ThrowSyntaxError("A parameter property cannot be declared using a rest parameter.", parameter_start);
    }

    if (modifiers != ir::ModifierFlags::NONE &&
        (function_parameter->IsArrayPattern() || function_parameter->IsObjectPattern() ||
         (function_parameter->IsAssignmentPattern() &&
          (function_parameter->AsAssignmentPattern()->Left()->IsArrayPattern() ||
           function_parameter->AsAssignmentPattern()->Left()->IsObjectPattern())))) {
        ThrowSyntaxError("A parameter property may not be declared using a binding pattern.", parameter_start);
    }

    if (modifiers != ir::ModifierFlags::NONE) {
        function_parameter = CreateParameterProperty(function_parameter, modifiers);
        function_parameter->SetRange(
            {parameter_start, function_parameter->AsTSParameterProperty()->Parameter()->End()});
    }

    Binder()->AddParamDecl(function_parameter);

    return function_parameter;
}

ir::TypeNode *TSParser::ParseClassKeyAnnotation()
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::BREAK_AT_NEW_LINE;
        return ParseTypeAnnotation(&options);
    }

    return nullptr;
}

void TSParser::ValidateClassMethodStart(ClassElementDescriptor *desc, ir::TypeNode *type_annotation)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS && desc->is_private_ident) {
        ThrowSyntaxError("A method cannot be named with a private identifier");
    }

    if (type_annotation == nullptr && (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
                                       Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN)) {
        if (((desc->modifiers & (ir::ModifierFlags::DECLARE | ir::ModifierFlags::READONLY)) != 0)) {
            ThrowSyntaxError("Class method can not be declare nor readonly");
        }
        desc->class_method = true;
    } else {
        if (((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) || desc->is_generator) {
            ThrowSyntaxError("Expected '('");
        }
        desc->class_field = true;

        if (desc->invalid_computed_property) {
            ThrowSyntaxError(
                "Computed property name must refer to a symbol or "
                "literal expression whose value is "
                "number or string");
        }
    }

    if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) {
        desc->new_status |= ParserStatus::ASYNC_FUNCTION;
    }

    if (desc->is_generator) {
        desc->new_status |= ParserStatus::GENERATOR_FUNCTION;
    }
}

ir::MethodDefinition *TSParser::ParseClassMethod(ClassElementDescriptor *desc,
                                                 const ArenaVector<ir::AstNode *> &properties,
                                                 ir::Expression *prop_name, lexer::SourcePosition *prop_end)
{
    if (desc->method_kind == ir::MethodDefinitionKind::SET || desc->method_kind == ir::MethodDefinitionKind::GET) {
        desc->new_status |= ParserStatus::ACCESSOR_FUNCTION;
    }

    desc->new_status |= ParserStatus::IN_METHOD_DEFINITION;

    if (InAmbientContext() && (desc->new_status & ParserStatus::ASYNC_FUNCTION) != 0) {
        ThrowSyntaxError("'async' modifier cannot be used in an ambient context.");
    }

    if (InAmbientContext() && desc->is_generator) {
        ThrowSyntaxError("Generators are not allowed in an ambient context.");
    }

    if (desc->method_kind != ir::MethodDefinitionKind::SET &&
        ((desc->new_status & ParserStatus::CONSTRUCTOR_FUNCTION) == 0)) {
        desc->new_status |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *func = ParseFunction(desc->new_status);

    if (func->IsOverload() && !desc->decorators.empty()) {
        ThrowSyntaxError("A decorator can only decorate a method implementation, not an overload.",
                         desc->decorators.front()->Start());
    }

    auto *func_expr = AllocNode<ir::FunctionExpression>(func);
    func_expr->SetRange(func->Range());

    if (desc->method_kind == ir::MethodDefinitionKind::SET) {
        ValidateClassSetter(desc, properties, prop_name, func);
    } else if (desc->method_kind == ir::MethodDefinitionKind::GET) {
        ValidateClassGetter(desc, properties, prop_name, func);
    }

    *prop_end = func->End();
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);
    auto *method = AllocNode<ir::MethodDefinition>(desc->method_kind, prop_name, func_expr, desc->modifiers,
                                                   Allocator(), desc->is_computed);
    method->SetRange(func_expr->Range());

    return method;
}

void TSParser::ValidateClassSetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                   ir::Expression *prop_name, ir::ScriptFunction *func)
{
    if (func->Params().size() != 1) {
        ThrowSyntaxError("Setter must have exactly one formal parameter");
    }

    if ((desc->modifiers & ir::ModifierFlags::STATIC) == 0) {
        ir::ModifierFlags access = GetAccessability(desc->modifiers);
        CheckAccessorPair(properties, prop_name, ir::MethodDefinitionKind::GET, access);
    }
}

void TSParser::ValidateClassGetter(ClassElementDescriptor *desc, const ArenaVector<ir::AstNode *> &properties,
                                   ir::Expression *prop_name, ir::ScriptFunction *func)
{
    if (!func->Params().empty()) {
        ThrowSyntaxError("Getter must not have formal parameters");
    }

    if ((desc->modifiers & ir::ModifierFlags::STATIC) == 0) {
        ir::ModifierFlags access = GetAccessability(desc->modifiers);

        CheckAccessorPair(properties, prop_name, ir::MethodDefinitionKind::SET, access);
    }
}

void TSParser::ValidateIndexSignatureTypeAnnotation(ir::TypeNode *type_annotation)
{
    if (type_annotation == nullptr) {
        ThrowSyntaxError("An index signature must have a type annotation");
    }
}

bool TSParser::IsModifierKind(const lexer::Token &token)
{
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_PUBLIC:
        case lexer::TokenType::KEYW_PRIVATE:
        case lexer::TokenType::KEYW_PROTECTED:
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ASYNC:
        case lexer::TokenType::KEYW_ABSTRACT:
        case lexer::TokenType::KEYW_DECLARE:
        case lexer::TokenType::KEYW_READONLY:
            return true;
        default:
            break;
    }

    return false;
}

void TSParser::CheckIfTypeParameterNameIsReserved()
{
    if (Lexer()->GetToken().IsReservedTypeName()) {
        ThrowSyntaxError("Invalid type parameter name");
    }
}

void TSParser::ThrowErrorIfStaticConstructor(ir::ModifierFlags flags)
{
    if ((flags & ir::ModifierFlags::STATIC) != 0) {
        ThrowSyntaxError("Static modifier can not appear on a constructor");
    }
}

std::tuple<bool, bool, bool> TSParser::ParseComputedClassFieldOrIndexSignature(ir::Expression **prop_name)
{
    Lexer()->NextToken();  // eat left square bracket

    if (Lexer()->GetToken().Type() == lexer::TokenType::LITERAL_IDENT &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_COLON) {
        auto id = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        id->SetRange(Lexer()->GetToken().Loc());

        Lexer()->NextToken();  // eat param

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_COLON) {
            ThrowSyntaxError("':' expected");
        }

        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        ir::TypeNode *type_annotation = ParseTypeAnnotation(&options);

        if (!type_annotation->IsTSNumberKeyword() && !type_annotation->IsTSStringKeyword()) {
            ThrowSyntaxError(
                "An index signature parameter type must be either "
                "'string' or 'number'");
        }

        id->SetTsTypeAnnotation(type_annotation);

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
            ThrowSyntaxError("']' expected");
        }

        *prop_name = id;
        Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        return {false, false, true};
    }

    *prop_name = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    bool invalid_computed_property =
        !(*prop_name)->IsNumberLiteral() && !(*prop_name)->IsStringLiteral() &&
        !((*prop_name)->IsMemberExpression() && (*prop_name)->AsMemberExpression()->Object()->IsIdentifier() &&
          (*prop_name)->AsMemberExpression()->Object()->AsIdentifier()->Name().Is("Symbol"));

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        ThrowSyntaxError("Unexpected token, expected ']'");
    }

    return {true, invalid_computed_property, false};
}

ir::TypeNode *TSParser::ParseFunctionReturnType([[maybe_unused]] ParserStatus status)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options =
            TypeAnnotationParsingOptions::THROW_ERROR | TypeAnnotationParsingOptions::CAN_BE_TS_TYPE_PREDICATE;
        return ParseTypeAnnotation(&options);
    }

    return nullptr;
}

void TSParser::ValidateFunctionOverloadParams(const ArenaVector<ir::Expression *> &params)
{
    for (auto *it : params) {
        if (it->IsAssignmentPattern()) {
            ThrowSyntaxError(
                "A parameter initializer is only allowed in a function "
                "or constructor implementation.",
                it->Start());
        }
    }
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> TSParser::ParseFunctionBody(
    const ArenaVector<ir::Expression *> &params, ParserStatus new_status, ParserStatus context_status,
    binder::FunctionScope *func_scope)
{
    bool is_declare = InAmbientContext();
    bool is_overload = false;
    bool let_declare = true;
    ir::BlockStatement *body = nullptr;
    lexer::SourcePosition end_loc = Lexer()->GetToken().End();

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        if ((new_status & ParserStatus::FUNCTION_DECLARATION) != 0) {
            ValidateFunctionOverloadParams(params);
        } else if (!is_declare && ((context_status & ParserStatus::IN_METHOD_DEFINITION) == 0)) {
            ThrowSyntaxError("Unexpected token, expected '{'");
        } else {
            let_declare = false;
        }

        is_overload = true;
    } else if (is_declare) {
        ThrowSyntaxError("An implementation cannot be declared in ambient contexts.");
    } else {
        body = ParseBlockStatement(func_scope);
        end_loc = body->End();
    }

    return {let_declare, body, end_loc, is_overload};
}

ir::Expression *TSParser::ParseModuleReference()
{
    ir::Expression *result = nullptr;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_REQUIRE &&
        Lexer()->Lookahead() == lexer::LEX_CHAR_LEFT_PAREN) {
        lexer::SourcePosition start = Lexer()->GetToken().Start();
        Lexer()->NextToken();  // eat 'require'
        Lexer()->NextToken();  // eat '('

        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
            ThrowSyntaxError("String literal expected.");
        }

        result = AllocNode<ir::StringLiteral>(Lexer()->GetToken().String());
        result->SetRange(Lexer()->GetToken().Loc());
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            ThrowSyntaxError("')' expected.");
        }

        result = AllocNode<ir::TSExternalModuleReference>(result);
        result->SetRange({start, Lexer()->GetToken().End()});
        Lexer()->NextToken();  // eat ')'
    } else {
        result = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
        result->SetRange(Lexer()->GetToken().Loc());
        Lexer()->NextToken();

        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD) {
            result = ParseQualifiedReference(result);
        }
    }

    return result;
}

ir::AstNode *TSParser::ParseImportDefaultSpecifier(ArenaVector<ir::AstNode *> *specifiers)
{
    ir::Identifier *local = ParseNamedImport(Lexer()->GetToken());
    Lexer()->NextToken();  // eat local name

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        Lexer()->NextToken();  // eat substitution
        if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
            ThrowSyntaxError("identifier expected");
        }

        auto *import_equals_decl = AllocNode<ir::TSImportEqualsDeclaration>(local, ParseModuleReference(), false);

        return import_equals_decl;
    }

    auto *specifier = AllocNode<ir::ImportDefaultSpecifier>(local);
    specifier->SetRange(specifier->Local()->Range());
    specifiers->push_back(specifier);

    Binder()->AddDecl<binder::ImportDecl>(local->Start(), "default", local->Name(), specifier);

    Lexer()->NextToken();  // eat specifier name

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
        Lexer()->NextToken();  // eat comma
    }

    return nullptr;
}

ir::TSImportEqualsDeclaration *TSParser::ParseTsImportEqualsDeclaration(const lexer::SourcePosition &start_loc,
                                                                        bool is_export)
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::KEYW_IMPORT);
    Lexer()->NextToken();
    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("Unexpected token");
    }

    auto *id = AllocNode<ir::Identifier>(Lexer()->GetToken().Ident(), Allocator());
    id->SetRange(Lexer()->GetToken().Loc());
    Lexer()->NextToken();  // eat id name

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("'=' expected");
    }
    Lexer()->NextToken();  // eat substitution

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        ThrowSyntaxError("identifier expected");
    }

    auto *import_equals_decl = AllocNode<ir::TSImportEqualsDeclaration>(id, ParseModuleReference(), is_export);
    import_equals_decl->SetRange({start_loc, Lexer()->GetToken().End()});

    ConsumeSemicolon(import_equals_decl);

    return import_equals_decl;
}

ir::Statement *TSParser::ParseExportDeclaration(StatementParsingFlags flags)
{
    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat `export` keyword

    switch (Lexer()->GetToken().Type()) {
        case lexer::TokenType::KEYW_DEFAULT: {
            return ParseExportDefaultDeclaration(start_loc);
        }
        case lexer::TokenType::PUNCTUATOR_MULTIPLY: {
            return ParseExportAllDeclaration(start_loc);
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_BRACE: {
            return ParseExportNamedSpecifiers(start_loc);
        }
        case lexer::TokenType::KEYW_IMPORT: {
            return ParseTsImportEqualsDeclaration(start_loc, true);
        }
        case lexer::TokenType::PUNCTUATOR_SUBSTITUTION: {
            return ParseExportDefaultDeclaration(start_loc, true);
        }
        default: {
            ir::ExportNamedDeclaration *export_decl = ParseNamedExportDeclaration(start_loc);

            if (export_decl->Decl()->IsVariableDeclaration() && ((flags & StatementParsingFlags::GLOBAL) == 0) &&
                export_decl->Parent() != nullptr && !export_decl->Parent()->IsTSModuleBlock() &&
                !GetContext().IsModule()) {
                ThrowSyntaxError("Modifiers cannot appear here'");
            }

            return export_decl;
        }
    }
}

ir::Expression *TSParser::ParseCoverParenthesizedExpressionAndArrowParameterList()
{
    ASSERT(Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    lexer::SourcePosition start = Lexer()->GetToken().Start();
    Lexer()->NextToken();
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        ir::SpreadElement *rest_element = ParseSpreadElement(ExpressionParseFlags::MUST_BE_PATTERN);

        rest_element->SetGrouped();
        rest_element->SetStart(start);

        ValidateArrowFunctionRestParameter(rest_element);

        Lexer()->NextToken();

        ir::TypeNode *return_type_annotation = nullptr;
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
            Lexer()->NextToken();  // eat ':'
            return_type_annotation = ParseTypeAnnotation(&options);
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        return ParseArrowFunctionExpression(rest_element, nullptr, return_type_annotation, false);
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        Lexer()->NextToken();

        ir::TypeNode *return_type_annotation = nullptr;
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
            Lexer()->NextToken();  // eat ':'
            return_type_annotation = ParseTypeAnnotation(&options);
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            ThrowSyntaxError("Unexpected token");
        }

        auto *arrow_expr = ParseArrowFunctionExpression(nullptr, nullptr, return_type_annotation, false);
        arrow_expr->SetStart(start);
        arrow_expr->AsArrowFunctionExpression()->Function()->SetStart(start);

        return arrow_expr;
    }

    ir::Expression *expr = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA | ExpressionParseFlags::ACCEPT_REST |
                                           ExpressionParseFlags::POTENTIALLY_IN_PATTERN);

    if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
        ThrowSyntaxError("Unexpected token, expected ')'");
    }

    expr->SetGrouped();
    expr->SetRange({start, Lexer()->GetToken().End()});
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        auto saved_pos = Lexer()->Save();
        Lexer()->NextToken();  // eat ':'
        options = TypeAnnotationParsingOptions::NO_OPTS;
        ir::TypeNode *return_type_annotation = ParseTypeAnnotation(&options);

        if (return_type_annotation == nullptr) {
            Lexer()->Rewind(saved_pos);
            return expr;
        }

        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_ARROW) {
            Lexer()->Rewind(saved_pos);
            return expr;
        }

        return ParseArrowFunctionExpression(expr, nullptr, return_type_annotation, false);
    }

    return expr;
}

ir::Statement *TSParser::ParseConstStatement(StatementParsingFlags flags)
{
    lexer::SourcePosition const_var_star = Lexer()->GetToken().Start();
    Lexer()->NextToken();

    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_ENUM) {
        return ParseEnumDeclaration(true);
    }

    if ((flags & StatementParsingFlags::ALLOW_LEXICAL) == 0) {
        ThrowSyntaxError("Lexical declaration is not allowed in single statement context");
    }

    auto *variable_decl =
        ParseVariableDeclaration(VariableParsingFlags::CONST | VariableParsingFlags::NO_SKIP_VAR_KIND);
    variable_decl->SetStart(const_var_star);
    ConsumeSemicolon(variable_decl);

    return variable_decl;
}

ir::Statement *TSParser::ParsePotentialConstEnum(VariableParsingFlags flags)
{
    if ((flags & VariableParsingFlags::CONST) == 0) {
        ThrowSyntaxError("Variable declaration expected.");
    }

    return ParseEnumDeclaration(true);
}

void TSParser::ParseCatchParamTypeAnnotation([[maybe_unused]] ir::AnnotatedExpression *param)
{
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'

        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        param->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    }

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        ThrowSyntaxError("Catch clause variable cannot have an initializer");
    }
}

ir::AnnotatedExpression *TSParser::ParseVariableDeclaratorKey(VariableParsingFlags flags)
{
    ir::AnnotatedExpression *init = ParserImpl::ParseVariableDeclaratorKey(flags);

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::THROW_ERROR;
        init->SetTsTypeAnnotation(ParseTypeAnnotation(&options));
    }

    return init;
}

void TSParser::ThrowPossibleOutOfBoundaryJumpError(bool allow_break)
{
    if (((GetContext().Status() & ParserStatus::FUNCTION) != 0) && !allow_break) {
        ThrowSyntaxError("Jump target cannot cross function boundary");
    }
}

void TSParser::ThrowIllegalBreakError()
{
    ThrowSyntaxError("A 'break' statement can only be used within an enclosing iteration or switch statement");
}

void TSParser::ThrowIllegalContinueError()
{
    ThrowSyntaxError("A 'continue' statement can only be used within an enclosing iteration statement");
}

void TSParser::ThrowMultipleDefaultError()
{
    ThrowSyntaxError("A 'default' clause cannot appear more than once in a 'switch' statement");
}

void TSParser::ThrowIllegalNewLineErrorAfterThrow()
{
    ThrowSyntaxError("Line break not permitted here");
}

void TSParser::ThrowIfBodyEmptyError(ir::Statement *consequent)
{
    if (consequent->IsEmptyStatement()) {
        ThrowSyntaxError("The body of an if statement cannot be the empty statement");
    }
}

void TSParser::CreateFunctionDeclaration(ir::Identifier *ident_node, util::StringView &name, ir::ScriptFunction *func,
                                         const lexer::SourcePosition &start_loc)
{
    const auto &bindings = Binder()->GetScope()->Bindings();
    auto res = bindings.find(name);
    binder::FunctionDecl *decl {};

    if (res == bindings.end()) {
        decl = Binder()->AddDecl<binder::FunctionDecl>(ident_node->Start(), Allocator(), name, func);
    } else {
        binder::Decl *current_decl = res->second->Declaration();

        if (!current_decl->IsFunctionDecl()) {
            Binder()->ThrowRedeclaration(start_loc, current_decl->Name());
        }

        decl = current_decl->AsFunctionDecl();
        if (!decl->Node()->AsScriptFunction()->IsOverload()) {
            Binder()->ThrowRedeclaration(start_loc, current_decl->Name());
        }
    }

    decl->Add(func);
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ExportDefaultDeclaration *TSParser::ParseExportDefaultDeclaration(const lexer::SourcePosition &start_loc,
                                                                      bool is_export_equals)
{
    Lexer()->NextToken();  // eat `default` keyword or `=`

    ir::AstNode *decl_node = nullptr;
    bool eat_semicolon = false;

    ExportDeclarationContext export_decl_ctx(Binder());

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_FUNCTION: {
            decl_node = ParseFunctionDeclaration(true);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            decl_node = ParseClassDeclaration(ir::ClassDefinitionModifiers::ID_REQUIRED);
            break;
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            decl_node = ParseInterfaceDeclaration(false);
            break;
        }
        case lexer::TokenType::KEYW_ASYNC: {
            if ((Lexer()->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) == 0) {
                Lexer()->NextToken();  // eat `async`
                decl_node = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
                break;
            }
            [[fallthrough]];
        }
        default: {
            decl_node = ParseExpression();
            eat_semicolon = true;
            break;
        }
    }

    lexer::SourcePosition end_loc = decl_node->End();
    auto *export_declaration = AllocNode<ir::ExportDefaultDeclaration>(decl_node, is_export_equals);
    export_declaration->SetRange({start_loc, end_loc});

    if (eat_semicolon) {
        ConsumeSemicolon(export_declaration);
    }

    return export_declaration;
}

ir::ExportNamedDeclaration *TSParser::ParseNamedExportDeclaration(const lexer::SourcePosition &start_loc)
{
    ir::Statement *decl = nullptr;

    ir::ClassDefinitionModifiers class_modifiers = ir::ClassDefinitionModifiers::ID_REQUIRED;
    ir::ModifierFlags flags = ir::ModifierFlags::NONE;

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_DECLARE) {
        CheckDeclare();
    }

    if (Lexer()->GetToken().KeywordType() == lexer::TokenType::KEYW_ABSTRACT) {
        Lexer()->NextToken();  // eat 'abstract'
        flags |= ir::ModifierFlags::ABSTRACT;
    }

    ExportDeclarationContext export_decl_ctx(Binder());

    switch (Lexer()->GetToken().KeywordType()) {
        case lexer::TokenType::KEYW_VAR: {
            decl = ParseVariableDeclaration(VariableParsingFlags::VAR);
            break;
        }
        case lexer::TokenType::KEYW_CONST: {
            decl = ParseVariableDeclaration(VariableParsingFlags::CONST);
            break;
        }
        case lexer::TokenType::KEYW_LET: {
            decl = ParseVariableDeclaration(VariableParsingFlags::LET);
            break;
        }
        case lexer::TokenType::KEYW_FUNCTION: {
            decl = ParseFunctionDeclaration(false, ParserStatus::NO_OPTS);
            break;
        }
        case lexer::TokenType::KEYW_CLASS: {
            decl = ParseClassDeclaration(class_modifiers, flags);
            break;
        }
        case lexer::TokenType::KEYW_ENUM: {
            decl = ParseEnumDeclaration();
            break;
        }
        case lexer::TokenType::KEYW_INTERFACE: {
            decl = ParseInterfaceDeclaration(false);
            break;
        }
        case lexer::TokenType::KEYW_TYPE: {
            decl = ParseTypeAliasDeclaration();
            break;
        }
        case lexer::TokenType::KEYW_GLOBAL:
        case lexer::TokenType::KEYW_MODULE:
        case lexer::TokenType::KEYW_NAMESPACE: {
            decl = ParseModuleDeclaration();
            break;
        }
        default: {
            if (!Lexer()->GetToken().IsAsyncModifier()) {
                ThrowSyntaxError("Unexpected token");
            }

            Lexer()->NextToken();  // eat `async` keyword
            decl = ParseFunctionDeclaration(false, ParserStatus::ASYNC_FUNCTION);
        }
    }

    if (decl->IsVariableDeclaration()) {
        ConsumeSemicolon(decl);
    }

    lexer::SourcePosition end_loc = decl->End();
    ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
    auto *export_declaration = AllocNode<ir::ExportNamedDeclaration>(Allocator(), decl, std::move(specifiers));
    export_declaration->SetRange({start_loc, end_loc});

    return export_declaration;
}

ir::Statement *TSParser::ParseImportDeclaration([[maybe_unused]] StatementParsingFlags flags)
{
    ImportDeclarationContext import_ctx(Binder());

    char32_t next_char = Lexer()->Lookahead();
    if (next_char == lexer::LEX_CHAR_LEFT_PAREN || next_char == lexer::LEX_CHAR_DOT) {
        return ParseExpressionStatement();
    }

    lexer::SourcePosition start_loc = Lexer()->GetToken().Start();
    Lexer()->NextToken();  // eat import

    ArenaVector<ir::AstNode *> specifiers(Allocator()->Adapter());

    ir::StringLiteral *source = nullptr;

    if (Lexer()->GetToken().Type() != lexer::TokenType::LITERAL_STRING) {
        ir::AstNode *ast_node = ParseImportSpecifiers(&specifiers);
        if (ast_node != nullptr) {
            ASSERT(ast_node->IsTSImportEqualsDeclaration());
            ast_node->SetRange({start_loc, Lexer()->GetToken().End()});
            ConsumeSemicolon(ast_node->AsTSImportEqualsDeclaration());
            return ast_node->AsTSImportEqualsDeclaration();
        }
        source = ParseFromClause(true);
    } else {
        source = ParseFromClause(false);
    }

    lexer::SourcePosition end_loc = source->End();
    auto *import_declaration = AllocNode<ir::ImportDeclaration>(source, std::move(specifiers));
    import_declaration->SetRange({start_loc, end_loc});

    ConsumeSemicolon(import_declaration);

    return import_declaration;
}

}  // namespace panda::es2panda::parser
