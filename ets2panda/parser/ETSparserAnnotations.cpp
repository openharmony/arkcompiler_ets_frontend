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
#include <utility>
#include "parser/parserStatusContext.h"
#include "util/language.h"
#include "utils/arena_containers.h"
#include "lexer/lexer.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/spreadElement.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/dummyNode.h"
#include "ir/ets/etsTuple.h"
#include "ir/ets/etsTypeReference.h"
#include "ir/ets/etsTypeReferencePart.h"
#include "ir/ets/etsParameterExpression.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "generated/signatures.h"

namespace ark::es2panda::parser {

ir::Statement *ETSParser::ParseTopLevelAnnotation(ir::ModifierFlags memberModifiers)
{
    ir::Statement *result = nullptr;

    Lexer()->NextToken();  // eat '@'
    if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
        result = ParseAnnotationDeclaration(memberModifiers);
    } else {
        auto annotations = ParseAnnotations(true);
        auto savePos = Lexer()->GetToken().Start();
        result = ParseTopLevelStatement();
        if (result != nullptr) {
            ApplyAnnotationsToNode(result, std::move(annotations), savePos);
        } else {
            LogSyntaxError("Annotations cannot be applied here!");
        }
    }

    return result;
}

template <bool IS_USAGE>
ir::Expression *ETSParser::ParseAnnotationName()
{
    ir::Expression *expr = nullptr;

    auto setAnnotation = [](ir::Identifier *ident) {
        if constexpr (IS_USAGE) {
            ident->SetAnnotationUsage();
        } else {
            ident->SetAnnotationDecl();
        }
    };
    auto save = Lexer()->Save();
    Lexer()->NextToken();
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD) {
        Lexer()->Rewind(save);
        expr = ExpectIdentifier();
        setAnnotation(expr->AsIdentifier());
        return expr;
    }
    Lexer()->Rewind(save);
    if (Lexer()->Lookahead() == '.') {
        auto opt = TypeAnnotationParsingOptions::NO_OPTS;
        expr = ParseTypeReference(&opt);
        setAnnotation(expr->AsETSTypeReference()->Part()->Name()->AsTSQualifiedName()->Right());
    } else {
        expr = ExpectIdentifier();
        setAnnotation(expr->AsIdentifier());
    }

    return expr;
}

ir::AnnotationDeclaration *ETSParser::ParseAnnotationDeclaration(ir::ModifierFlags flags)
{
    const lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    // The default modifier of the annotation is public abstract
    flags |= ir::ModifierFlags::ABSTRACT | ir::ModifierFlags::PUBLIC | ir::ModifierFlags::ANNOTATION_DECLARATION;
    flags &= ~ir::ModifierFlags::STATIC;
    if (InAmbientContext()) {
        flags |= ir::ModifierFlags::DECLARE;
    }
    Lexer()->NextToken();
    ir::Expression *expr = ParseAnnotationName<false>();

    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE, false);
    auto properties = ParseAnnotationProperties(flags);

    lexer::SourcePosition endLoc = Lexer()->GetToken().End();

    auto *annotationDecl = AllocNode<ir::AnnotationDeclaration>(expr, std::move(properties));
    annotationDecl->SetRange({startLoc, endLoc});
    annotationDecl->AddModifier(flags);
    return annotationDecl;
}

static bool IsMemberAccessModifiers(lexer::TokenType type)
{
    return type == lexer::TokenType::KEYW_STATIC || type == lexer::TokenType::KEYW_ASYNC ||
           type == lexer::TokenType::KEYW_PUBLIC || type == lexer::TokenType::KEYW_PROTECTED ||
           type == lexer::TokenType::KEYW_PRIVATE || type == lexer::TokenType::KEYW_DECLARE ||
           type == lexer::TokenType::KEYW_READONLY || type == lexer::TokenType::KEYW_ABSTRACT ||
           type == lexer::TokenType::KEYW_CONST || type == lexer::TokenType::KEYW_FINAL ||
           type == lexer::TokenType::KEYW_NATIVE;
}

ArenaVector<ir::AstNode *> ETSParser::ParseAnnotationProperties(ir::ModifierFlags memberModifiers)
{
    Lexer()->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    while (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        if ((memberModifiers & ir::ModifierFlags::ANNOTATION_DECLARATION) != 0U &&
            Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
            Lexer()->NextToken();  // eat ';'
            continue;
        }
        // check no modifiers
        while (IsMemberAccessModifiers(Lexer()->GetToken().Type())) {
            LogSyntaxError("Annotation property can not have access modifiers", Lexer()->GetToken().Start());
            Lexer()->NextToken();
        }
        auto *fieldName = ExpectIdentifier();
        if (fieldName == nullptr) {
            LogSyntaxError("Unexpected token.");
        } else {
            bool needTypeAnnotation = (memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) == 0U;
            ir::AstNode *property = ParseAnnotationProperty(fieldName, memberModifiers, needTypeAnnotation);
            properties.push_back(property);
        }
        if ((memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) != 0U &&
            Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            ExpectToken(lexer::TokenType::PUNCTUATOR_COMMA);  // eat ','
        }
    }

    Lexer()->NextToken();  // eat "}"
    return properties;
}

bool ETSParser::ValidAnnotationValue(ir::Expression *initializer)
{
    if (initializer->IsArrayExpression()) {
        for (auto *element : initializer->AsArrayExpression()->Elements()) {
            if (!ValidAnnotationValue(element)) {
                return false;
            }
        }
        return true;
    }
    return initializer->IsStringLiteral() || initializer->IsNumberLiteral() || initializer->IsMemberExpression() ||
           initializer->IsBooleanLiteral() || initializer->IsBinaryExpression() || initializer->IsUnaryExpression() ||
           initializer->IsConditionalExpression() || initializer->IsIdentifier() || initializer->IsTSAsExpression();
}

ir::AstNode *ETSParser::ParseAnnotationProperty(ir::Identifier *fieldName, ir::ModifierFlags memberModifiers,
                                                bool needTypeAnnotation)
{
    lexer::SourcePosition endLoc = fieldName->End();
    // check no methods
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS ||
        Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LESS_THAN) {
        LogSyntaxError("Annotation can not have method as property", Lexer()->GetToken().Start());
    }

    ir::TypeNode *typeAnnotation = nullptr;
    TypeAnnotationParsingOptions options = TypeAnnotationParsingOptions::REPORT_ERROR;
    if (needTypeAnnotation && Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON) {
        Lexer()->NextToken();  // eat ':'
        typeAnnotation = ParseTypeAnnotation(&options);
    }

    if (typeAnnotation == nullptr && (memberModifiers & ir::ModifierFlags::ANNOTATION_DECLARATION) != 0) {
        auto nameField = fieldName->Name().Mutf8();
        auto logField = !fieldName->IsErrorPlaceHolder() ? " '" + nameField + "'." : ".";
        LogSyntaxError("Missing type annotation for property" + logField, Lexer()->GetToken().Start());
    }

    if (typeAnnotation != nullptr) {
        endLoc = typeAnnotation->End();
    }

    ir::Expression *initializer = nullptr;
    lexer::SourcePosition savePos;
    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION ||
        (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COLON)) {
        Lexer()->NextToken();  // eat '=' or ':'
        savePos = Lexer()->GetToken().Start();
        initializer = ParseExpression();
    }

    if (initializer == nullptr && (memberModifiers & ir::ModifierFlags::ANNOTATION_USAGE) != 0) {
        LogSyntaxError("Invalid argument passed to '" + fieldName->Name().Mutf8() + "'", Lexer()->GetToken().Start());
    }

    if (initializer != nullptr && !ValidAnnotationValue(initializer)) {
        LogSyntaxError("Invalid value for annotation field, expected a constant literal.", savePos);
    }

    memberModifiers |= ir::ModifierFlags::PUBLIC;
    memberModifiers |= ir::ModifierFlags::ABSTRACT;
    auto *field =
        AllocNode<ir::ClassProperty>(fieldName, initializer, typeAnnotation, memberModifiers, Allocator(), false);
    field->SetRange({fieldName->Start(), initializer != nullptr ? initializer->End() : endLoc});
    return field;
}

ArenaVector<ir::AnnotationUsage *> ETSParser::ParseAnnotations(bool isTopLevelSt)
{
    ArenaVector<ir::AnnotationUsage *> annotations(Allocator()->Adapter());
    bool hasMoreAnnotations = true;
    while (hasMoreAnnotations) {
        if (Lexer()->GetToken().Type() == lexer::TokenType::KEYW_INTERFACE) {
            if (!annotations.empty()) {
                LogSyntaxError("Annotations cannot be applied to an annotation declaration.");
            }

            if (!isTopLevelSt) {
                LogSyntaxError("Annotations can only be declared at the top level.");
            }

            // For now we don't support use Annotation before AnnotationDecl,
            // program will only reach here after LogSyntaxError
            return annotations;
        }

        annotations.emplace_back(ParseAnnotationUsage());
        if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_AT) {
            hasMoreAnnotations = false;
        } else {
            Lexer()->NextToken();
        }
    }
    return annotations;
}

static bool ApplyAnnotationsToNamespace(ir::ETSModule *ns, ArenaVector<ir::AnnotationUsage *> &annotations)
{
    if (ns->IsNamespaceChainLastNode()) {
        ns->SetAnnotations(std::move(annotations));
        return true;
    }

    for (auto *node : ns->Statements()) {
        if (node->IsETSModule()) {
            if (ApplyAnnotationsToNamespace(node->AsETSModule(), annotations)) {
                return true;
            }
        }
    }
    return false;
}

void ETSParser::ApplyAnnotationsToNode(ir::AstNode *node, ArenaVector<ir::AnnotationUsage *> &&annotations,
                                       lexer::SourcePosition pos)
{
    if (!annotations.empty()) {
        if (node->IsAbstract() ||
            (node->IsClassDeclaration() && node->AsClassDeclaration()->Definition()->IsAbstract())) {
            LogSyntaxError("Annotations are not allowed on an abstract class or methods.", pos);
        }
        if (node->IsExpressionStatement()) {
            ApplyAnnotationsToNode(node->AsExpressionStatement()->GetExpression(), std::move(annotations), pos);
            return;
        }

        switch (node->Type()) {
            case ir::AstNodeType::METHOD_DEFINITION:
                node->AsMethodDefinition()->Function()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::CLASS_DECLARATION:
                node->AsClassDeclaration()->Definition()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::FUNCTION_DECLARATION:
                node->AsFunctionDeclaration()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::TS_INTERFACE_DECLARATION:
                node->AsTSInterfaceDeclaration()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::CLASS_PROPERTY:
                node->AsClassProperty()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::VARIABLE_DECLARATION:
                node->AsVariableDeclaration()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
                node->AsTSTypeAliasDeclaration()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::ETS_PARAMETER_EXPRESSION:
                node->AsETSParameterExpression()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::ARROW_FUNCTION_EXPRESSION:
                node->AsArrowFunctionExpression()->SetAnnotations(std::move(annotations));
                break;
            case ir::AstNodeType::ETS_MODULE:
                ApplyAnnotationsToNamespace(node->AsETSModule(), annotations);
                break;
            default:
                LogSyntaxError("Annotations are not allowed on this type of declaration.", pos);
        }
    }
}

ir::AnnotationUsage *ETSParser::ParseAnnotationUsage()
{
    const lexer::SourcePosition startLoc = Lexer()->GetToken().Start();
    ir::Expression *expr = ParseAnnotationName<true>();

    auto flags = ir::ModifierFlags::ANNOTATION_USAGE;
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS &&
        !IsArrowFunctionExpressionStart()) {
        Lexer()->NextToken();  // eat '('
        if (Lexer()->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
            properties = ParseAnnotationProperties(flags);
        } else if (Lexer()->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            // handle single field annotation
            auto *singleParamName = AllocNode<ir::Identifier>(compiler::Signatures::ANNOTATION_KEY_VALUE, Allocator());
            singleParamName->SetRange({Lexer()->GetToken().Start(), Lexer()->GetToken().End()});

            const auto savePos = Lexer()->GetToken().Start();
            auto *initializer = ParseExpression();
            if (initializer != nullptr && !ValidAnnotationValue(initializer)) {
                LogSyntaxError("Invalid value for annotation field, expected a constant literal.", savePos);
            }

            auto *singleParam = AllocNode<ir::ClassProperty>(singleParamName, initializer, nullptr,
                                                             ir::ModifierFlags::ANNOTATION_USAGE, Allocator(), false);
            singleParam->SetRange(
                {singleParamName->Start(), initializer != nullptr ? initializer->End() : singleParamName->End()});
            properties.push_back(singleParam);
        }
        ExpectToken(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS, true);  // eat ')'
    }

    auto *annotationUsage = AllocNode<ir::AnnotationUsage>(expr, std::move(properties));
    annotationUsage->AddModifier(flags);
    annotationUsage->SetRange({startLoc, Lexer()->GetToken().End()});
    return annotationUsage;
}

}  // namespace ark::es2panda::parser
