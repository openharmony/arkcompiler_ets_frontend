/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "parserImpl.h"
#include "parserStatusContext.h"

#include "varbinder/privateBinding.h"
#include "ir/astNode.h"
#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/classStaticBlock.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/base/spreadElement.h"
#include "ir/expression.h"
#include "ir/expressions/arrayExpression.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/superExpression.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/module/exportSpecifier.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/functionDeclaration.h"
#include "lexer/lexer.h"
#include "lexer/token/letters.h"
#include "lexer/token/sourceLocation.h"
#include "parser/ETSparser.h"
#include "util/errorRecovery.h"

using namespace std::literals::string_literals;

namespace ark::es2panda::parser {
ParserImpl::ParserImpl(Program *program, const CompilerOptions &options, ParserStatus status)
    : program_(program), context_(program_, status), options_(options)
{
}

std::unique_ptr<lexer::Lexer> ParserImpl::InitLexer(const SourceFile &sourceFile)
{
    program_->SetSource(sourceFile);
    std::unique_ptr<lexer::Lexer> lexer = std::make_unique<lexer::Lexer>(&context_, &errorLogger_);
    lexer_ = lexer.get();
    return lexer;
}

void ParserImpl::ParseScript(const SourceFile &sourceFile, bool genStdLib)
{
    auto lexer = InitLexer(sourceFile);

    if (sourceFile.isModule) {
        context_.Status() |= (ParserStatus::MODULE);
        ParseProgram(ScriptKind::MODULE);
    } else if (genStdLib) {
        ParseProgram(ScriptKind::STDLIB);
    } else {
        ParseProgram(ScriptKind::SCRIPT);
    }
}

void ParserImpl::ParseProgram(ScriptKind kind)
{
    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    lexer_->NextToken();
    program_->SetKind(kind);

    auto statements = ParseStatementList(StatementParsingFlags::STMT_GLOBAL_LEXICAL);

    auto *blockStmt = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    blockStmt->SetRange({startLoc, lexer_->GetToken().End()});

    program_->SetAst(blockStmt);
    program_->SetDeclarationModuleInfo();
}

bool ParserImpl::InAmbientContext()
{
    return (context_.Status() & ParserStatus::IN_AMBIENT_CONTEXT) != 0;
}

ExpressionParseFlags ParserImpl::CarryExpressionParserFlag(ExpressionParseFlags origin, ExpressionParseFlags carry)
{
    return static_cast<ExpressionParseFlags>(origin & carry);
}

ExpressionParseFlags ParserImpl::CarryPatternFlags(ExpressionParseFlags flags)
{
    return CarryExpressionParserFlag(flags, ExpressionParseFlags::POTENTIALLY_IN_PATTERN |
                                                ExpressionParseFlags::OBJECT_PATTERN);
}

ir::ModifierFlags ParserImpl::GetAccessability(ir::ModifierFlags modifiers)
{
    if ((modifiers & ir::ModifierFlags::PUBLIC) != 0) {
        return ir::ModifierFlags::PUBLIC;
    }

    if ((modifiers & ir::ModifierFlags::PRIVATE) != 0) {
        return ir::ModifierFlags::PRIVATE;
    }

    if ((modifiers & ir::ModifierFlags::PROTECTED) != 0) {
        return ir::ModifierFlags::PROTECTED;
    }

    if ((modifiers & ir::ModifierFlags::INTERNAL) != 0) {
        return ir::ModifierFlags::INTERNAL;
    }

    return ir::ModifierFlags::NONE;
}

bool ParserImpl::IsModifierKind(const lexer::Token &token)
{
    switch (token.KeywordType()) {
        case lexer::TokenType::KEYW_STATIC:
        case lexer::TokenType::KEYW_ASYNC:
            return true;
        default:
            break;
    }

    return false;
}

ir::ModifierFlags ParserImpl::ParseModifiers()
{
    ir::ModifierFlags resultStatus = ir::ModifierFlags::NONE;
    ir::ModifierFlags prevStatus = ir::ModifierFlags::ALL;

    while (IsModifierKind(lexer_->GetToken())) {
        char32_t nextCp = lexer_->Lookahead();
        if (nextCp == lexer::LEX_CHAR_LEFT_PAREN) {
            return resultStatus;
        }

        lexer::TokenFlags tokenFlags = lexer_->GetToken().Flags();
        if ((tokenFlags & lexer::TokenFlags::HAS_ESCAPE) != 0) {
            LogSyntaxError("Keyword must not contain escaped characters");
        }

        ir::ModifierFlags actualStatus = ir::ModifierFlags::NONE;
        ir::ModifierFlags nextStatus = ir::ModifierFlags::NONE;

        switch (lexer_->GetToken().KeywordType()) {
            case lexer::TokenType::KEYW_STATIC: {
                actualStatus = ir::ModifierFlags::STATIC;
                nextStatus = ir::ModifierFlags::ASYNC;
                break;
            }
            case lexer::TokenType::KEYW_ASYNC: {
                actualStatus = ir::ModifierFlags::ASYNC;
                nextStatus = ir::ModifierFlags::NONE;
                break;
            }
            default: {
                break;
            }
        }

        if (lexer_->Lookahead() == lexer::LEX_CHAR_COLON || lexer_->Lookahead() == lexer::LEX_CHAR_COMMA ||
            lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_PAREN || lexer_->Lookahead() == lexer::LEX_CHAR_QUESTION ||
            lexer_->Lookahead() == lexer::LEX_CHAR_RIGHT_BRACE || lexer_->Lookahead() == lexer::LEX_CHAR_LESS_THAN) {
            break;
        }

        if ((prevStatus & actualStatus) == 0) {
            LogSyntaxError("Unexpected modifier");
        }

        if ((resultStatus & actualStatus) != 0) {
            LogSyntaxError("Duplicated modifier is not allowed");
        }

        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

        resultStatus |= actualStatus;
        prevStatus = nextStatus;
    }

    return resultStatus;
}

void ParserImpl::CheckAccessorPair(const ArenaVector<ir::AstNode *> &properties, const ir::Expression *propName,
                                   ir::MethodDefinitionKind methodKind, ir::ModifierFlags access)
{
    for (const auto &it : properties) {
        if (!it->IsMethodDefinition() || it->AsMethodDefinition()->Kind() != methodKind) {
            continue;
        }

        const ir::Expression *key = it->AsMethodDefinition()->Key();

        if (key->Type() != propName->Type()) {
            continue;
        }

        bool keyIsSame = false;

        if (key->IsIdentifier()) {
            const util::StringView &strName = propName->AsIdentifier()->Name();
            const util::StringView &compareName = (key->AsIdentifier()->Name());

            keyIsSame = strName == compareName;
        } else if (key->IsNumberLiteral()) {
            keyIsSame =
                key->AsNumberLiteral()->Number().GetDouble() == propName->AsNumberLiteral()->Number().GetDouble();
        } else if (key->IsStringLiteral()) {
            keyIsSame = *key->AsStringLiteral() == *propName->AsStringLiteral();
        }

        if (!keyIsSame) {
            continue;
        }

        ir::ModifierFlags getAccess;
        ir::ModifierFlags setAccess;

        if (methodKind == ir::MethodDefinitionKind::GET) {
            setAccess = access;
            getAccess = GetAccessability(it->Modifiers());
        } else {
            getAccess = access;
            setAccess = GetAccessability(it->Modifiers());
        }

        if ((setAccess == ir::ModifierFlags::NONE && getAccess > ir::ModifierFlags::PUBLIC) ||
            (setAccess != ir::ModifierFlags::NONE && getAccess > setAccess)) {
            LogSyntaxError("A get accessor must be at least as accessible as the setter", key->Start());
        }
    }
}

void ParserImpl::ParseClassAccessor(ClassElementDescriptor *desc, char32_t *nextCp)
{
    ConsumeClassPrivateIdentifier(desc, nextCp);

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT) {
        return;
    }

    auto keywordType = lexer_->GetToken().KeywordType();
    if ((keywordType != lexer::TokenType::KEYW_GET && keywordType != lexer::TokenType::KEYW_SET) ||
        (*nextCp == lexer::LEX_CHAR_EQUALS || *nextCp == lexer::LEX_CHAR_SEMICOLON ||
         *nextCp == lexer::LEX_CHAR_LEFT_PAREN || *nextCp == lexer::LEX_CHAR_COLON ||
         *nextCp == lexer::LEX_CHAR_LESS_THAN)) {
        return;
    }

    LogIfPrivateIdent(desc, "Unexpected identifier");

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0) {
        LogSyntaxError("Keyword must not contain escaped characters");
    }

    desc->methodKind =
        keywordType == lexer::TokenType::KEYW_GET ? ir::MethodDefinitionKind::GET : ir::MethodDefinitionKind::SET;
    desc->methodStart = lexer_->GetToken().Start();

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    ConsumeClassPrivateIdentifier(desc, nextCp);
}

void ParserImpl::LogIfPrivateIdent(ClassElementDescriptor *desc, const char *msg)
{
    if (desc->isPrivateIdent) {
        LogSyntaxError(msg);
    }
}

void ParserImpl::CheckIfStaticConstructor([[maybe_unused]] ir::ModifierFlags flags) {}

void ParserImpl::ValidateClassKey(ClassElementDescriptor *desc)
{
    if (((desc->modifiers & ir::ModifierFlags::ASYNC) != 0 || desc->isGenerator) &&
        (desc->methodKind == ir::MethodDefinitionKind::GET || desc->methodKind == ir::MethodDefinitionKind::SET)) {
        LogSyntaxError("Invalid accessor");
    }

    const util::StringView &propNameStr = lexer_->GetToken().Ident();

    if (propNameStr.Is("constructor")) {
        if (lexer_->Lookahead() != lexer::LEX_CHAR_LEFT_PAREN) {
            // test-class-constructor3.ts
            LogSyntaxError("Classes may not have a field named 'constructor'");
        }

        LogIfPrivateIdent(desc, "Private identifier can not be constructor");

        if ((desc->modifiers & ir::ModifierFlags::STATIC) == 0) {
            if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0 ||
                desc->methodKind == ir::MethodDefinitionKind::GET ||
                desc->methodKind == ir::MethodDefinitionKind::SET || desc->isGenerator) {
                LogSyntaxError("Constructor can not be special method");
            }

            desc->methodKind = ir::MethodDefinitionKind::CONSTRUCTOR;
            desc->methodStart = lexer_->GetToken().Start();
            desc->newStatus |= ParserStatus::CONSTRUCTOR_FUNCTION;

            if (desc->hasSuperClass) {
                desc->newStatus |= ParserStatus::ALLOW_SUPER_CALL;
            }
        }

        CheckIfStaticConstructor(desc->modifiers);
    } else if (propNameStr.Is("prototype") && (desc->modifiers & ir::ModifierFlags::STATIC) != 0) {
        LogSyntaxError("Classes may not have static property named prototype");
    }
}

std::tuple<bool, bool, bool> ParserImpl::ParseComputedClassFieldOrIndexSignature(ir::Expression **propName)
{
    lexer_->NextToken();  // eat left square bracket
    *propName = ParseExpression(ExpressionParseFlags::ACCEPT_COMMA);

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        // test exists for js extension only
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET);
    }

    return {true, false, false};
}

ir::Expression *ParserImpl::ParseClassKey(ClassElementDescriptor *desc)
{
    ir::Expression *propName = nullptr;
    if (lexer_->GetToken().IsKeyword()) {
        lexer_->GetToken().SetTokenType(lexer::TokenType::LITERAL_IDENT);
        Lexer()->GetToken().SetTokenStr(ERROR_LITERAL);
    }

    switch (lexer_->GetToken().Type()) {
        case lexer::TokenType::LITERAL_IDENT: {
            ValidateClassKey(desc);

            propName = AllocNode<ir::Identifier>(lexer_->GetToken().Ident(), Allocator());
            propName->SetRange(lexer_->GetToken().Loc());
            propName->AsIdentifier()->SetPrivate(desc->isPrivateIdent);
            break;
        }
        case lexer::TokenType::LITERAL_STRING: {
            LogIfPrivateIdent(desc, "Private identifier name can not be string");

            if (lexer_->GetToken().Ident().Is("constructor")) {
                LogSyntaxError("Classes may not have a field named 'constructor'");
            }

            if (lexer_->GetToken().Ident().Is("prototype") && (desc->modifiers & ir::ModifierFlags::STATIC) != 0) {
                LogSyntaxError("Classes may not have a static property named 'prototype'");
            }

            propName = AllocNode<ir::StringLiteral>(lexer_->GetToken().String());
            propName->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::LITERAL_NUMBER: {
            LogIfPrivateIdent(desc, "Private identifier name can not be number");

            if ((lexer_->GetToken().Flags() & lexer::TokenFlags::NUMBER_BIGINT) != 0) {
                propName = AllocNode<ir::BigIntLiteral>(lexer_->GetToken().BigInt());
            } else {
                propName = AllocNode<ir::NumberLiteral>(lexer_->GetToken().GetNumber());
            }

            propName->SetRange(lexer_->GetToken().Loc());
            break;
        }
        case lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET: {
            LogIfPrivateIdent(desc, "Unexpected character in private identifier");
            std::tie(desc->isComputed, desc->invalidComputedProperty, desc->isIndexSignature) =
                ParseComputedClassFieldOrIndexSignature(&propName);
            break;
        }
        default: {
            LogSyntaxError("Unexpected token in class property");
        }
    }

    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    return propName;
}

void ParserImpl::ValidateClassMethodStart(ClassElementDescriptor *desc, [[maybe_unused]] ir::TypeNode *typeAnnotation)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        return;
    }
    desc->classMethod = true;

    if ((desc->modifiers & ir::ModifierFlags::ASYNC) != 0) {
        desc->newStatus |= ParserStatus::ASYNC_FUNCTION;
    }

    if (desc->isGenerator) {
        desc->newStatus |= ParserStatus::GENERATOR_FUNCTION;
    }
}

void ParserImpl::ValidateGetterSetter(ir::MethodDefinitionKind methodDefinition, size_t number)
{
    if (methodDefinition == ir::MethodDefinitionKind::SET) {
        if (number != 1) {
            LogSyntaxError("Setter must have exactly one formal parameter");
        }
    } else if (methodDefinition == ir::MethodDefinitionKind::GET) {
        if (number != 0) {
            LogSyntaxError("Getter must not have formal parameters");
        }
    }
}

void ParserImpl::ValidateClassSetter([[maybe_unused]] ClassElementDescriptor *desc,
                                     [[maybe_unused]] const ArenaVector<ir::AstNode *> &properties,
                                     [[maybe_unused]] ir::Expression *propName, ir::ScriptFunction *func)
{
    ValidateGetterSetter(ir::MethodDefinitionKind::SET, func->Params().size());
}

void ParserImpl::ValidateClassGetter([[maybe_unused]] ClassElementDescriptor *desc,
                                     [[maybe_unused]] const ArenaVector<ir::AstNode *> &properties,
                                     [[maybe_unused]] ir::Expression *propName, ir::ScriptFunction *func)
{
    ValidateGetterSetter(ir::MethodDefinitionKind::GET, func->Params().size());
}

ir::MethodDefinition *ParserImpl::ParseClassMethod(ClassElementDescriptor *desc,
                                                   const ArenaVector<ir::AstNode *> &properties,
                                                   ir::Expression *propName, lexer::SourcePosition *propEnd)
{
    if (desc->methodKind != ir::MethodDefinitionKind::SET &&
        (desc->newStatus & ParserStatus::CONSTRUCTOR_FUNCTION) == 0) {
        desc->newStatus |= ParserStatus::NEED_RETURN_TYPE;
    }

    ir::ScriptFunction *func = ParseFunction(desc->newStatus);

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    funcExpr->SetRange(func->Range());

    if (desc->methodKind == ir::MethodDefinitionKind::SET) {
        ValidateClassSetter(desc, properties, propName, func);
    } else if (desc->methodKind == ir::MethodDefinitionKind::GET) {
        ValidateClassGetter(desc, properties, propName, func);
    }

    *propEnd = func->End();
    func->AddFlag(ir::ScriptFunctionFlags::METHOD);

    auto *ident = !propName->IsArrowFunctionExpression() && !propName->IsFunctionExpression()
                      ? propName->Clone(Allocator(), nullptr)->AsExpression()
                      : propName;
    auto *method = AllocNode<ir::MethodDefinition>(desc->methodKind, ident, funcExpr, desc->modifiers, Allocator(),
                                                   desc->isComputed);
    method->SetRange(funcExpr->Range());

    return method;
}

ir::ClassElement *ParserImpl::ParseClassProperty(ClassElementDescriptor *desc,
                                                 const ArenaVector<ir::AstNode *> &properties, ir::Expression *propName,
                                                 ir::TypeNode *typeAnnotation)
{
    lexer::SourcePosition propEnd = propName->End();
    ir::ClassElement *property = nullptr;

    if (desc->classMethod) {
        if ((desc->modifiers & ir::ModifierFlags::DECLARE) != 0) {
            LogSyntaxError("'declare modifier cannot appear on class elements of this kind.");
        }

        property = ParseClassMethod(desc, properties, propName, &propEnd);
        property->SetRange({desc->propStart, propEnd});
        return property;
    }

    ir::Expression *value = nullptr;

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SUBSTITUTION) {
        lexer_->NextToken();  // eat equals

        if (InAmbientContext() || (desc->modifiers & ir::ModifierFlags::DECLARE) != 0) {
            LogSyntaxError("Initializers are not allowed in ambient contexts.");
        }

        value = ParseExpression();
        propEnd = value->End();
    }

    property =
        AllocNode<ir::ClassProperty>(propName, value, typeAnnotation, desc->modifiers, Allocator(), desc->isComputed);

    property->SetRange({desc->propStart, propEnd});

    return property;
}

void ParserImpl::CheckClassGeneratorMethod(ClassElementDescriptor *desc, char32_t *nextCp)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_MULTIPLY) {
        return;
    }

    desc->isGenerator = true;
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    *nextCp = lexer_->Lookahead();
}

bool ParserImpl::ValidatePrivateIdentifier()
{
    size_t iterIdx = lexer_->GetToken().Start().index;
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT ||
        (lexer_->GetToken().Start().index - iterIdx > 1)) {
        LogSyntaxError("Unexpected token in private field");
        return false;
    }

    return true;
}

void ParserImpl::ConsumeClassPrivateIdentifier(ClassElementDescriptor *desc, char32_t *nextCp)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_HASH_MARK) {
        return;
    }

    desc->isPrivateIdent = true;
    ValidatePrivateIdentifier();
    *nextCp = lexer_->Lookahead();
}

void ParserImpl::AddPrivateElement(const ir::ClassElement *elem)
{
    if (elem->Id() == nullptr) {  // Error processing.
        return;
    }

    if (!classPrivateContext_.AddElement(elem)) {
        LogSyntaxError("Private field has already been declared");
    }
}

ir::ClassElement *ParserImpl::ParseClassStaticBlock()
{
    const lexer::SourcePosition &startPos = lexer_->GetToken().Start();

    lexer_->NextToken();  // eat 'static'

    SavedParserContext context(this, ParserStatus::ALLOW_SUPER);
    context_.Status() &= ~(ParserStatus::ASYNC_FUNCTION | ParserStatus::GENERATOR_FUNCTION);

    lexer_->NextToken();  // eat '{'

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    ArenaVector<ir::Statement *> statements = ParseStatementList();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
        // redundant check -> we have it in parse statements
        // we even do not do lexer_->NextToken() trying to eat '}' after
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_RIGHT_BRACE);
    }

    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    // clang-format off
    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {
            body, ir::FunctionSignature(nullptr, std::move(params), nullptr),
            ir::ScriptFunctionFlags::EXPRESSION | ir::ScriptFunctionFlags::STATIC_BLOCK,
            ir::ModifierFlags::STATIC, context_.GetLanguage()});
    // clang-format on

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    auto *staticBlock = AllocNode<ir::ClassStaticBlock>(funcExpr, Allocator());
    staticBlock->SetRange({startPos, lexer_->GetToken().End()});

    lexer_->NextToken();  // eat '}'

    return staticBlock;
}

ir::AstNode *ParserImpl::ParseClassElement(const ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers,
                                           [[maybe_unused]] ir::ModifierFlags flags)
{
    if (lexer_->GetToken().KeywordType() == lexer::TokenType::KEYW_STATIC &&
        lexer_->Lookahead() == lexer::LEX_CHAR_LEFT_BRACE) {
        return ParseClassStaticBlock();
    }

    ClassElementDescriptor desc(Allocator());

    desc.methodKind = ir::MethodDefinitionKind::METHOD;
    desc.newStatus = ParserStatus::ALLOW_SUPER;
    desc.hasSuperClass = (modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U;
    desc.propStart = lexer_->GetToken().Start();
    desc.modifiers = ParseModifiers();

    char32_t nextCp = lexer_->Lookahead();
    CheckClassGeneratorMethod(&desc, &nextCp);
    ParseClassAccessor(&desc, &nextCp);

    if ((desc.modifiers & ir::ModifierFlags::STATIC) == 0) {
        context_.Status() |= ParserStatus::ALLOW_THIS_TYPE;
    }

    ir::Expression *propName = ParseClassKey(&desc);
    if (propName == nullptr) {  // Error processing.
        context_.Status() &= ~ParserStatus::ALLOW_THIS_TYPE;
        return nullptr;
    }

    ValidateClassMethodStart(&desc, nullptr);
    ir::ClassElement *property = ParseClassProperty(&desc, properties, propName, nullptr);

    if (property != nullptr && lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_SEMI_COLON &&
        lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
        (lexer_->GetToken().Flags() & lexer::TokenFlags::NEW_LINE) == 0 &&
        !(property->IsMethodDefinition() &&
          property->AsMethodDefinition()->Value()->AsFunctionExpression()->Function()->Body() != nullptr)) {
        // test exists for js extension only
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_SEMI_COLON);
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
        lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);
    }

    context_.Status() &= ~ParserStatus::ALLOW_THIS_TYPE;

    if (desc.isPrivateIdent) {
        AddPrivateElement(property);
    }

    return property;
}

ir::MethodDefinition *ParserImpl::BuildImplicitConstructor(ir::ClassDefinitionModifiers modifiers,
                                                           const lexer::SourcePosition &startLoc)
{
    ArenaVector<ir::Expression *> params(Allocator()->Adapter());
    ArenaVector<ir::Statement *> statements(Allocator()->Adapter());

    if ((modifiers & ir::ClassDefinitionModifiers::HAS_SUPER) != 0U) {
        util::StringView argsStr = "args";
        params.push_back(AllocNode<ir::SpreadElement>(ir::AstNodeType::REST_ELEMENT, Allocator(),
                                                      AllocNode<ir::Identifier>(argsStr, Allocator())));
        ArenaVector<ir::Expression *> callArgs(Allocator()->Adapter());
        auto *superExpr = AllocNode<ir::SuperExpression>();
        callArgs.push_back(AllocNode<ir::SpreadElement>(ir::AstNodeType::SPREAD_ELEMENT, Allocator(),
                                                        AllocNode<ir::Identifier>(argsStr, Allocator())));

        auto *callExpr = AllocNode<ir::CallExpression>(superExpr, std::move(callArgs), nullptr, false);
        statements.push_back(AllocNode<ir::ExpressionStatement>(callExpr));
    }

    auto *body = AllocNode<ir::BlockStatement>(Allocator(), std::move(statements));
    auto *func = AllocNode<ir::ScriptFunction>(
        Allocator(), ir::ScriptFunction::ScriptFunctionData {body,
                                                             ir::FunctionSignature(nullptr, std::move(params), nullptr),
                                                             ir::ScriptFunctionFlags::CONSTRUCTOR |
                                                                 ir::ScriptFunctionFlags::IMPLICIT_SUPER_CALL_NEEDED,
                                                             {},
                                                             context_.GetLanguage()});

    auto *funcExpr = AllocNode<ir::FunctionExpression>(func);
    auto *key = AllocNode<ir::Identifier>("constructor", Allocator());

    if ((modifiers & ir::ClassDefinitionModifiers::SET_CTOR_ID) != 0U) {
        func->SetIdent(key->Clone(Allocator(), nullptr));
    }

    auto *ctor = AllocNode<ir::MethodDefinition>(ir::MethodDefinitionKind::CONSTRUCTOR, key, funcExpr,
                                                 ir::ModifierFlags::NONE, Allocator(), false);

    ctor->SetRange({startLoc, lexer_->GetToken().End()});

    return ctor;
}

void ParserImpl::CreateImplicitConstructor(ir::MethodDefinition *&ctor,
                                           [[maybe_unused]] ArenaVector<ir::AstNode *> &properties,
                                           ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags,
                                           const lexer::SourcePosition &startLoc)
{
    if (ctor != nullptr) {
        return;
    }

    ctor = BuildImplicitConstructor(modifiers, startLoc);
    if ((flags & ir::ModifierFlags::DECLARE) != 0) {
        ctor->Function()->AddFlag(ir::ScriptFunctionFlags::EXTERNAL);
    }
}

ir::Identifier *ParserImpl::ParseClassIdent(ir::ClassDefinitionModifiers modifiers)
{
    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        return ExpectIdentifier();
    }

    auto idRequired =
        static_cast<ir::ClassDefinitionModifiers>(modifiers & ir::ClassDefinitionModifiers::DECLARATION_ID_REQUIRED);

    if (idRequired == ir::ClassDefinitionModifiers::DECLARATION_ID_REQUIRED) {
        LogSyntaxError("Unexpected token, expected an identifier.");
    }

    return nullptr;
}

bool ParserImpl::CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                                   [[maybe_unused]] ArenaVector<ir::AstNode *> &properties)
{
    if (!property->IsMethodDefinition()) {
        return false;
    }

    ir::MethodDefinition *def = property->AsMethodDefinition();
    if (!def->IsConstructor()) {
        return false;
    }

    if (ctor != nullptr) {
        LogSyntaxError("Multiple constructor implementations are not allowed.", property->Start());
    }
    ctor = def;

    return true;
}

ir::Expression *ParserImpl::ParseSuperClassReference()
{
    if (lexer_->GetToken().Type() == lexer::TokenType::KEYW_EXTENDS) {
        lexer_->NextToken();
        return ParseLeftHandSideExpression();
    }

    return nullptr;
}

std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParserImpl::ParseSuperClass()
{
    return {ParseSuperClassReference(), nullptr};
}

// NOLINTNEXTLINE(google-default-arguments)
ir::ClassDefinition *ParserImpl::ParseClassDefinition(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    ExpectToken(lexer::TokenType::KEYW_CLASS);

    ir::Identifier *identNode = ParseClassIdent(modifiers);

    if (identNode == nullptr && (modifiers & ir::ClassDefinitionModifiers::DECLARATION) != 0U) {
        LogSyntaxError("Unexpected token, expected an identifier.");
        return nullptr;
    }

    varbinder::PrivateBinding privateBinding(Allocator(), classId_++);

    // Parse SuperClass
    auto [superClass, superTypeParams] = ParseSuperClass();

    if (superClass != nullptr) {
        modifiers |= ir::ClassDefinitionModifiers::HAS_SUPER;
    }

    // test exists for js extension only
    ExpectToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE, false);

    auto [ctor, properties, bodyRange] = ParseClassBody(modifiers, flags);

    ArenaVector<ir::TSClassImplements *> implements(Allocator()->Adapter());
    auto *classDefinition = AllocNode<ir::ClassDefinition>(
        privateBinding.View(), identNode, nullptr, superTypeParams, std::move(implements), ctor, superClass,
        std::move(properties), modifiers, flags, GetContext().GetLanguage());

    classDefinition->SetRange(bodyRange);

    return classDefinition;
}

ParserImpl::ClassBody ParserImpl::ParseClassBody(ir::ClassDefinitionModifiers modifiers, ir::ModifierFlags flags)
{
    auto savedCtx = SavedStatusContext<ParserStatus::IN_CLASS_BODY>(&context_);

    lexer::SourcePosition startLoc = lexer_->GetToken().Start();
    lexer_->NextToken(lexer::NextTokenFlags::KEYWORD_TO_IDENT);

    ir::MethodDefinition *ctor = nullptr;
    ArenaVector<ir::AstNode *> properties(Allocator()->Adapter());

    SavedClassPrivateContext classContext(this);

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT &&
        lexer_->Lookahead() == static_cast<char32_t>(ARRAY_FORMAT_NODE)) {
        properties = std::move(ParseAstNodesArrayFormatPlaceholder());
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE) {
            // NOTE(schernykh): add info about LoC
            LOG(FATAL, ES2PANDA) << "Unexpected " << lexer::TokenToString(lexer_->GetToken().Type())
                                 << ", expected '}'.";
        }
    } else {
        while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_BRACE &&
               lexer_->GetToken().Type() != lexer::TokenType::EOS) {
            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_SEMI_COLON) {
                lexer_->NextToken();
                continue;
            }

            ir::AstNode *property = ParseClassElement(properties, modifiers, flags);
            if (property == nullptr) {  // Error processing.
                lexer_->NextToken();
                continue;
            }

            if (CheckClassElement(property, ctor, properties)) {
                continue;
            }

            properties.push_back(property);
        }
    }

    lexer::SourcePosition endLoc = lexer_->GetToken().End();
    CreateImplicitConstructor(ctor, properties, modifiers, flags, endLoc);
    lexer_->NextToken();

    return {ctor, std::move(properties), lexer::SourceRange {startLoc, endLoc}};
}

void ParserImpl::ValidateRestParameter(ir::Expression *param)
{
    if (!param->IsIdentifier()) {
        context_.Status() |= ParserStatus::HAS_COMPLEX_PARAM;
        if (!param->IsRestElement()) {
            return;
        }
        if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
            // for now test exists for js extension only
            LogSyntaxError("Rest parameter must be the last formal parameter.");

            lexer_->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
        }
    }
}

bool ParserImpl::ValidateBreakLabel(util::StringView label)
{
    return context_.FindLabel(label) != nullptr;
}

bool ParserImpl::ValidateContinueLabel(util::StringView label)
{
    const ParserContext *labelCtx = context_.FindLabel(label);
    return labelCtx != nullptr && ((labelCtx->Status() & ParserStatus::IN_ITERATION) != 0);
}

ArenaVector<ir::Expression *> ParserImpl::ParseFunctionParams()
{
    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        lexer_->NextToken();  // eat '('
    }

    ArenaVector<ir::Expression *> params(Allocator()->Adapter());

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_FORMAT &&
        lexer_->Lookahead() == static_cast<char32_t>(ARRAY_FORMAT_NODE)) {
        params = std::move(ParseExpressionsArrayFormatPlaceholder());
    } else {
        while (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS &&
               lexer_->GetToken().Type() != lexer::TokenType::EOS) {
            util::ErrorRecursionGuard infiniteLoopBlocker(lexer_);

            ir::Expression *parameter = ParseFunctionParameter();
            if (parameter == nullptr) {  // Error processing.
                continue;
            }

            ValidateRestParameter(parameter);
            params.push_back(parameter);

            if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_COMMA) {
                lexer_->NextToken();
                // CC-OFFNXT(G.FMT.06-CPP) project code style
            } else if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {
                LogSyntaxError("Invalid token: ',' or ')' expected.");

                lexer_->GetToken().SetTokenType(lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS);
            }
        }
    }

    if (lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_RIGHT_PARENTHESIS) {  // Error processing.
        lexer_->NextToken();
    }

    return params;
}

ir::Expression *ParserImpl::CreateParameterThis([[maybe_unused]] ir::TypeNode *typeAnnotation)
{
    LogSyntaxError("Unexpected token, expected function identifier");
    return nullptr;
}

std::tuple<bool, ir::BlockStatement *, lexer::SourcePosition, bool> ParserImpl::ParseFunctionBody(
    // CC-OFFNXT(G.FMT.06-CPP) project code style
    [[maybe_unused]] const ArenaVector<ir::Expression *> &params, [[maybe_unused]] ParserStatus newStatus,
    [[maybe_unused]] ParserStatus contextStatus)
{
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_BRACE) {
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_BRACE);
    }

    ir::BlockStatement *body = ParseBlockStatement();

    return {true, body, body->End(), false};
}

FunctionSignature ParserImpl::ParseFunctionSignature(ParserStatus status, ir::TypeNode *typeAnnotation)
{
    ir::TSTypeParameterDeclaration *typeParamDecl = ParseFunctionTypeParameters();

    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS) {
        LogExpectedToken(lexer::TokenType::PUNCTUATOR_LEFT_PARENTHESIS);
    }

    FunctionParameterContext funcParamContext(&context_);

    ir::Expression *parameterThis = nullptr;
    if (typeAnnotation != nullptr) {
        const auto savedPos = Lexer()->Save();
        lexer_->NextToken();  // eat '('
        parameterThis = CreateParameterThis(typeAnnotation);
        Lexer()->Rewind(savedPos);
    }

    auto params = ParseFunctionParams();

    if (typeAnnotation != nullptr) {
        params.emplace(params.begin(), parameterThis);
    }

    ir::TypeNode *returnTypeAnnotation = ParseFunctionReturnType(status);
    ir::ScriptFunctionFlags throwMarker = ParseFunctionThrowMarker(true);

    auto res = ir::FunctionSignature(typeParamDecl, std::move(params), returnTypeAnnotation);
    return {std::move(res), throwMarker};
}

ir::ScriptFunction *ParserImpl::ParseFunction(ParserStatus newStatus)
{
    FunctionContext functionContext(this, newStatus | ParserStatus::FUNCTION | ParserStatus::ALLOW_NEW_TARGET);

    lexer::SourcePosition startLoc = lexer_->GetToken().Start();

    auto [signature, throw_marker] = ParseFunctionSignature(newStatus);

    auto [letDeclare, body, endLoc, isOverload] = ParseFunctionBody(signature.Params(), newStatus, context_.Status());

    if (isOverload) {
        functionContext.AddFlag(ir::ScriptFunctionFlags::OVERLOAD);
    }

    functionContext.AddFlag(throw_marker);
    auto *funcNode = AllocNode<ir::ScriptFunction>(
        Allocator(),
        ir::ScriptFunction::ScriptFunctionData {body,
                                                std::move(signature),      // CC-OFFNXT(G.FMT.02-CPP) project code style
                                                functionContext.Flags(),   // CC-OFFNXT(G.FMT.02-CPP) project code style
                                                {},                        // CC-OFFNXT(G.FMT.02-CPP) project code style
                                                context_.GetLanguage()});  // CC-OFF(G.FMT.02-CPP) project code style

    funcNode->SetRange({startLoc, endLoc});

    return funcNode;
}

ir::SpreadElement *ParserImpl::ParseSpreadElement(ExpressionParseFlags flags)
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::PUNCTUATOR_PERIOD_PERIOD_PERIOD);
    lexer::SourcePosition startLocation = lexer_->GetToken().Start();
    bool inPattern = (flags & ExpressionParseFlags::MUST_BE_PATTERN) != 0;
    lexer_->NextToken();

    ir::Expression *argument {};
    if (inPattern) {
        argument = ParsePatternElement(ExpressionParseFlags::IN_REST);
        if ((flags & ExpressionParseFlags::OBJECT_PATTERN) != 0 && (argument == nullptr || !argument->IsIdentifier())) {
            LogSyntaxError("RestParameter must be followed by an identifier in declaration contexts");
        }
    } else {
        argument = ParseExpression(flags);
    }

    if (argument == nullptr) {  // Error processing.
        return nullptr;
    }

    if (inPattern && argument->IsAssignmentExpression()) {
        LogSyntaxError("RestParameter does not support an initializer");
    }

    auto nodeType = inPattern ? ir::AstNodeType::REST_ELEMENT : ir::AstNodeType::SPREAD_ELEMENT;
    auto *spreadElementNode = AllocNode<ir::SpreadElement>(nodeType, Allocator(), argument);
    spreadElementNode->SetRange({startLocation, argument->End()});
    return spreadElementNode;
}

void ParserImpl::CheckRestrictedBinding()
{
    ASSERT(lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT);
    CheckRestrictedBinding(lexer_->GetToken().KeywordType());
}

void ParserImpl::CheckRestrictedBinding(lexer::TokenType keywordType)
{
    if (keywordType == lexer::TokenType::KEYW_ARGUMENTS || keywordType == lexer::TokenType::KEYW_EVAL) {
        LogSyntaxError(
            "'eval' or 'arguments' can't be defined or assigned to "
            "in strict mode code",
            lexer_->GetToken().Start());
    }
}

void ParserImpl::CheckRestrictedBinding(const util::StringView &ident, const lexer::SourcePosition &pos)
{
    if (ident.Is("eval") || ident.Is("arguments")) {
        LogSyntaxError(
            "'eval' or 'arguments' can't be defined or assigned to "
            "in strict mode code",
            pos);
    }
}

ir::Expression *ParserImpl::ParseFunctionParameter()
{
    ConvertThisKeywordToIdentIfNecessary();

    if (lexer_->GetToken().Type() == lexer::TokenType::LITERAL_IDENT) {
        CheckRestrictedBinding();
    }

    return ParsePatternElement(ExpressionParseFlags::NO_OPTS, true);
}

void ParserImpl::ValidateLvalueAssignmentTarget(ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            CheckRestrictedBinding(node->AsIdentifier()->Name(), node->Start());
            break;
        }
        case ir::AstNodeType::MEMBER_EXPRESSION: {
            break;
        }
        default: {
            LogSyntaxError("Invalid left-hand side in assignment expression");
        }
    }
}

void ParserImpl::ValidateAssignmentTarget(ExpressionParseFlags flags, ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::ARRAY_PATTERN:
        case ir::AstNodeType::OBJECT_PATTERN: {
            break;
        }
        case ir::AstNodeType::ARRAY_EXPRESSION:
        case ir::AstNodeType::OBJECT_EXPRESSION: {
            if ((flags & ExpressionParseFlags::POTENTIALLY_IN_PATTERN) != 0) {
                return;
            }

            [[fallthrough]];
        }
        default: {
            return ValidateLvalueAssignmentTarget(node);
        }
    }
}

void ParserImpl::ValidateArrowParameterBindings(const ir::Expression *node)
{
    switch (node->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            CheckRestrictedBinding(node->AsIdentifier()->Name(), node->Start());
            break;
        }
        case ir::AstNodeType::OMITTED_EXPRESSION: {
            break;
        }
        case ir::AstNodeType::REST_ELEMENT: {
            ValidateArrowParameterBindings(node->AsRestElement()->Argument());
            break;
        }
        case ir::AstNodeType::PROPERTY: {
            break;
        }
        case ir::AstNodeType::OBJECT_PATTERN: {
            const auto &props = node->AsObjectPattern()->Properties();

            for (auto *it : props) {
                ValidateArrowParameterBindings(it);
            }
            break;
        }
        case ir::AstNodeType::ARRAY_PATTERN: {
            const auto &elements = node->AsArrayPattern()->Elements();

            for (auto *it : elements) {
                ValidateArrowParameterBindings(it);
            }
            break;
        }
        case ir::AstNodeType::ASSIGNMENT_PATTERN: {
            ValidateArrowParameterBindings(node->AsAssignmentPattern()->Left());
            // CC-OFFNXT(G.FMT.06-CPP) project code style
            break;
        }
        default: {
            LogSyntaxError("Unexpected ArrowParameter element");
        }
    }
}

void ParserImpl::LogParameterModifierError(ir::ModifierFlags status)
{
    LogSyntaxError({"'",
                    (status & ir::ModifierFlags::STATIC) != 0  ? "static"
                    : (status & ir::ModifierFlags::ASYNC) != 0 ? "async"
                                                               : "declare",
                    "' modifier cannot appear on a parameter."},
                   lexer_->GetToken().Start());
}

ir::Identifier *ParserImpl::ParseIdentifierFormatPlaceholder([[maybe_unused]] std::optional<NodeFormatType> nodeFormat)
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Format placeholder with identifier is not supported";
    return nullptr;
}

ir::Statement *ParserImpl::ParseStatementFormatPlaceholder()
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Statement with format placeholder is not supported";
    return nullptr;
}

ir::AstNode *ParserImpl::ParseTypeParametersFormatPlaceholder()
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Format placeholder with type parameter(s) is not supported";
    return nullptr;
}

ArenaVector<ir::Statement *> &ParserImpl::ParseStatementsArrayFormatPlaceholder()
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Format placeholder from statements array is not supported";
    UNREACHABLE();
}

ArenaVector<ir::AstNode *> &ParserImpl::ParseAstNodesArrayFormatPlaceholder()
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Format placeholder from AST nodes is not supported";
    UNREACHABLE();
}

ArenaVector<ir::Expression *> &ParserImpl::ParseExpressionsArrayFormatPlaceholder()
{
    // NOTE(schernykh): add info about LoC
    LOG(FATAL, ES2PANDA) << "Format placeholder from expressions array is not supported";
    UNREACHABLE();
}

util::StringView ParserImpl::ParseSymbolIteratorIdentifier() const noexcept
{
    // Duplicate check - just in case of improper call!
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        return util::StringView {};
    }

    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT || !lexer_->GetToken().Ident().Is("Symbol")) {
        return util::StringView {};
    }

    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_PERIOD) {
        return util::StringView {};
    }

    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::LITERAL_IDENT || !lexer_->GetToken().Ident().Is("iterator")) {
        return util::StringView {};
    }

    lexer_->NextToken();
    if (lexer_->GetToken().Type() != lexer::TokenType::PUNCTUATOR_RIGHT_SQUARE_BRACKET) {
        return util::StringView {};
    }

    //  Just replace '[Symbol.iterator]` identifier with the standard '$_iterator' name.
    return util::StringView {compiler::Signatures::ITERATOR_METHOD};
}

ir::Identifier *ParserImpl::ExpectIdentifier([[maybe_unused]] bool isReference, bool isUserDefinedType)
{
    auto const &token = lexer_->GetToken();
    auto const tokenType = token.Type();
    if (tokenType == lexer::TokenType::PUNCTUATOR_FORMAT) {
        return ParseIdentifierFormatPlaceholder(std::nullopt);
    }

    if (token.IsDefinableTypeName() && isUserDefinedType) {
        LogSyntaxError("Cannot be used as user-defined type.");
    }

    auto const &tokenStart = token.Start();
    util::StringView tokenName {};

    if (tokenType == lexer::TokenType::LITERAL_IDENT) {
        tokenName = token.Ident();
    } else if (tokenType == lexer::TokenType::PUNCTUATOR_LEFT_SQUARE_BRACKET) {
        // Special case for processing of special '[Symbol.iterator]` identifier using in stdlib.
        tokenName = ParseSymbolIteratorIdentifier();
    }

    if (tokenName.Empty()) {
        LogSyntaxError({"Identifier expected, got '", TokenToString(tokenType), "'."}, tokenStart);
        tokenName = ERROR_LITERAL;
    }

    auto *ident = AllocNode<ir::Identifier>(tokenName, Allocator());
    //  NOTE: here actual token can be changed!
    ident->SetRange({tokenStart, lexer_->GetToken().End()});

    lexer_->NextToken();

    return ident;
}

void ParserImpl::ExpectToken(lexer::TokenType tokenType, bool consumeToken)
{
    if (lexer_->GetToken().Type() == tokenType) {
        if (consumeToken) {
            lexer_->NextToken();
        }
        return;
    }
    LogExpectedToken(tokenType);
    if (consumeToken) {
        lexer_->NextToken();
    }
}

void ParserImpl::ThrowUnexpectedToken(lexer::TokenType const tokenType) const
{
    ThrowSyntaxError("Unexpected token: '"s + TokenToString(tokenType) + "'."s);
}

void ParserImpl::ThrowSyntaxError(std::string_view const errorMessage) const
{
    ThrowSyntaxError(errorMessage, lexer_->GetToken().Start());
}

void ParserImpl::ThrowSyntaxError(std::initializer_list<std::string_view> list) const
{
    ThrowSyntaxError(list, lexer_->GetToken().Start());
}

void ParserImpl::ThrowSyntaxError(std::initializer_list<std::string_view> list, const lexer::SourcePosition &pos) const
{
    std::stringstream ss;

    for (const auto &it : list) {
        ss << it;
    }

    std::string err = ss.str();

    ThrowSyntaxError(std::string_view {err}, pos);
}

void ParserImpl::ThrowSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos) const
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    throw Error {ErrorType::SYNTAX, program_->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col};
}

void ParserImpl::LogUnexpectedToken(lexer::TokenType tokenType)
{
    LogSyntaxError("Unexpected token: '"s + TokenToString(tokenType) + "'."s);
}

void ParserImpl::LogExpectedToken(lexer::TokenType tokenType)
{
    if (tokenType != lexer::TokenType::LITERAL_IDENT && tokenType != lexer::TokenType::LITERAL_STRING) {
        LogSyntaxError("Unexpected token, expected: '"s + TokenToString(tokenType) + "'."s);
    } else if (tokenType == lexer::TokenType::LITERAL_IDENT) {
        LogSyntaxError("Unexpected token, expected an identifier.");
        lexer_->GetToken().SetTokenStr(ERROR_LITERAL);
    } else if (tokenType == lexer::TokenType::LITERAL_STRING) {
        LogSyntaxError("Unexpected token, expected string literal.");
        lexer_->GetToken().SetTokenStr(ERROR_LITERAL);
    }
    lexer_->GetToken().SetTokenType(tokenType);
}

void ParserImpl::LogSyntaxError(std::string_view errorMessage, const lexer::SourcePosition &pos)
{
    lexer::LineIndex index(program_->SourceCode());
    lexer::SourceLocation loc = index.GetLocation(pos);

    errorLogger_.WriteLog(
        Error {ErrorType::SYNTAX, program_->SourceFilePath().Utf8(), errorMessage, loc.line, loc.col});
}

void ParserImpl::LogSyntaxError(std::string_view const errorMessage)
{
    LogSyntaxError(errorMessage, lexer_->GetToken().Start());
}

void ParserImpl::LogSyntaxError(std::initializer_list<std::string_view> list)
{
    LogSyntaxError(list, lexer_->GetToken().Start());
}

void ParserImpl::LogSyntaxError(std::initializer_list<std::string_view> list, const lexer::SourcePosition &pos)
{
    std::stringstream ss;

    for (const auto &it : list) {
        ss << it;
    }

    std::string err = ss.str();

    LogSyntaxError(std::string_view {err}, pos);
}

void ParserImpl::ThrowAllocationError(std::string_view message) const
{
    throw Error(ErrorType::GENERIC, program_->SourceFilePath().Utf8(), message);
}

ScriptExtension ParserImpl::Extension() const
{
    return program_->Extension();
}

bool ParserImpl::CheckModuleAsModifier()
{
    if (lexer_->GetToken().KeywordType() != lexer::TokenType::KEYW_AS) {
        return false;
    }

    if ((lexer_->GetToken().Flags() & lexer::TokenFlags::HAS_ESCAPE) != 0U) {
        LogSyntaxError("Escape sequences are not allowed in 'as' keyword");
    }

    return true;
}

}  // namespace ark::es2panda::parser
