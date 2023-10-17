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

#ifndef ES2PANDA_PARSER_CORE_TYPED_PARSER_H
#define ES2PANDA_PARSER_CORE_TYPED_PARSER_H

#include "parserImpl.h"

namespace panda::es2panda::ir {
class TSClassImplements;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::parser {
class TypedParser : public ParserImpl {
public:
    TypedParser(Program *program, const CompilerOptions &options, ParserStatus status = ParserStatus::NO_OPTS)
        : ParserImpl(program, options, status)
    {
    }

protected:
    void ParseDecorators(ArenaVector<ir::Decorator *> &decorators);
    void CheckDeclare();
    ir::TSModuleDeclaration *ParseAmbientExternalModuleDeclaration(const lexer::SourcePosition &start_loc);
    ir::TSModuleBlock *ParseTsModuleBlock();
    ir::TSModuleDeclaration *ParseModuleOrNamespaceDeclaration(const lexer::SourcePosition &start_loc);
    ArenaVector<ir::AstNode *> ParseTypeLiteralOrInterface();
    void CheckObjectTypeForDuplicatedProperties(ir::Expression *key, ArenaVector<ir::AstNode *> &members);

    ir::ArrowFunctionExpression *ParseGenericArrowFunction();
    ir::TSTypeAssertion *ParseTypeAssertion();
    ir::TSTypeParameterInstantiation *ParseTypeParameterInstantiation(TypeAnnotationParsingOptions *options);

    ir::TSTypeParameterDeclaration *ParseTypeParameterDeclaration(TypeAnnotationParsingOptions *options);
    ir::Expression *ParseQualifiedName(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    ir::Expression *ParseQualifiedReference(ir::Expression *type_name,
                                            ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS);
    void ParsePotentialOptionalFunctionParameter(ir::AnnotatedExpression *return_node);
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Expression *ParseExpression(ExpressionParseFlags flags = ExpressionParseFlags::NO_OPTS) override;
    ir::Statement *ParseInterfaceDeclaration(bool is_static) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseEnumDeclaration(bool is_const = false, bool is_static = false) override;
    ir::Statement *ParsePotentialExpressionStatement(StatementParsingFlags flags) override;
    void ConvertThisKeywordToIdentIfNecessary() override;
    ir::TypeNode *ParseFunctionReturnType(ParserStatus status) override;
    ir::TSTypeParameterDeclaration *ParseFunctionTypeParameters() override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::ClassDefinition *ParseClassDefinition(ir::ClassDefinitionModifiers modifiers,
                                              ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;
    // NOLINTNEXTLINE(google-default-arguments)
    ir::AstNode *ParseClassElement(const ArenaVector<ir::AstNode *> &properties, ir::ClassDefinitionModifiers modifiers,
                                   ir::ModifierFlags flags = ir::ModifierFlags::NONE) override;

    static bool CheckClassElementInterfaceBody(ir::AstNode *property, ArenaVector<ir::AstNode *> &properties);
    bool CheckClassElement(ir::AstNode *property, ir::MethodDefinition *&ctor,
                           ArenaVector<ir::AstNode *> &properties) override;

    ir::ModifierFlags ParseModifiers() override;
    ParserStatus ValidateArrowParameter(ir::Expression *expr, bool *seen_optional) override;
    ir::Expression *ParsePotentialAsExpression(ir::Expression *primary_expr) override;

    std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseSuperClass() override;
    ir::Expression *ParseSuperClassReference() override;
    virtual ArenaVector<ir::TSClassImplements *> ParseClassImplementClause();

    // NOLINTNEXTLINE(google-default-arguments)
    ir::Statement *ParseModuleDeclaration(StatementParsingFlags flags = StatementParsingFlags::NONE) override;
    virtual void CheckIfTypeParameterNameIsReserved() {};
    virtual ArenaVector<ir::TSInterfaceHeritage *> ParseInterfaceExtendsClause();
    virtual ir::Statement *ParseDeclareAndDecorators(StatementParsingFlags flags);
    virtual void ParseOptionalClassElement(ClassElementDescriptor *desc);
    virtual ir::TSTypeParameter *ParseTypeParameter(TypeAnnotationParsingOptions *options);
    virtual ir::TSEnumDeclaration *ParseEnumMembers(ir::Identifier *key, const lexer::SourcePosition &enum_start,
                                                    bool is_const, bool is_static);
    virtual std::tuple<ir::Expression *, ir::TSTypeParameterInstantiation *> ParseClassImplementsElement();
    virtual ir::TypeNode *ParseInterfaceExtendsElement();

    virtual void ValidateIndexSignatureTypeAnnotation([[maybe_unused]] ir::TypeNode *type_annotation) {}
    virtual ir::Decorator *ParseDecorator()
    {
        return nullptr;
    }
    virtual bool CurrentIsBasicType()
    {
        return false;
    }
    virtual ir::TSTypeAliasDeclaration *ParseTypeAliasDeclaration()
    {
        return nullptr;
    }
    virtual ir::AstNode *ParseTypeLiteralOrInterfaceMember()
    {
        return nullptr;
    }
    // NOLINTNEXTLINE(google-default-arguments)
    virtual ir::TSIndexSignature *ParseIndexSignature([[maybe_unused]] const lexer::SourcePosition &start_loc,
                                                      [[maybe_unused]] bool is_readonly = false)
    {
        return nullptr;
    }
    virtual ir::AstNode *ParsePropertyOrMethodSignature([[maybe_unused]] const lexer::SourcePosition &start_loc,
                                                        [[maybe_unused]] bool is_readonly)
    {
        return nullptr;
    }
    virtual std::tuple<ir::Expression *, bool> ParseInterfacePropertyKey()
    {
        return {nullptr, false};
    }
    virtual ir::TypeNode *ParseClassKeyAnnotation()
    {
        return nullptr;
    }
    virtual ir::TypeNode *ParseTypeAnnotation([[maybe_unused]] TypeAnnotationParsingOptions *options)
    {
        return nullptr;
    }
    virtual void AddDecorators([[maybe_unused]] ir::AstNode *node,
                               [[maybe_unused]] ArenaVector<ir::Decorator *> &decorators)
    {
    }

    ir::VariableDeclarator *ParseVariableDeclarator(ir::Expression *init, lexer::SourcePosition start_loc,
                                                    VariableParsingFlags flags) override;

    virtual util::StringView FormInterfaceOrEnumDeclarationIdBinding(ir::Identifier *id);

    using InterfaceId = std::tuple<ir::Identifier *, binder::InterfaceDecl *, bool>;
    InterfaceId ParseInterfaceDeclarationId();

    void BindInterfaceDeclarationId(binder::InterfaceDecl *decl, bool already_exists,
                                    ir::TSInterfaceDeclaration *interface_decl);

    virtual bool AllowInterfaceRedeclaration()
    {
        return false;
    }

    // NOLINTNEXTLINE(google-default-arguments)
    virtual void CreateCCtor([[maybe_unused]] binder::LocalScope *class_scope,
                             [[maybe_unused]] ArenaVector<ir::AstNode *> &properties,
                             [[maybe_unused]] const lexer::SourcePosition &loc,
                             [[maybe_unused]] bool in_global_class = false)
    {
    }
};
}  // namespace panda::es2panda::parser

#endif
