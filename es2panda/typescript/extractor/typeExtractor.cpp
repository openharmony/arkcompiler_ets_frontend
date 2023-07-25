/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "typeExtractor.h"

#include <binder/binder.h>
#include <binder/tsBinding.h>
#include <ir/base/spreadElement.h>
#include <ir/expressions/callExpression.h>
#include <ir/expressions/classExpression.h>
#include <ir/expressions/memberExpression.h>
#include <ir/expressions/newExpression.h>
#include <ir/module/exportNamedDeclaration.h>
#include <ir/statements/expressionStatement.h>
#include <ir/statements/variableDeclaration.h>
#include <ir/statements/variableDeclarator.h>
#include <ir/ts/tsAsExpression.h>
#include <ir/ts/tsClassImplements.h>
#include <ir/ts/tsImportEqualsDeclaration.h>
#include <ir/ts/tsLiteralType.h>
#include <ir/ts/tsModuleDeclaration.h>
#include <ir/ts/tsParenthesizedType.h>
#include <ir/ts/tsQualifiedName.h>
#include <ir/ts/tsTypeAliasDeclaration.h>
#include <ir/ts/tsTypeAssertion.h>
#include <ir/ts/tsTypeParameterInstantiation.h>
#include <ir/ts/tsTypeReference.h>
#include <parser/module/sourceTextModuleRecord.h>

#include "typeSystem.h"

namespace panda::es2panda::extractor {

#ifndef NDEBUG
#define TLOG(type, res)                                                                                        \
    do {                                                                                                       \
        std::cout << "[LOG]" << __func__ << ": " << static_cast<int64_t>(type) << " | " << (res) << std::endl; \
    } while (0)
#else
#define TLOG(type, res) static_cast<void>(0)
#endif

const std::set<ir::AstNodeType> PRUNING_SET = {
    ir::AstNodeType::IDENTIFIER,
    ir::AstNodeType::TS_INTERFACE_DECLARATION,
    ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION,
    ir::AstNodeType::IMPORT_DECLARATION,
    ir::AstNodeType::EXPORT_ALL_DECLARATION
};

TypeExtractor::TypeExtractor(const ir::BlockStatement *rootNode, bool typeDtsExtractor, bool typeDtsBuiltin,
                             ArenaAllocator *allocator, compiler::CompilerContext *context)
    : rootNode_(rootNode), typeDtsExtractor_(typeDtsExtractor), typeDtsBuiltin_(typeDtsBuiltin)
{
    recorder_ = std::make_unique<TypeRecorder>(allocator, context);

    getterMap_[ir::AstNodeType::IDENTIFIER] =
        std::bind(&TypeExtractor::GetTypeIndexFromIdentifierNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::CLASS_EXPRESSION] =
        std::bind(&TypeExtractor::GetTypeIndexFromClassExpression, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::CLASS_DEFINITION] =
        std::bind(&TypeExtractor::GetTypeIndexFromClassDefinition, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::TS_INTERFACE_DECLARATION] =
        std::bind(&TypeExtractor::GetTypeIndexFromInterfaceNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::FUNCTION_EXPRESSION] =
        std::bind(&TypeExtractor::GetTypeIndexFromFunctionNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::ARROW_FUNCTION_EXPRESSION] =
        std::bind(&TypeExtractor::GetTypeIndexFromFunctionNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::IMPORT_NAMESPACE_SPECIFIER] =
        std::bind(&TypeExtractor::GetTypeIndexFromImportNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::IMPORT_SPECIFIER] =
        std::bind(&TypeExtractor::GetTypeIndexFromImportNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::IMPORT_DEFAULT_SPECIFIER] =
        std::bind(&TypeExtractor::GetTypeIndexFromImportNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION] =
        std::bind(&TypeExtractor::GetTypeIndexFromTypeAliasNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::TS_AS_EXPRESSION] =
        std::bind(&TypeExtractor::GetTypeIndexFromAsNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::TS_TYPE_ASSERTION] =
        std::bind(&TypeExtractor::GetTypeIndexFromAssertionNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::MEMBER_EXPRESSION] =
        std::bind(&TypeExtractor::GetTypeIndexFromMemberNode, this, std::placeholders::_1, std::placeholders::_2);
    getterMap_[ir::AstNodeType::TS_QUALIFIED_NAME] =
        std::bind(&TypeExtractor::GetTypeIndexFromTSQualifiedNode, this, std::placeholders::_1, std::placeholders::_2);

    handlerMap_[ir::AstNodeType::VARIABLE_DECLARATION] =
        std::bind(&TypeExtractor::HandleVariableDeclaration, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::FUNCTION_DECLARATION] =
        std::bind(&TypeExtractor::HandleFunctionDeclaration, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::CLASS_DECLARATION] =
        std::bind(&TypeExtractor::HandleClassDeclaration, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::TS_INTERFACE_DECLARATION] =
        std::bind(&TypeExtractor::HandleInterfaceDeclaration, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION] =
        std::bind(&TypeExtractor::HandleTypeAliasDeclaration, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::EXPRESSION_STATEMENT] =
        std::bind(&TypeExtractor::HandleNewlyGenFuncExpression, this, std::placeholders::_1);
    handlerMap_[ir::AstNodeType::ARROW_FUNCTION_EXPRESSION] =
        std::bind(&TypeExtractor::HandleArrowFunctionExpression, this, std::placeholders::_1);
}

void TypeExtractor::StartTypeExtractor(const parser::Program *program)
{
    ASSERT(rootNode_->IsProgram());

    TypeCounter counter(this);

    ExtractImport(program);
    ExtractNodesType(rootNode_);
    ExtractExport(program);

    recorder_->Dump(program);
    recorder_->SetTypeSummaryIndex(counter.GetTypeIndexPlaceHolder());
    counter.FillLiteralBuffer();
}

bool TypeExtractor::GetTypeDtsExtractor() const
{
    return typeDtsExtractor_;
}

bool TypeExtractor::GetTypeDtsBuiltin() const
{
    return typeDtsBuiltin_;
}

TypeRecorder *TypeExtractor::Recorder() const
{
    return recorder_.get();
}

void TypeExtractor::ExtractNodesType(const ir::AstNode *parent)
{
    parent->Iterate([this, parent](const auto *childNode) {
        ExtractNodeType(parent, childNode);
    });
}

void TypeExtractor::ExtractNodeType(const ir::AstNode *parent, const ir::AstNode *childNode)
{
    auto iter = handlerMap_.find(childNode->Type());
    if (iter != handlerMap_.end()) {
        iter->second(childNode);
    }

    // Traversal pruning
    if (PRUNING_SET.find(childNode->Type()) != PRUNING_SET.end()) {
        return;
    }

    ExtractNodesType(childNode);
}

void TypeExtractor::ExtractImport(const parser::Program *program)
{
    auto moduleRecord = program->Binder()->Program()->ModuleRecord();
    if (moduleRecord == nullptr) {
        return;
    }
    ExtractImportModuleRecord(moduleRecord);

    auto typeModuleRecord = program->Binder()->Program()->TypeModuleRecord();
    if (typeModuleRecord == nullptr) {
        return;
    }
    ExtractImportModuleRecord(typeModuleRecord);
}

void TypeExtractor::ExtractImportModuleRecord(parser::SourceTextModuleRecord *moduleRecord)
{
    const auto &regularImportEntries = moduleRecord->GetRegularImportEntries();
    for (const auto &t : regularImportEntries) {
        const auto &redirectPath = moduleRecord->GetModuleRequestIdxMap().at(t.second->moduleRequestIdx_);
        ExternalType externalType(this, t.first, redirectPath);
        recorder_->SetNodeTypeIndex(t.second->localId_->Parent(), externalType.GetTypeIndexShift());
    }

    const auto &namespaceImportEntries = moduleRecord->GetNamespaceImportEntries();
    for (const auto &t : namespaceImportEntries) {
        /*
         * eg. export * as ns from './test'
         */
        if (t->localId_ == nullptr) {
            continue;
        }
        const auto &redirectPath = moduleRecord->GetModuleRequestIdxMap().at(t->moduleRequestIdx_);
        ExternalType externalType(this, "*", redirectPath);
        recorder_->SetNodeTypeIndex(t->localId_->Parent(), externalType.GetTypeIndexShift());
        recorder_->SetNamespaceType(std::string(t->localName_), externalType.GetTypeIndexShift());
        recorder_->SetNamespacePath(std::string(t->localName_), std::string(redirectPath));
    }
}

void TypeExtractor::ExtractExport(const parser::Program *program)
{
    auto moduleRecord = program->Binder()->Program()->ModuleRecord();
    if (moduleRecord == nullptr) {
        return;
    }
    ExtractExportModuleRecord(moduleRecord);
    auto typeModuleRecord = program->Binder()->Program()->TypeModuleRecord();
    if (typeModuleRecord == nullptr) {
        return;
    }
    ExtractExportModuleRecord(typeModuleRecord);
}

void TypeExtractor::ExtractExportModuleRecord(parser::SourceTextModuleRecord *moduleRecord)
{
    const auto &localExportEntries = moduleRecord->GetLocalExportEntries();
    for (const auto &t : localExportEntries) {
        auto identifier = t.second->localId_;
        if (identifier == nullptr) {
            if (t.second->exportId_ != nullptr) {
                // Special case for NamespaceExport transform
                // Refer to parser/statementParser.cpp `AddExportStarEntryItem`
                recorder_->SetExportType(std::string(t.second->exportName_),
                    recorder_->GetNamespaceType(std::string(t.second->localName_)));
            }
            // Other export extries without local identifier is handled during traversal
            continue;
        }
        auto typeIndex = recorder_->GetVariableTypeIndex(identifier->Variable());
        if (typeIndex != PrimitiveType::ANY) {
            recorder_->SetExportType(std::string(t.second->exportName_), typeIndex);
            continue;
        }
        if (identifier->Variable() != nullptr && identifier->Variable()->Declaration() != nullptr) {
            auto declNode = identifier->Variable()->Declaration()->Node();
            typeIndex = recorder_->GetNodeTypeIndex(declNode);
            if (typeIndex == PrimitiveType::ANY && declNode != nullptr) {
                typeIndex = GetTypeIndexFromDeclNode(declNode, true);
                recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
            }
            if (typeIndex != PrimitiveType::ANY) {
                recorder_->SetExportType(std::string(t.second->exportName_), typeIndex);
            }
        }
    }

    const auto &starExportEntries = moduleRecord->GetStarExportEntries();
    for (const auto &t : starExportEntries) {
        recorder_->AddAnonymousReExport(moduleRecord->GetModuleRequestIdxMap().at(t->moduleRequestIdx_));
    }

    const auto &indirectExportEntries = moduleRecord->GetIndirectExportEntries();
    for (const auto &t : indirectExportEntries) {
        const auto &redirectPath = moduleRecord->GetModuleRequestIdxMap().at(t->moduleRequestIdx_);
        ExternalType externalType(this, t->importName_, redirectPath);
        recorder_->SetExportType(std::string(t->exportName_), externalType.GetTypeIndexShift());
    }
}

const ir::Identifier *TypeExtractor::GetIdentifierFromExpression(const ir::Expression *expression)
{
    switch (expression->Type()) {
        case ir::AstNodeType::IDENTIFIER:
            return expression->AsIdentifier();
        case ir::AstNodeType::REST_ELEMENT: {
            auto argument = expression->AsRestElement()->Argument();
            if (argument->IsIdentifier()) {
                return argument->AsIdentifier();
            }
            return nullptr;
        }
        case ir::AstNodeType::SPREAD_ELEMENT: {
            auto argument = expression->AsSpreadElement()->Argument();
            if (argument->IsIdentifier()) {
                return argument->AsIdentifier();
            }
            return nullptr;
        }
        default:
            return nullptr;
    }
}

const ir::AstNode *TypeExtractor::GetDeclNodeFromIdentifier(const ir::Identifier *identifier,
    const ir::Identifier **variable)
{
    if (identifier == nullptr) {
        return nullptr;
    }

    std::vector<binder::Variable *> variables;
    variables.reserve(identifier->TSVariables().size() + 1U);
    variables.emplace_back(identifier->Variable());
    for (const auto &v : identifier->TSVariables()) {
        variables.emplace_back(v);
    }

    for (const auto &v : variables) {
        if (v == nullptr || v->Declaration() == nullptr || v->Declaration()->Node() == nullptr) {
            continue;
        }

        auto res = v->Declaration()->Node();
        // Save reference identifier if it contains variable binding to decl node
        // TODO(extractor): consider js&ts decl node merging, for example
        // class A { a : string = "aaa" }
        // interface A { b : number }
        // let a : A = new A()
        // console.log(a.b)
        *variable = identifier;
        TLOG(res->Type(), identifier);
        return res;
    }
    return nullptr;
}

const ir::AstNode *TypeExtractor::GetDeclNodeFromInitializer(const ir::Expression *initializer,
    const ir::Identifier **variable)
{
    switch (initializer->Type()) {
        case ir::AstNodeType::IDENTIFIER:  // let a = b / let a : A
            return GetDeclNodeFromIdentifier(initializer->AsIdentifier(), variable);
        case ir::AstNodeType::NEW_EXPRESSION: {
            auto callee = initializer->AsNewExpression()->Callee();
            if (callee->IsClassExpression()) {  // let a = new class {}
                return callee;
            } else if (callee->IsIdentifier()) {  // let a = new A()
                return GetDeclNodeFromIdentifier(callee->AsIdentifier(), variable);
            }
            break;
        }
        case ir::AstNodeType::TS_CLASS_IMPLEMENTS: {  // class a implements A {}
            auto expr = initializer->AsTSClassImplements()->Expr();
            if (expr->IsIdentifier()) {
                return GetDeclNodeFromIdentifier(expr->AsIdentifier(), variable);
            }
            ASSERT(expr->IsTSQualifiedName());
            return expr->AsTSQualifiedName();
        }
        case ir::AstNodeType::CLASS_EXPRESSION:  // let a = class A {}
        case ir::AstNodeType::FUNCTION_EXPRESSION:  // let a = function func () {}
        case ir::AstNodeType::ARROW_FUNCTION_EXPRESSION:  // let a = () => {}
        case ir::AstNodeType::MEMBER_EXPRESSION:  // let a = ns.A
        case ir::AstNodeType::TS_QUALIFIED_NAME:  // let a : ns.A
        case ir::AstNodeType::TS_AS_EXPRESSION:  // let a = x as number
        case ir::AstNodeType::TS_TYPE_ASSERTION:  // let a = <number>x
            return initializer;
        default:
            break;
    }

    auto identifier = GetIdentifierFromExpression(initializer);
    if (identifier != nullptr) {
        return GetDeclNodeFromIdentifier(identifier, variable);
    }
    return nullptr;
}

int64_t TypeExtractor::GetTypeIndexFromDeclNode(const ir::AstNode *node, bool isNewInstance)
{
    auto iter = getterMap_.find(node->Type());
    if (iter != getterMap_.end()) {
        return iter->second(node, isNewInstance);
    }
    return PrimitiveType::ANY;
}

int64_t TypeExtractor::GetTypeIndexFromIdentifierNode(const ir::AstNode *node, bool isNewInstance)
{
    auto typeIndex = recorder_->GetNodeTypeIndex(node);
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromClassExpression(const ir::AstNode *node, bool isNewInstance)
{
    auto classDef = node->AsClassExpression()->Definition();
    auto typeIndex = GetTypeIndexFromClassDefinition(classDef, isNewInstance);
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromClassDefinition(const ir::AstNode *node, bool isNewInstance)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto fn = [&node, &typeIndex, this](const util::StringView &name) {
        ClassType classType(this, node->AsClassDefinition(), name);
        typeIndex = classType.GetTypeIndexShift();
    };

    auto identifier = node->AsClassDefinition()->Ident();
    if (identifier != nullptr) {
        fn(identifier->Name());
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    } else {
        fn(std::move(DEFAULT_NAME));
    }

    if (isNewInstance) {
        typeIndex = GetTypeIndexFromClassInst(typeIndex, node);
    }

    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromInterfaceNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto fn = [&node, &typeIndex, this](const util::StringView &name) {
        InterfaceType interfaceType(this, node->AsTSInterfaceDeclaration(), name);
        typeIndex = interfaceType.GetTypeIndexShift();
    };

    auto identifier = node->AsTSInterfaceDeclaration()->Id();
    if (identifier != nullptr) {
        fn(identifier->Name());
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    } else {
        fn(std::move(DEFAULT_NAME));
    }

    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromFunctionNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto fn = [&node, &typeIndex, this](const util::StringView &name) {
        FunctionType functionType(this, node, name);
        typeIndex = functionType.GetTypeIndexShift();
    };

    if (node->IsFunctionExpression()) {
        auto identifier = node->AsFunctionExpression()->Function()->Id();
        if (identifier != nullptr) {
            fn(identifier->Name());
            recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
        } else {
            fn("");
        }
    } else {
        fn("");
    }

    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromImportNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    auto typeIndex = recorder_->GetNodeTypeIndex(node);
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromTypeAliasNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    auto typeNode = node->AsTSTypeAliasDeclaration()->TypeAnnotation();
    if (!AddSearchingTypeRefNodes(typeNode)) {
        RemoveSearchingTypeRefNodes(typeNode);
        return PrimitiveType::ANY;
    }
    auto typeIndex = GetTypeIndexFromAnnotation(typeNode);
    TLOG(node->Type(), typeIndex);
    RemoveSearchingTypeRefNodes(typeNode);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromAsNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    auto typeIndex = GetTypeIndexFromAnnotation(node->AsTSAsExpression()->TypeAnnotation());
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromAssertionNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    auto typeIndex = GetTypeIndexFromAnnotation(node->AsTSTypeAssertion()->TypeAnnotation());
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromMemberNode(const ir::AstNode *node, [[maybe_unused]] bool isNewInstance)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto object = node->AsMemberExpression()->Object();
    auto property = node->AsMemberExpression()->Property();
    if (object->IsIdentifier() && property->IsIdentifier()) {
        auto redirectPath = recorder_->GetNamespacePath(std::string(object->AsIdentifier()->Name()));
        if (redirectPath != "") {
            ExternalType externalType(this, property->AsIdentifier()->Name(), util::StringView(redirectPath));
            typeIndex = externalType.GetTypeIndexShift();
        }
    }
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromTSQualifiedNode(const ir::AstNode *node, bool isNewInstance)
{
    ArenaDeque<const ir::Identifier *> identifiers(recorder_->Allocator()->Adapter());
    const ir::Expression *head = node->AsTSQualifiedName();
    while (head->IsTSQualifiedName()) {
        identifiers.emplace_front(head->AsTSQualifiedName()->Right());
        head = head->AsTSQualifiedName()->Left();
    }

    ASSERT(head->IsIdentifier());
    ArenaVector<const binder::Variable *> variables(recorder_->Allocator()->Adapter());
    for (const auto &v : head->AsIdentifier()->TSVariables()) {
        GetVariablesFromTSQualifiedNodes(v, identifiers, variables);
    }

    int64_t typeIndex = PrimitiveType::ANY;
    for (const auto &v : variables) {
        if (v->Declaration() != nullptr && v->Declaration()->Node() != nullptr) {
            typeIndex = GetTypeIndexFromDeclNode(v->Declaration()->Node(), isNewInstance);
            if (typeIndex != PrimitiveType::ANY) {
                break;
            }
        }
    }
    if (typeIndex == PrimitiveType::ANY) {
        auto left = node->AsTSQualifiedName()->Left();
        auto right = node->AsTSQualifiedName()->Right();
        if (left->IsIdentifier()) {
            auto redirectPath = recorder_->GetNamespacePath(std::string(left->AsIdentifier()->Name()));
            if (redirectPath != "") {
                ExternalType externalType(this, right->Name(), util::StringView(redirectPath));
                typeIndex = externalType.GetTypeIndexShift();
            }
        }
    }
    TLOG(node->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromAnnotation(const ir::Expression *typeAnnotation, bool isNewInstance)
{
    if (typeAnnotation == nullptr) {
        return PrimitiveType::ANY;
    }

    switch (typeAnnotation->AsTypeNode()->Type()) {
        case ir::AstNodeType::TS_ANY_KEYWORD:
        case ir::AstNodeType::TS_NUMBER_KEYWORD:
        case ir::AstNodeType::TS_BOOLEAN_KEYWORD:
        case ir::AstNodeType::TS_VOID_KEYWORD:
        case ir::AstNodeType::TS_STRING_KEYWORD:
        case ir::AstNodeType::TS_SYMBOL_KEYWORD:
        case ir::AstNodeType::TS_NULL_KEYWORD:
        case ir::AstNodeType::TS_UNDEFINED_KEYWORD:
            return PRIMITIVE_TYPE_MAP.at(typeAnnotation->AsTypeNode()->Type());
        case ir::AstNodeType::TS_LITERAL_TYPE:
            return GetTypeIndexFromTSLiteralType(typeAnnotation->AsTSLiteralType());
        case ir::AstNodeType::TS_NEVER_KEYWORD:
        case ir::AstNodeType::TS_UNKNOWN_KEYWORD:
            return PrimitiveType::ANY;
        case ir::AstNodeType::TS_ARRAY_TYPE: {  // ArrayType
            ArrayType arrayType(this, typeAnnotation->AsTSArrayType());
            return arrayType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_UNION_TYPE: {  // UnionType
            UnionType unionType(this, typeAnnotation->AsTSUnionType());
            return unionType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_PARENT_TYPE: { // (UnionType) / (FunctionType)
            auto type = typeAnnotation->AsTSParenthesizedType()->Type();
            ASSERT(type != nullptr);
            if (type->IsTSUnionType()) {
                UnionType unionType(this, type->AsTSUnionType());
                return unionType.GetTypeIndexShift();
            } else if (type->IsTSFunctionType()) {
                FunctionType functionType(this, type->AsTSFunctionType(), "");
                return functionType.GetTypeIndexShift();
            } else if (type->IsTSConstructorType()) {
                FunctionType functionType(this, type->AsTSConstructorType(), "");
                return functionType.GetTypeIndexShift();
            }
            return PrimitiveType::ANY;
        }
        case ir::AstNodeType::TS_TYPE_LITERAL: {  // ObjectType
            ObjectType objectType(this, typeAnnotation->AsTSTypeLiteral());
            return objectType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_OBJECT_KEYWORD: {  // ObjectType
            ObjectType objectType(this, nullptr);  // let a : object
            return objectType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_FUNCTION_TYPE: {  // FunctionType, let a : () => {}
            FunctionType functionType(this, typeAnnotation->AsTSFunctionType(), "");
            return functionType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_CONSTRUCTOR_TYPE: {  // FunctionType, let a : new () => {}
            FunctionType functionType(this, typeAnnotation->AsTSConstructorType(), "");
            return functionType.GetTypeIndexShift();
        }
        case ir::AstNodeType::TS_BIGINT_KEYWORD:
        case ir::AstNodeType::TS_CONDITIONAL_TYPE:
        case ir::AstNodeType::TS_IMPORT_TYPE:
        case ir::AstNodeType::TS_INDEXED_ACCESS_TYPE:
        case ir::AstNodeType::TS_INTERSECTION_TYPE:
        case ir::AstNodeType::TS_INFER_TYPE:
        case ir::AstNodeType::TS_MAPPED_TYPE:
        case ir::AstNodeType::TS_OPTIONAL_TYPE:
        case ir::AstNodeType::TS_REST_TYPE:
        case ir::AstNodeType::TS_TEMPLATE_LITERAL_TYPE:
        case ir::AstNodeType::TS_THIS_TYPE:
        case ir::AstNodeType::TS_TUPLE_TYPE:
        case ir::AstNodeType::TS_TYPE_OPERATOR:
        case ir::AstNodeType::TS_TYPE_PREDICATE:
        case ir::AstNodeType::TS_TYPE_QUERY:
            return PrimitiveType::ANY;
        case ir::AstNodeType::TS_TYPE_REFERENCE: {  // let a : A
            return GetTypeIndexFromTypeReference(typeAnnotation->AsTSTypeReference(), isNewInstance);
        }
        default:
            UNREACHABLE();
    }
}

int64_t TypeExtractor::GetTypeIndexFromIdentifier(const ir::Identifier *identifier)
{
    auto typeAnnotation = identifier->TypeAnnotation();
    auto typeIndex = GetTypeIndexFromAnnotation(typeAnnotation);
    recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    TLOG(identifier->Type(), typeIndex);
    return typeIndex;
}

int64_t TypeExtractor::GetTypeIndexFromInitializer(const ir::Expression *initializer)
{
    int64_t typeIndex = PrimitiveType::ANY;
    // Special case for Builtin
    if (initializer->IsNewExpression()) {
        auto callee = initializer->AsNewExpression()->Callee();
        if (callee->IsIdentifier()) {
            typeIndex = GetTypeIndexFromBuiltin(callee->AsIdentifier()->Name(),
                initializer->AsNewExpression()->TypeParams());
            if (typeIndex != PrimitiveType::ANY) {
                return typeIndex;
            }
        }
    }

    const ir::Identifier *identifier = nullptr;
    // Identifier here is a reference identifier binding to decl node which also contains variable
    auto declNode = GetDeclNodeFromInitializer(initializer, &identifier);
    if (declNode != nullptr) {
        if (initializer->IsNewExpression() && initializer->AsNewExpression()->TypeParams() != nullptr) {
            typeIndex = GetTypeIndexFromGenericInst(declNode, initializer->AsNewExpression()->TypeParams());
        } else {
            typeIndex = GetTypeIndexFromDeclNode(declNode, initializer->IsNewExpression());
        }
        recorder_->SetIdentifierTypeIndex(identifier, recorder_->GetClassType(typeIndex));
    }
    TLOG(initializer->Type(), typeIndex);
    return typeIndex;
}

void TypeExtractor::HandleVariableDeclaration(const ir::AstNode *node)
{
    auto isExported = IsExportNode(node);
    for (const auto *it : node->AsVariableDeclaration()->Declarators()) {
        if (!it->Id()->IsIdentifier()) {
            // BindingElement needs type inference, like:
            // ArrayExpression: let [a, b] = [1, 2]
            // ObjectExpression: let {a, b} = c
            continue;
        }
        auto identifier = it->Id()->AsIdentifier();
        ASSERT(identifier != nullptr);
        auto typeIndex = GetTypeIndexFromIdentifier(identifier);
        if (typeIndex == PrimitiveType::ANY && it->Init() != nullptr) {
            typeIndex = GetTypeIndexFromInitializer(it->Init());
        }
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
        if (isExported && typeIndex != PrimitiveType::ANY) {
            recorder_->SetExportType(std::string(identifier->Name()), typeIndex);
        }
    }
}

void TypeExtractor::HandleFunctionDeclaration(const ir::AstNode *node)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto fn = [&node, &typeIndex, this](const util::StringView &name) {
        FunctionType functionType(this, node, name);
        typeIndex = functionType.GetTypeIndexShift();
        if (IsExportNode(node)) {
            recorder_->SetExportType(std::string(name), typeIndex);
        }
        if (IsDeclareNode(node)) {
            recorder_->SetDeclareType(std::string(name), typeIndex);
        }
    };

    auto identifier = node->AsFunctionDeclaration()->Function()->Id();
    if (identifier != nullptr) {
        fn(identifier->Name());
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    } else {
        fn("");
    }
}

void TypeExtractor::HandleClassDeclaration(const ir::AstNode *node)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto classDef = node->AsClassDeclaration()->Definition();
    auto fn = [&node, &typeIndex, &classDef, this](const util::StringView &name) {
        ClassType classType(this, classDef, name);
        typeIndex = classType.GetTypeIndexShift();
        if (IsExportNode(node)) {
            recorder_->SetExportType(std::string(name), typeIndex);
        }
        if (IsDeclareNode(node)) {
            recorder_->SetDeclareType(std::string(name), typeIndex);
        }
    };

    auto identifier = classDef->Ident();
    if (identifier != nullptr) {
        fn(identifier->Name());
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    } else {
        fn(std::move(DEFAULT_NAME));
    }
}

void TypeExtractor::HandleInterfaceDeclaration(const ir::AstNode *node)
{
    int64_t typeIndex = PrimitiveType::ANY;
    auto interfaceDef = node->AsTSInterfaceDeclaration();
    auto fn = [&node, &typeIndex, &interfaceDef, this](const util::StringView &name) {
        InterfaceType interfaceType(this, interfaceDef, name);
        typeIndex = interfaceType.GetTypeIndexShift();
        if (IsExportNode(node)) {
            recorder_->SetExportType(std::string(name), typeIndex);
        }
        if (IsDeclareNode(node)) {
            recorder_->SetDeclareType(std::string(name), typeIndex);
        }
    };

    auto identifier = interfaceDef->Id();
    if (identifier != nullptr) {
        fn(identifier->Name());
        recorder_->SetIdentifierTypeIndex(identifier, typeIndex);
    } else {
        fn(std::move(DEFAULT_NAME));
    }
}

void TypeExtractor::HandleTypeAliasDeclaration(const ir::AstNode *node)
{
    // Create the type if it is exported or declared
    auto typeAliasDef = node->AsTSTypeAliasDeclaration();
    auto identifier = typeAliasDef->Id();
    if (IsExportNode(node)) {
        recorder_->SetExportType(std::string(identifier->Name()),
            GetTypeIndexFromAnnotation(typeAliasDef->TypeAnnotation()));
    }
    if (IsDeclareNode(node)) {
        recorder_->SetDeclareType(std::string(identifier->Name()),
            GetTypeIndexFromAnnotation(typeAliasDef->TypeAnnotation()));
    }
}

void TypeExtractor::HandleNewlyGenFuncExpression(const ir::AstNode *node)
{
    if (!node->Original()) {
        return;
    }
    auto originalNode = node->Original();
    int64_t typeFlag = PrimitiveType::ANY;
    switch (originalNode->Type()) {
        case ir::AstNodeType::TS_MODULE_DECLARATION: {
            typeFlag = extractor::BuiltinFlag::NAMESPACE_FUNCTION;
            break;
        }
        case ir::AstNodeType::TS_ENUM_DECLARATION: {
            typeFlag = extractor::BuiltinFlag::ENUM_FUNCTION;
            break;
        }
        case ir::AstNodeType::EXPORT_NAMED_DECLARATION: {
            auto decl = originalNode->AsExportNamedDeclaration()->Decl();
            if (!decl) {
                return;
            }
            if (decl->IsTSModuleDeclaration()) {
                typeFlag = extractor::BuiltinFlag::NAMESPACE_FUNCTION;
            } else if (decl->IsTSEnumDeclaration()) {
                typeFlag = extractor::BuiltinFlag::ENUM_FUNCTION;
            }
            break;
        }
        default: {
            return;
        }
    }
    if (typeFlag != PrimitiveType::ANY) {
        auto funcExpr = node->AsExpressionStatement()->GetExpression()->AsCallExpression()->Callee();
        recorder_->SetNodeTypeIndex(funcExpr->AsFunctionExpression()->Function(), typeFlag);
    }
}

void TypeExtractor::HandleArrowFunctionExpression(const ir::AstNode *node)
{
    ASSERT(node->IsArrowFunctionExpression());
    auto typeIndex = recorder_->GetNodeTypeIndex(node->AsArrowFunctionExpression()->Function());
    if (typeIndex != PrimitiveType::ANY) {
        return;
    }
    GetTypeIndexFromFunctionNode(node, false);
}

int64_t TypeExtractor::GetTypeIndexFromClassInst(int64_t typeIndex, const ir::AstNode *node, int64_t builtinTypeIndex)
{
    // A class instance type should point to a class type or a builtin type
    ASSERT((node == nullptr) ^ (builtinTypeIndex == PrimitiveType::ANY));
    if (node && !node->IsClassDefinition()) {
        return PrimitiveType::ANY;
    }

    if (builtinTypeIndex != PrimitiveType::ANY && !recorder_->isBuiltinType(builtinTypeIndex)) {
        return PrimitiveType::ANY;
    }

    auto typeIndexTmp = recorder_->GetClassInst(typeIndex);
    if (typeIndexTmp == PrimitiveType::ANY) {
        ClassInstType classInstType(this, typeIndex);
        return classInstType.GetTypeIndexShift();
    }
    return typeIndexTmp;
}

int64_t TypeExtractor::GetTypeIndexFromTypeReference(const ir::TSTypeReference *typeReference, bool isNewInstance)
{
    auto typeName = typeReference->TypeName();
    ASSERT(typeName != nullptr);
    if (typeName->IsIdentifier()) {
        const auto &name = typeName->AsIdentifier()->Name();
        // First, consider if the type identify is Builtin Type
        auto typeIndexBuiltin = GetTypeIndexFromBuiltin(name, typeReference->TypeParams());
        if (typeIndexBuiltin != PrimitiveType::ANY) {
            return typeIndexBuiltin;
        }
        // Second, consider if the type identify is Generic Type
        auto genericParamTypeMap = GetGenericParamTypeMap();
        if (genericParamTypeMap != nullptr) {
            auto t = genericParamTypeMap->find(name);
            if (t != genericParamTypeMap->end()) {
                return t->second;
            }
        }
    }

    const ir::Identifier *identifier = nullptr;
    // TypeName can be Identifier or TSQualifiedName
    // Identifier here is a reference identifier binding to decl node which also contains variable
    auto declNode = GetDeclNodeFromInitializer(typeName, &identifier);
    if (declNode != nullptr) {
        int64_t typeIndex = PrimitiveType::ANY;
        if (typeReference->TypeParams() != nullptr) {
            typeIndex = GetTypeIndexFromGenericInst(declNode, typeReference->TypeParams());
        } else {
            typeIndex = GetTypeIndexFromDeclNode(declNode, isNewInstance);
        }
        recorder_->SetIdentifierTypeIndex(identifier, recorder_->GetClassType(typeIndex));
        return typeIndex;
    }
    return PrimitiveType::ANY;
}

int64_t TypeExtractor::GetTypeIndexFromTSLiteralType(const ir::TSLiteralType *tsLiteralType)
{
    switch (tsLiteralType->Literal()->Type()) {
        case ir::AstNodeType::NUMBER_LITERAL:
            return PrimitiveType::NUMBER;
        case ir::AstNodeType::BOOLEAN_LITERAL:
            return PrimitiveType::BOOLEAN;
        case ir::AstNodeType::STRING_LITERAL:
            return PrimitiveType::STRING;
        case ir::AstNodeType::NULL_LITERAL:
            return PrimitiveType::NUL;
        default:
            return PrimitiveType::ANY;
    }
}

int64_t TypeExtractor::GetTypeIndexFromBuiltin(const util::StringView &name,
                                               const ir::TSTypeParameterInstantiation *node)
{
    auto typeIndexBuiltin = GetBuiltinTypeIndex(name);
    if (typeIndexBuiltin != PrimitiveType::ANY) {
        if (node == nullptr) {
            return GetTypeIndexFromClassInst(typeIndexBuiltin, nullptr, typeIndexBuiltin);
        }
        return GetTypeIndexFromBuiltinInst(typeIndexBuiltin, node);
    }
    return PrimitiveType::ANY;
}

int64_t TypeExtractor::GetTypeIndexFromBuiltinInst(int64_t typeIndexBuiltin,
                                                   const ir::TSTypeParameterInstantiation *node)
{
    std::vector<int64_t> allTypes = {typeIndexBuiltin};
    for (const auto &t : node->Params()) {
        allTypes.emplace_back(GetTypeIndexFromAnnotation(t));
    }
    auto typeIndex = recorder_->GetBuiltinInst(allTypes);
    if (typeIndex != PrimitiveType::ANY) {
        return typeIndex;
    }

    // New instance for builtin generic type
    BuiltinInstType builtinInstType(this, allTypes);
    return GetTypeIndexFromClassInst(builtinInstType.GetTypeIndexShift(), nullptr, typeIndexBuiltin);
}

int64_t TypeExtractor::GetTypeIndexFromGenericInst(const ir::AstNode *declNode,
                                                   const ir::TSTypeParameterInstantiation *node)
{
    if (!declNode->IsClassDefinition()) {
        return PrimitiveType::ANY;
    }
    int64_t typeIndexGeneric = GetTypeIndexFromDeclNode(declNode, false);
    std::vector<int64_t> allTypes = {typeIndexGeneric};
    for (const auto &t : node->Params()) {
        allTypes.emplace_back(GetTypeIndexFromAnnotation(t));
    }
    auto typeIndex = recorder_->GetGenericInst(allTypes);
    if (typeIndex != PrimitiveType::ANY) {
        return typeIndex;
    }

    // New instance for generic type
    GenericInstType genericInstType(this, allTypes);
    return GetTypeIndexFromClassInst(genericInstType.GetTypeIndexShift(), declNode);
}

bool TypeExtractor::IsExportNode(const ir::AstNode *node) const
{
    auto parent = node->Parent();
    if (parent->Parent() != rootNode_) {
        return false;
    }
    if (parent->IsExportNamedDeclaration() || parent->IsExportDefaultDeclaration()) {
        return true;
    }
    return false;
}

bool TypeExtractor::IsDeclareNode(const ir::AstNode *node) const
{
    if (!typeDtsExtractor_) {
        return false;
    }
    switch (node->Type()) {
        case ir::AstNodeType::FUNCTION_DECLARATION:
            return node->AsFunctionDeclaration()->Function()->Declare();
        case ir::AstNodeType::CLASS_DEFINITION:
            return node->AsClassDefinition()->Declare();
        case ir::AstNodeType::TS_INTERFACE_DECLARATION:
            return true;
        case ir::AstNodeType::TS_TYPE_ALIAS_DECLARATION:
            return node->AsTSTypeAliasDeclaration()->Declare();
        default:
            break;
    }
    return false;
}

void TypeExtractor::GetVariablesFromTSQualifiedNodes(const binder::Variable *variable,
    ArenaDeque<const ir::Identifier *> &identifiers, ArenaVector<const binder::Variable *> &variables) const
{
    ASSERT(variable != nullptr);

    if (identifiers.empty()) {
        variables.emplace_back(variable);
        return;
    }
    switch (variable->Type()) {
        case binder::VariableType::ENUMLITERAL: {
            auto name = identifiers.front()->Name();
            identifiers.pop_front();
            auto findRes = variable->AsEnumLiteralVariable()->FindEnumMemberVariable(name);
            if (findRes != nullptr) {
                GetVariablesFromTSQualifiedNodes(findRes, identifiers, variables);
            }
            break;
        }
        case binder::VariableType::NAMESPACE: {
            ArenaVector<binder::Variable *> findRes(recorder_->Allocator()->Adapter());
            GetVariablesFromNamespace(variable->AsNamespaceVariable(), findRes, identifiers, variables);
            identifiers.pop_front();
            for (const auto &v : findRes) {
                GetVariablesFromTSQualifiedNodes(v, identifiers, variables);
            }
            break;
        }
        case binder::VariableType::IMPORT_EQUALS: {
            auto ref = variable->Declaration()->Node()->Parent()->AsTSImportEqualsDeclaration()->ModuleReference();
            while (ref->IsTSQualifiedName()) {
                identifiers.emplace_front(ref->AsTSQualifiedName()->Right());
                ref = ref->AsTSQualifiedName()->Left();
            }

            ASSERT(ref->IsIdentifier());
            for (const auto &v : ref->AsIdentifier()->TSVariables()) {
                if (v->Name() == ref->AsIdentifier()->Name()) {
                    GetVariablesFromTSQualifiedNodes(v, identifiers, variables);
                }
            }
            break;
        }
        default:
            break;
    }
}

void TypeExtractor::GetVariablesFromNamespace(const binder::NamespaceVariable *variable,
    ArenaVector<binder::Variable *> &findRes, ArenaDeque<const ir::Identifier *> &identifiers,
    ArenaVector<const binder::Variable *> &variables) const
{
    ASSERT(variable->IsNamespaceVariable());
    auto exportBindings = variable->GetExportBindings();
    if (!exportBindings) {
        return;
    }
    auto fn = [&findRes](binder::Variable *variable) {
        if (variable != nullptr) {
            findRes.emplace_back(variable);
        }
    };
    auto name = identifiers.front()->Name();
    if (identifiers.size() == 1U) {
        fn(exportBindings->FindExportVariable(name));
        if (findRes.empty()) {
            fn(exportBindings->FindExportVariable(util::StringView(binder::TSBinding::ToTSBinding(name))));
        }
    } else {
        fn(exportBindings->FindExportTSVariable<binder::TSBindingType::NAMESPACE>(name));
    }
    fn(exportBindings->FindExportTSVariable<binder::TSBindingType::ENUMLITERAL>(name));
    fn(exportBindings->FindExportTSVariable<binder::TSBindingType::IMPORT_EQUALS>(name));
}

// static
int64_t TypeExtractor::GetBuiltinTypeIndex(util::StringView name)
{
    auto t = BUILTIN_TYPE_MAP.find(std::string(name));
    if (t != BUILTIN_TYPE_MAP.end()) {
        return t->second;
    }
    return PrimitiveType::ANY;
}

}  // namespace panda::es2panda::extractor
