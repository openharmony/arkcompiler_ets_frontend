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

#include "transformer.h"

#include <util/ustring.h>

#include "ir/base/classDefinition.h"
#include "ir/base/classProperty.h"
#include "ir/base/decorator.h"
#include "ir/base/methodDefinition.h"
#include "ir/base/scriptFunction.h"
#include "ir/expressions/assignmentExpression.h"
#include "ir/expressions/binaryExpression.h"
#include "ir/expressions/callExpression.h"
#include "ir/expressions/classExpression.h"
#include "ir/expressions/functionExpression.h"
#include "ir/expressions/identifier.h"
#include "ir/expressions/literals/stringLiteral.h"
#include "ir/expressions/literals/numberLiteral.h"
#include "ir/expressions/literals/bigIntLiteral.h"
#include "ir/expressions/memberExpression.h"
#include "ir/expressions/objectExpression.h"
#include "ir/expressions/sequenceExpression.h"
#include "ir/expressions/thisExpression.h"
#include "ir/module/exportNamedDeclaration.h"
#include "ir/statements/blockStatement.h"
#include "ir/statements/classDeclaration.h"
#include "ir/statements/emptyStatement.h"
#include "ir/statements/expressionStatement.h"
#include "ir/statements/functionDeclaration.h"
#include "ir/statements/variableDeclaration.h"
#include "ir/statements/variableDeclarator.h"
#include "ir/ts/tsImportEqualsDeclaration.h"
#include "ir/ts/tsModuleBlock.h"
#include "ir/ts/tsModuleDeclaration.h"
#include "ir/ts/tsParameterProperty.h"
#include "ir/ts/tsPrivateIdentifier.h"
#include "ir/ts/tsQualifiedName.h"
#include "util/helpers.h"

namespace panda::es2panda::parser {

void Transformer::Transform(Program *program)
{
    program_ = program;
    if (Extension() == ScriptExtension::TS) {
        TransformFromTS();
    }
}

void Transformer::TransformFromTS()
{
    ASSERT(Extension() == ScriptExtension::TS);
    VisitTSNodes(program_->Ast());
    PushVariablesToNearestStatements(program_->Ast());
}

ir::AstNode *Transformer::VisitTSNodes(ir::AstNode *parent)
{
    if (!parent) {
        return nullptr;
    }
    parent->UpdateSelf([this](auto *childNode) { return VisitTSNode(childNode); }, Binder());
    return parent;
}

void Transformer::AddVariableToNearestStatements(util::StringView name)
{
    /*
     *  Add variable declare like 'var ##var_1;' to nearest statements in namespace function or top level scope
     *  Record the variable name and scope in tempVarDeclStatements_ and will push the VariableDeclaration nodes
     *  to statements in PushVariablesToNearestStatements
     */
    auto currentScope = Scope();
    while (currentScope != nullptr) {
        if (currentScope->IsTSModuleScope()) {
            auto node = currentScope->Node();
            ASSERT(node->IsTSModuleDeclaration());
            if (node->AsTSModuleDeclaration()->Body()->IsTSModuleBlock()) {
                break;
            }
        }
        if (currentScope->IsFunctionScope()) {
            auto node = currentScope->Node();
            ASSERT(node->IsScriptFunction());
            if (!node->AsScriptFunction()->FunctionBodyIsExpression()) {
                break;
            }
        }
        currentScope = currentScope->Parent();
    }
    tempVarDeclStatements_.insert({name, currentScope});
}

void Transformer::PushVariablesToNearestStatements(ir::BlockStatement *ast)
{
    /*
     *  Push the VariableDeclaration nodes to nearest statements
     *  For example, transform:
     *  namespace ns {
     *    ...
     *  }
     *
     *  To:
     *  namespace ns {
     *    var ##var_1;
     *    ...
     *  }
     */
    if (tempVarDeclStatements_.empty()) {
        return;
    }
    for (auto it : tempVarDeclStatements_) {
        auto *scope = it.second;
        if (scope == nullptr) {
            auto scopeCtx = binder::LexicalScope<binder::Scope>::Enter(Binder(), ast->Scope());
            ast->AddStatementInFront(CreateVariableDeclarationWithIdentify(it.first, VariableParsingFlags::VAR,
                nullptr, false));
        } else if (scope->IsFunctionScope()) {
            auto *body = scope->Node()->AsScriptFunction()->Body();
            ASSERT(body->IsBlockStatement());
            auto scopeCtx = binder::LexicalScope<binder::Scope>::Enter(Binder(), scope);
            body->AsBlockStatement()->AddStatementInFront(CreateVariableDeclarationWithIdentify(it.first,
                VariableParsingFlags::VAR, nullptr, false));
        } else if (scope->IsTSModuleScope()) {
            auto *body = scope->Node()->AsTSModuleDeclaration()->Body();
            ASSERT(body->IsTSModuleBlock());
            auto scopeCtx = binder::LexicalScope<binder::Scope>::Enter(Binder(), scope);
            body->AsTSModuleBlock()->AddStatementInFront(CreateVariableDeclarationWithIdentify(it.first,
                VariableParsingFlags::VAR, nullptr, false));
        }
    }
}

binder::Scope *Transformer::FindExportVariableInTsModuleScope(util::StringView name) const
{
    bool isExport = false;
    auto currentScope = Scope();
    while (currentScope != nullptr) {
        binder::Variable *v = currentScope->FindLocal(name, binder::ResolveBindingOptions::ALL);
        bool isTSModuleScope = currentScope->IsTSModuleScope();
        if (v != nullptr) {
            if (!v->HasFlag(binder::VariableFlags::VAR)) {
                break;
            }
            if (isTSModuleScope && currentScope->AsTSModuleScope()->FindExportVariable(name)) {
                isExport = true;
            }
            break;
        }
        if (currentScope->InLocalTSBindings(name) &&
            !currentScope->FindLocalTSVariable<binder::TSBindingType::IMPORT_EQUALS>(name)) {
            break;
        }
        if (isTSModuleScope && currentScope->AsTSModuleScope()->InExportBindings(name)) {
            isExport = true;
            break;
        }
        currentScope = currentScope->Parent();
    }
    if (!isExport) {
        return nullptr;
    }
    return currentScope;
}

ir::UpdateNodes Transformer::VisitTSNode(ir::AstNode *childNode)
{
    ASSERT(childNode != nullptr);
    switch (childNode->Type()) {
        case ir::AstNodeType::IDENTIFIER: {
            auto *ident = childNode->AsIdentifier();
            if (!ident->IsReference() || !IsTsModule()) {
                return VisitTSNodes(childNode);
            }

            auto name = ident->Name();
            auto scope = FindExportVariableInTsModuleScope(name);
            if (scope) {
                auto moduleName = FindTSModuleNameByScope(scope);
                auto *id = CreateReferenceIdentifier(moduleName);
                auto *res = AllocNode<ir::MemberExpression>(id, AllocNode<ir::Identifier>(name, Allocator()),
                    ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
                SetOriginalNode(res, childNode);
                return res;
            }

            return VisitTSNodes(childNode);
        }
        case ir::AstNodeType::TS_MODULE_DECLARATION: {
            auto *node = childNode->AsTSModuleDeclaration();
            if (node->Declare() || !node->IsInstantiated()) {
                return childNode;
            }
            auto res = VisitTsModuleDeclaration(node);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::EXPORT_NAMED_DECLARATION: {
            auto *node = childNode->AsExportNamedDeclaration();
            auto *decl = node->Decl();
            if (!decl) {
                return VisitTSNodes(childNode);
            }

            if (decl->IsTSModuleDeclaration()) {
                auto *tsModuleDeclaration = decl->AsTSModuleDeclaration();
                if (tsModuleDeclaration->Declare() || !tsModuleDeclaration->IsInstantiated()) {
                    return childNode;
                }
                auto res = VisitTsModuleDeclaration(tsModuleDeclaration, true);
                SetOriginalNode(res, childNode);
                return res;
            }

            if (!IsTsModule()) {
                return VisitTSNodes(childNode);
            }

            auto res = VisitExportNamedVariable(decl);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::TS_IMPORT_EQUALS_DECLARATION: {
            auto *node = childNode->AsTSImportEqualsDeclaration();
            auto *express = node->ModuleReference();
            if (express->IsTSExternalModuleReference()) {
                return VisitTSNodes(childNode);
            }
            auto *res = VisitTsImportEqualsDeclaration(node);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::CLASS_DECLARATION: {
            auto *node = childNode->AsClassDeclaration();
            DuringClass duringClass(&classList_, node->Definition()->GetName());
            node = VisitTSNodes(node)->AsClassDeclaration();
            auto res = VisitClassDeclaration(node);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::CLASS_EXPRESSION: {
            auto *node = childNode->AsClassExpression();
            DuringClass duringClass(&classList_, node->Definition()->GetName());
            node = VisitTSNodes(node)->AsClassExpression();
            auto res = VisitClassExpression(node);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::CLASS_DEFINITION: {
            auto *node = childNode->AsClassDefinition();
            VisitPrivateProperty(node);
            VisitComputedProperty(node);
            VisitTSParameterProperty(node);
            auto res = VisitTSNodes(childNode);
            SetOriginalNode(res, childNode);
            return res;
        }
        case ir::AstNodeType::TS_PRIVATE_IDENTIFIER: {
            auto id = childNode->AsTSPrivateIdentifier()->Key()->AsIdentifier();
            auto name = FindPrivatePropertyBindName(id->Name());
            auto res = CreateReferenceIdentifier(name);
            SetOriginalNode(res, childNode);
            return res;
        }
        default: {
            return VisitTSNodes(childNode);
        }
    }
}

util::StringView Transformer::CreateNewVariable(bool needAddToStatements)
{
    util::StringView name = CreateNewVariableName();
    if (needAddToStatements) {
        AddVariableToNearestStatements(name);
    }
    return name;
}

util::StringView Transformer::CreateUniqueName(const std::string &head, size_t *index) const
{
    util::StringView name;
    size_t idx = 0;
    if (index != nullptr) {
        idx = *index;
    }
    do {
        idx++;
        std::stringstream ss;
        ss << head << std::to_string(idx);
        auto s = ss.str();
        if (!Binder()->HasVariableName(util::StringView(s))) {
            name = util::UString(s, Allocator()).View();
            break;
        }
    } while (true);
    if (index != nullptr) {
        *index = idx;
    }
    Binder()->AddDeclarationName(name);
    return name;
}

util::StringView Transformer::CreateNewVariableName() const
{
    auto name = CreateUniqueName(std::string(NEW_VAR_PREFIX) + std::string(NEW_VAR_HEAD));
    return name;
}

ir::UpdateNodes Transformer::VisitClassExpression(ir::ClassExpression *node)
{
    /*
     *  Transform:
     *  var c = class C {
     *    static a = 1
     *  }
     *
     *  To:
     *  var ##var_1;
     *  var c = (##var_1 = class C {},
     *           ##var_1.a = 1,
     *           ##var_1)
     */
    auto varName = CreateNewVariable(false);
    auto staticProperty = VisitStaticProperty(node->Definition(), varName);
    if (staticProperty.empty()) {
        return node;
    }
    AddVariableToNearestStatements(varName);

    auto assignment = AllocNode<ir::AssignmentExpression>(CreateReferenceIdentifier(varName),
        node->AsExpression(), lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    ArenaVector<ir::Expression *> sequence(Allocator()->Adapter());
    sequence.push_back(assignment);
    for (auto *it : staticProperty) {
        sequence.push_back(it->GetExpression());
    }
    sequence.push_back(CreateReferenceIdentifier(varName));
    return AllocNode<ir::SequenceExpression>(std::move(sequence));
}

void Transformer::VisitComputedProperty(ir::ClassDefinition *node)
{
    /*
     *  Only create variable for the computed members with decorators or static class property
     *  The new value will be used in the decorators or static property initialize
     *  Transform:
     *  class C {
     *    @f
     *    [a](){}
     *    static [b] = 1
     *  }
     *
     *  To:
     *  var ##var_1;
     *  var ##var_2;
     *  class C {
     *    @f
     *    [##var_1 = a](){}
     *    static [##var_2 = b] = 1
     *  }
     */
    for (auto *it : node->Body()) {
        if (it->IsClassProperty()) {
            auto *classProperty = it->AsClassProperty();
            if (!classProperty->IsComputed() || (!classProperty->HasDecorators() && !classProperty->IsStatic())) {
                continue;
            }
            auto *key = classProperty->Key();
            auto name = CreateNewVariable();
            auto *newKey = AllocNode<ir::AssignmentExpression>(CreateReferenceIdentifier(name),
                key, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            classProperty->SetKey(newKey);
            AddComputedPropertyBinding(it, name);
        } else if (it->IsMethodDefinition()) {
            auto *methodDefinition = it->AsMethodDefinition();
            if (!methodDefinition->Computed() ||
                (!methodDefinition->HasDecorators() && !methodDefinition->HasParamDecorators())) {
                continue;
            }
            auto *key = methodDefinition->Key();
            auto name = CreateNewVariable();
            auto *newKey = AllocNode<ir::AssignmentExpression>(CreateReferenceIdentifier(name),
                key, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
            methodDefinition->SetKey(newKey);
            AddComputedPropertyBinding(it, name);
        }
    }
}

void Transformer::VisitPrivateProperty(ir::ClassDefinition *node)
{
    /*
     *  Create an unique variable name for private property member in class
     *  Transform:
     *  class C {
     *    #a = 1
     *  }
     *
     *  To:
     *  class C {
     *    ##${RecordName}#C#a#1 = 1
     *  }
     */
    for (auto *it : node->Body()) {
        if (!it->IsClassProperty()) {
            continue;
        }
        auto *key = it->AsClassProperty()->Key();
        if (!key->IsTSPrivateIdentifier()) {
            continue;
        }
        auto name = key->AsTSPrivateIdentifier()->Key()->AsIdentifier()->Name();
        auto bindName = CreatePrivatePropertyBindName(name);
        AddPrivatePropertyBinding(name, bindName);
    }
}

util::StringView Transformer::FindPrivatePropertyBindName(util::StringView name)
{
    for (size_t i = classList_.size() - 1; i >= 0; i--) {
        auto res = classList_[i].bindNameMap->find(name);
        if (res != classList_[i].bindNameMap->end()) {
            return res->second;
        }
    }
    UNREACHABLE();
}

util::StringView Transformer::CreatePrivatePropertyBindName(util::StringView name)
{
    std::stringstream head;
    head << NEW_VAR_PREFIX << std::string(RecordName());
    for (auto it : classList_) {
        head << PRIVATE_PROPERTY_SIGN << std::string(it.name);
    }
    head << PRIVATE_PROPERTY_SIGN << std::string(name) << PRIVATE_PROPERTY_SIGN;
    size_t index = GetCurrentClassInfoPropertyIndex();
    auto uniqueName = CreateUniqueName(head.str(), &index);
    SetCurrentClassInfoPropertyIndex(index);
    return uniqueName;
}

void Transformer::VisitTSParameterProperty(ir::ClassDefinition *node)
{
    /*
     *  Add class property for the parameter property declaration in constructor
     *  Transform:
     *  class C {
     *    constructor(public a = 1) {}
     *  }
     *
     *  To:
     *  class C {
     *    constructor(public a = 1) {
     *      this.a = a;
     *    }
     *  }
     */
    auto *func = node->Ctor()->Function();
    auto *body = func->Body();
    if (body == nullptr) {
        return;
    }
    auto blockStatement = body->AsBlockStatement();
    for (auto *it : func->Params()) {
        if (!it->IsTSParameterProperty()) {
            continue;
        }
        auto *parameter = it->AsTSParameterProperty()->Parameter();
        util::StringView name;
        // TSParameterPropert only can be identifier or assignment expression
        if (parameter->IsIdentifier()) {
            name = parameter->AsIdentifier()->Name();
        } else {
            ASSERT(parameter->IsAssignmentExpression());
            auto *left = parameter->AsAssignmentExpression()->Left();
            ASSERT(left->IsIdentifier());
            name = left->AsIdentifier()->Name();
        }
        auto left = AllocNode<ir::MemberExpression>(AllocNode<ir::ThisExpression>(),
            AllocNode<ir::Identifier>(name, Allocator()),
            ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        auto right = CreateReferenceIdentifier(name);
        auto assignment = AllocNode<ir::AssignmentExpression>(left, right,
            lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        blockStatement->AddStatementInFront(AllocNode<ir::ExpressionStatement>(assignment));
    }
}

std::vector<ir::ExpressionStatement *> Transformer::VisitStaticProperty(ir::ClassDefinition *node,
                                                                        util::StringView name)
{
    /*
     *  Create statement for static class property
     *  If it's a conputed property, we should initialize it's new variable first.
     *  Transform:
     *  var ##var_1;
     *  class C {
     *    static a = 1
     *    static [##var_1 = s] = 1
     *  }
     *
     *  To:
     *  var ##var_1;
     *  class C {
     *  }
     *  C.a = 1;
     *  ##var_1 = s;
     *  C[##var_1] = 1;
     *
     *  TODO(xucheng): should support static private property
     */
    std::vector<ir::ExpressionStatement *> res;
    auto classDefinitionBody = node->Body();
    for (auto *it : classDefinitionBody) {
        if (!it->IsClassProperty()) {
            continue;
        }
        auto *classProperty = it->AsClassProperty();
        if (!classProperty->IsStatic()) {
            continue;
        }
        if (classProperty->IsComputed()) {
            res.push_back(AllocNode<ir::ExpressionStatement>(classProperty->Key()));
        }
        auto right = classProperty->Value();
        if (right == nullptr) {
            continue;
        }
        auto *member = GetClassMemberName(classProperty->Key(), classProperty->IsComputed(), classProperty);
        auto left = AllocNode<ir::MemberExpression>(CreateReferenceIdentifier(name), member,
            ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, classProperty->IsComputed(), false);
        auto assignment = AllocNode<ir::AssignmentExpression>(left, right, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        res.push_back(AllocNode<ir::ExpressionStatement>(assignment));
    }
    return res;
}

ir::UpdateNodes Transformer::VisitClassDeclaration(ir::ClassDeclaration *node)
{
    // TODO(xucheng): maybe will support metadata later
    auto name = node->Definition()->GetName();
    std::vector<ir::AstNode *> res;
    bool hasClassDecorators = node->HasDecorators();
    if (hasClassDecorators) {
        auto definiton = node->Definition();
        auto *clsExpression = AllocNode<ir::ClassExpression>(definiton);
        res.push_back(CreateVariableDeclarationWithIdentify(name, VariableParsingFlags::LET, node, false,
            clsExpression, false));
    } else {
        res.push_back(node);
    }

    auto staticProperty = VisitStaticProperty(node->Definition(), name);
    if (!staticProperty.empty()) {
        res.insert(res.end(), staticProperty.begin(), staticProperty.end());
    }

    auto classDefinitionBody = node->Definition()->Body();
    // decorators of static members, should be called after instance members
    std::vector<ir::AstNode *> staticMemberDecorators;
    for (auto *it : classDefinitionBody) {
        if (it->IsMethodDefinition()) {
            auto *definition = it->AsMethodDefinition();
            bool isStatic = definition->IsStatic();
            auto paramDecorators = CreateParamDecorators(name, definition, false, isStatic);
            if (isStatic) {
                staticMemberDecorators.insert(staticMemberDecorators.end(),
                    paramDecorators.begin(), paramDecorators.end());
            } else {
                res.insert(res.end(), paramDecorators.begin(), paramDecorators.end());
            }
            if (!definition->HasDecorators()) {
                continue;
            }
            auto methodDecorators = CreateMethodDecorators(name, definition, isStatic);
            if (isStatic) {
                staticMemberDecorators.insert(staticMemberDecorators.end(),
                    methodDecorators.begin(), methodDecorators.end());
            } else {
                res.insert(res.end(), methodDecorators.begin(), methodDecorators.end());
            }
        } else if (it->IsClassProperty()) {
            auto *classProperty = it->AsClassProperty();
            bool isStatic = classProperty->IsStatic();
            if (!classProperty->HasDecorators()) {
                continue;
            }
            auto propertyDecorators = CreatePropertyDecorators(name, classProperty, isStatic);
            if (isStatic) {
                staticMemberDecorators.insert(staticMemberDecorators.end(),
                    propertyDecorators.begin(), propertyDecorators.end());
            } else {
                res.insert(res.end(), propertyDecorators.begin(), propertyDecorators.end());
            }
        }
    }

    if (!staticMemberDecorators.empty()) {
        res.insert(res.end(), staticMemberDecorators.begin(), staticMemberDecorators.end());
    }

    // constructor decorators
    auto *ctor = node->Definition()->Ctor();
    auto ctorParamDecorators = CreateParamDecorators(name, ctor, true, false);
    res.insert(res.end(), ctorParamDecorators.begin(), ctorParamDecorators.end());

    // class decorators
    if (hasClassDecorators) {
        auto classDecorators = CreateClassDecorators(node);
        res.insert(res.end(), classDecorators.begin(), classDecorators.end());
    }
    if (res.size() == 1) {
        return res.front();
    }
    return res;
}

std::vector<ir::AstNode *> Transformer::CreateParamDecorators(util::StringView className,
                                                              ir::MethodDefinition *node,
                                                              bool isConstructor,
                                                              bool isStatic)
{
    /*
     *  Param decorators
     *  Transform:
     *  class C {
     *    f(@g a){}
     *  }
     *
     *  To:
     *  class C {
     *    f(a){}
     *  }
     *  g(C.prototype, "f", 0)
     *
     *  Static method or constructor will use constructor function of the class instead of prototype of class
     */
    std::vector<ir::AstNode *> res;
    auto paramsDecorators = node->GetParamDecorators();
    for (int i = paramsDecorators.size() - 1; i >= 0; i--) {
        auto paramIndex = paramsDecorators[i].paramIndex;
        auto decorators = paramsDecorators[i].decorators;
        for (int j = decorators.size() - 1; j >= 0; j--) {
            ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
            arguments.push_back(CreateDecoratorTarget(className, isConstructor || isStatic));
            arguments.push_back(isConstructor ?
                CreateReferenceIdentifier(CONSTRUCTOR_NAME) :
                GetClassMemberName(node->Key(), node->Computed(), node));
            arguments.push_back(AllocNode<ir::NumberLiteral>(paramIndex));
            auto *callExpr = AllocNode<ir::CallExpression>(decorators[j]->Expr(),
                std::move(arguments), nullptr, false);
            res.push_back(AllocNode<ir::ExpressionStatement>(callExpr));
        }
    }
    return res;
}

std::vector<ir::AstNode *> Transformer::CreatePropertyDecorators(util::StringView className,
                                                                 ir::ClassProperty *node,
                                                                 bool isStatic)
{
    /*
     *  Property decorators
     *  Transform:
     *  class C {
     *    @f a = 1
     *  }
     *
     *  To:
     *  class C {
     *    a = 1
     *  }
     *  f(C.prototype, "a")
     *
     *  Static property will use constructor function of the class instead of prototype of class
     */
    std::vector<ir::AstNode *> res;
    auto decorators = node->Decorators();
    for (int i = decorators.size() - 1; i >= 0; i--) {
        ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
        arguments.push_back(CreateDecoratorTarget(className, isStatic));
        arguments.push_back(GetClassMemberName(node->Key(), node->IsComputed(), node));
        auto *callExpr = AllocNode<ir::CallExpression>(decorators[i]->Expr(), std::move(arguments), nullptr, false);

        res.push_back(AllocNode<ir::ExpressionStatement>(callExpr));
    }
    return res;
}

std::vector<ir::AstNode *> Transformer::CreateMethodDecorators(util::StringView className,
                                                               ir::MethodDefinition *node,
                                                               bool isStatic)
{
    /*
     *  Method decorators and accessor decorators
     *  Transform:
     *  class C {
     *    @g
     *    f(){}
     *  }
     *
     *  To:
     *  class C {
     *    f(){}
     *  }
     *  Object.defineProperty(C.prototype, "f",
     *    g(C.prototype, "f", Object.getOwnPropertyDescriptor(C.prototype, "f")) ||
     *    Object.getOwnPropertyDescriptor(C.prototype, "f"));
     *
     *  static method will use constructor function of the class instead of prototype of class
     *  If the decorator has a return value, it will be set as the new property of the method
     */
    std::vector<ir::AstNode *> res;
    auto decorators = node->Decorators();
    for (int i = decorators.size() - 1; i >= 0; i--) {
        ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
        arguments.push_back(CreateDecoratorTarget(className, isStatic));
        arguments.push_back(GetClassMemberName(node->Key(), node->Computed(), node));
        arguments.push_back(CreateGetOwnPropertyDescriptorCall(CreateDecoratorTarget(className, isStatic),
            GetClassMemberName(node->Key(), node->Computed(), node)));
        auto *callExpr = AllocNode<ir::CallExpression>(decorators[i]->Expr(), std::move(arguments), nullptr, false);

        auto *getProperty = CreateGetOwnPropertyDescriptorCall(CreateDecoratorTarget(className, isStatic),
            GetClassMemberName(node->Key(), node->Computed(), node));
        auto newValue = AllocNode<ir::BinaryExpression>(callExpr, getProperty,
            lexer::TokenType::PUNCTUATOR_LOGICAL_OR);

        auto *defineProperty = CreateDefinePropertyCall(CreateDecoratorTarget(className, isStatic),
            GetClassMemberName(node->Key(), node->Computed(), node), newValue);

        res.push_back(AllocNode<ir::ExpressionStatement>(defineProperty));
    }
    return res;
}

ir::Expression *Transformer::CreateDecoratorTarget(util::StringView className, bool targetCtor)
{
    if (targetCtor) {
        return CreateReferenceIdentifier(className);
    }
    return CreateClassPrototype(className);
}

ir::MemberExpression *Transformer::CreateClassPrototype(util::StringView className)
{
    auto *cls = CreateReferenceIdentifier(className);
    return AllocNode<ir::MemberExpression>(cls, AllocNode<ir::Identifier>(CLASS_PROTOTYPE, Allocator()),
        ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
}

ir::CallExpression *Transformer::CreateDefinePropertyCall(ir::Expression *target,
                                                          ir::Expression *key,
                                                          ir::Expression *value)
{
    auto *id = CreateReferenceIdentifier(OBJECT_VAR_NAME);
    auto *caller = AllocNode<ir::MemberExpression>(id, AllocNode<ir::Identifier>(FUNC_NAME_OF_DEFINE_PROPERTY,
        Allocator()), ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    arguments.push_back(target);
    arguments.push_back(key);
    arguments.push_back(value);
    return AllocNode<ir::CallExpression>(caller, std::move(arguments), nullptr, false);
}

ir::CallExpression *Transformer::CreateGetOwnPropertyDescriptorCall(ir::Expression *target, ir::Expression *key)
{
    auto *id = CreateReferenceIdentifier(OBJECT_VAR_NAME);
    auto *caller = AllocNode<ir::MemberExpression>(id,
        AllocNode<ir::Identifier>(FUNC_NAME_OF_GET_OWN_PROPERTY_DESCRIPTOR, Allocator()),
        ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    arguments.push_back(target);
    arguments.push_back(key);
    return AllocNode<ir::CallExpression>(caller, std::move(arguments), nullptr, false);
}

ir::Expression *Transformer::GetClassMemberName(ir::Expression *key, bool isComputed, ir::Statement *node)
{
    if (isComputed) {
        auto name = GetComputedPropertyBinding(node);
        return AllocNode<ir::Identifier>(name, Allocator());
    }
    if (key->IsIdentifier()) {
        return AllocNode<ir::StringLiteral>(key->AsIdentifier()->Name());
    } else if (key->IsStringLiteral()) {
        return AllocNode<ir::StringLiteral>(key->AsStringLiteral()->Str());
    } else if (key->IsNumberLiteral()) {
        return AllocNode<ir::NumberLiteral>(key->AsNumberLiteral()->Number(), key->AsNumberLiteral()->Str());
    } else if (key->IsBigIntLiteral()) {
        return AllocNode<ir::BigIntLiteral>(key->AsBigIntLiteral()->Str());
    }
    UNREACHABLE();
    return nullptr;
}

std::vector<ir::AstNode *> Transformer::CreateClassDecorators(ir::ClassDeclaration *node)
{
    /*
     *  Class decorators
     *  Transform:
     *  @f
     *  class C {
     *  }
     *
     *  To:
     *  class C {
     *  }
     *  C = f(C) || C;
     *
     *  If the decorator has a return value, it will be used as the new declaration of the class
     */
    auto name = node->Definition()->GetName();
    auto decorators = node->Decorators();
    auto size = decorators.size();
    std::vector<ir::AstNode *> res;
    for (int i = size - 1; i >= 0; i--) {
        ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
        arguments.push_back(CreateReferenceIdentifier(name));
        auto *callExpr = AllocNode<ir::CallExpression>(decorators[i]->Expr(), std::move(arguments), nullptr, false);

        auto left = CreateReferenceIdentifier(name);
        auto id = CreateReferenceIdentifier(name);
        auto right = AllocNode<ir::BinaryExpression>(callExpr, id, lexer::TokenType::PUNCTUATOR_LOGICAL_OR);
        auto *assignExpr = AllocNode<ir::AssignmentExpression>(left, right,
            lexer::TokenType::PUNCTUATOR_SUBSTITUTION);

        res.push_back(AllocNode<ir::ExpressionStatement>(assignExpr));
    }
    return res;
}

ir::AstNode *Transformer::VisitTsImportEqualsDeclaration(ir::TSImportEqualsDeclaration *node)
{
    auto *express = node->ModuleReference();
    if (!IsInstantiatedTSModule(express)) {
        return node;
    }
    auto name = node->Id()->Name();
    if (IsTsModule() && node->IsExport()) {
        auto moduleName = GetCurrentTSModuleName();
        auto *id = CreateReferenceIdentifier(moduleName);
        auto *left = AllocNode<ir::MemberExpression>(id, AllocNode<ir::Identifier>(name, Allocator()),
            ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
        ir::Expression *right = CreateMemberExpressionFromQualified(express);
        auto *assignExpr = AllocNode<ir::AssignmentExpression>(left, right,
            lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        auto *res = AllocNode<ir::ExpressionStatement>(assignExpr);
        return res;
    }

    ir::Expression *init = CreateMemberExpressionFromQualified(express);
    ir::Statement *res = CreateVariableDeclarationWithIdentify(name, VariableParsingFlags::VAR, node,
        node->IsExport(), init);
    if (node->IsExport()) {
        ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
        res = AllocNode<ir::ExportNamedDeclaration>(res, std::move(specifiers));
        AddExportLocalEntryItem(name, node->Id());
    }
    return res;
}

bool Transformer::IsInstantiatedTSModule(const ir::Expression *node) const
{
    auto *var = FindTSModuleVariable(node, Scope());
    if (var == nullptr) {
        return true;
    }
    auto *decl = var->Declaration();
    ASSERT(decl->IsNamespaceDecl());
    auto tsModules = decl->AsNamespaceDecl()->Decls();
    for (auto *it : tsModules) {
        if (it->IsInstantiated()) {
            return true;
        }
    }
    return false;
}

binder::Variable *Transformer::FindTSModuleVariable(const ir::Expression *node, binder::Scope *scope) const
{
    if (node == nullptr) {
        return nullptr;
    }
    if (node->IsTSQualifiedName()) {
        auto *tsQualifiedName = node->AsTSQualifiedName();
        auto *var = FindTSModuleVariable(tsQualifiedName->Left(), scope);
        if (var == nullptr) {
            return nullptr;
        }
        auto *exportTSBindings = var->AsNamespaceVariable()->GetExportBindings();
        auto name = tsQualifiedName->Right()->Name();
        auto *res = exportTSBindings->FindExportTSVariable<binder::TSBindingType::NAMESPACE>(name);
        if (res != nullptr) {
            return res;
        }
        res = exportTSBindings->FindExportTSVariable<binder::TSBindingType::IMPORT_EQUALS>(name);
        if (res != nullptr) {
            auto *node = res->Declaration()->Node();
            return FindTSModuleVariable(node->Parent()->AsTSImportEqualsDeclaration()->ModuleReference(),
                res->AsImportEqualsVariable()->GetScope());
        }
        return nullptr;
    }
    ASSERT(node->IsIdentifier());
    auto name = node->AsIdentifier()->Name();
    auto *currentScope = scope;
    while (currentScope != nullptr) {
        auto *res = currentScope->FindLocalTSVariable<binder::TSBindingType::NAMESPACE>(name);
        if (res == nullptr && currentScope->IsTSModuleScope()) {
            res = currentScope->AsTSModuleScope()->FindExportTSVariable<binder::TSBindingType::NAMESPACE>(name);
        }
        if (res != nullptr) {
            return res;
        }
        res = currentScope->FindLocalTSVariable<binder::TSBindingType::IMPORT_EQUALS>(name);
        if (res == nullptr && currentScope->IsTSModuleScope()) {
            res = currentScope->AsTSModuleScope()->FindExportTSVariable<binder::TSBindingType::IMPORT_EQUALS>(name);
        }
        if (res != nullptr) {
            auto *node = res->Declaration()->Node();
            return FindTSModuleVariable(node->Parent()->AsTSImportEqualsDeclaration()->ModuleReference(),
                res->AsImportEqualsVariable()->GetScope());
        }
        currentScope = currentScope->Parent();
    }
    return nullptr;
}

std::vector<ir::AstNode *> Transformer::VisitExportNamedVariable(ir::Statement *decl)
{
    std::vector<ir::AstNode *> res;
    if (decl->IsVariableDeclaration()) {
        auto declarators = decl->AsVariableDeclaration()->Declarators();
        for (auto *it : declarators) {
            if (it->Init()) {
                auto *left = std::get<ir::AstNode *>(VisitTSNode(it->Id()))->AsExpression();
                auto *right = std::get<ir::AstNode *>(VisitTSNode(it->Init()))->AsExpression();
                auto *assignExpr = AllocNode<ir::AssignmentExpression>(left, right,
                    lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
                res.push_back(AllocNode<ir::ExpressionStatement>(assignExpr));
            }
        }
    } else if (decl->IsFunctionDeclaration() || decl->IsClassDeclaration()) {
        res.push_back(VisitTSNodes(decl));
        auto name = decl->IsFunctionDeclaration() ?
            decl->AsFunctionDeclaration()->Function()->Id() :
            decl->AsClassDeclaration()->Definition()->Ident();
        ASSERT(name != nullptr);
        res.push_back(CreateTsModuleAssignment(name->Name()));
    }
    return res;
}

ir::Expression *Transformer::CreateMemberExpressionFromQualified(ir::Expression *node)
{
    if (node->IsTSQualifiedName()) {
        auto *tsQualifiedName = node->AsTSQualifiedName();
        auto *left = CreateMemberExpressionFromQualified(tsQualifiedName->Left());
        auto *right = AllocNode<ir::Identifier>(tsQualifiedName->Right()->Name(), Allocator());
        return AllocNode<ir::MemberExpression>(left, right,
            ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    }
    ASSERT(node->IsIdentifier());
    auto *id = CreateReferenceIdentifier(node->AsIdentifier()->Name());
    return id;
}

void Transformer::SetOriginalNode(ir::UpdateNodes res, ir::AstNode *originalNode) const
{
    if (std::holds_alternative<ir::AstNode *>(res)) {
        auto *node = std::get<ir::AstNode *>(res);
        if (node == nullptr || node == originalNode) {
            return;
        }
        node->SetOriginal(originalNode);
        node->SetRange(originalNode->Range());
    } else {
        auto nodes = std::get<std::vector<ir::AstNode *>>(res);
        for (auto *it : nodes) {
            it->SetOriginal(originalNode);
            it->SetRange(originalNode->Range());
        }
    }
}

ir::ExpressionStatement *Transformer::CreateTsModuleAssignment(util::StringView name)
{
    auto moduleName = GetCurrentTSModuleName();
    auto *id = CreateReferenceIdentifier(moduleName);
    auto *left = AllocNode<ir::MemberExpression>(id, AllocNode<ir::Identifier>(name, Allocator()),
        ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    auto *right = CreateReferenceIdentifier(name);
    auto *assignExpr = AllocNode<ir::AssignmentExpression>(left, right, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    return AllocNode<ir::ExpressionStatement>(assignExpr);
}

util::StringView Transformer::GetNameFromModuleDeclaration(ir::TSModuleDeclaration *node) const
{
    return node->Name()->AsIdentifier()->Name();
}

ir::VariableDeclaration *Transformer::CreateVariableDeclarationWithIdentify(util::StringView name,
                                                                            VariableParsingFlags flags,
                                                                            ir::AstNode *node,
                                                                            bool isExport,
                                                                            ir::Expression *init,
                                                                            bool needBinding)
{
    auto *ident = CreateReferenceIdentifier(name);
    auto *declarator = AllocNode<ir::VariableDeclarator>(ident, init);
    ArenaVector<ir::VariableDeclarator *> declarators(Allocator()->Adapter());
    declarators.push_back(declarator);

    auto varKind = ir::VariableDeclaration::VariableDeclarationKind::VAR;
    if (flags & VariableParsingFlags::VAR) {
    } else if (flags & VariableParsingFlags::LET) {
        varKind = ir::VariableDeclaration::VariableDeclarationKind::LET;
    } else {
        varKind = ir::VariableDeclaration::VariableDeclarationKind::CONST;
    }
    auto *declaration = AllocNode<ir::VariableDeclaration>(varKind, std::move(declarators), false);

    lexer::SourcePosition startPos(0, 0);
    if (node != nullptr) {
        startPos = node->Start();
    }
    if (needBinding) {
        binder::Decl *decl = nullptr;
        binder::DeclarationFlags declflag = isExport ?
            binder::DeclarationFlags::EXPORT :
            binder::DeclarationFlags::NONE;
        if (flags & VariableParsingFlags::VAR) {
            decl = Binder()->AddDecl<binder::VarDecl>(startPos, declflag, name);
        } else if (flags & VariableParsingFlags::LET) {
            decl = Binder()->AddDecl<binder::LetDecl>(startPos, declflag, name);
        } else {
            decl = Binder()->AddDecl<binder::ConstDecl>(startPos, declflag, name);
        }
        decl->BindNode(declaration);
    }

    return declaration;
}

util::StringView Transformer::GetParamName(ir::TSModuleDeclaration *node, util::StringView name) const
{
    auto scope = node->Scope();
    if (!scope->HasVariableName(name)) {
        return name;
    }
    auto uniqueName = CreateUniqueName(std::string(name) + std::string(INDEX_DIVISION));
    return uniqueName;
}

ir::CallExpression *Transformer::CreateCallExpressionForTsModule(ir::TSModuleDeclaration *node,
                                                                 util::StringView name,
                                                                 bool isExport)
{
    ir::ScriptFunction *funcNode = nullptr;

    binder::FunctionScope *funcScope = node->Scope();
    binder::FunctionParamScope *funcParamScope = funcScope->ParamScope();
    auto paramName = GetParamName(node, name);
    {
        auto paramScopeCtx = binder::LexicalScope<binder::FunctionParamScope>::Enter(Binder(), funcParamScope);

        ArenaVector<ir::Expression *> params(Allocator()->Adapter());
        auto *parameter = CreateReferenceIdentifier(paramName);
        Binder()->AddParamDecl(parameter);
        params.push_back(parameter);

        ir::BlockStatement *blockNode = nullptr;
        {
            auto scopeCtx = binder::LexicalScope<binder::FunctionScope>::Enter(Binder(), funcScope);
            tsModuleList_.push_back({paramName, funcScope});
            if (node->Body()->IsTSModuleDeclaration()) {
                auto *tsModule = node->Body()->AsTSModuleDeclaration();
                auto body = std::get<std::vector<ir::AstNode *>>(VisitTsModuleDeclaration(tsModule, true));
                ArenaVector<ir::Statement *> statements(Allocator()->Adapter());
                for (auto *it : body) {
                    statements.push_back(static_cast<ir::Statement *>(it));
                }
                blockNode = AllocNode<ir::BlockStatement>(funcScope, std::move(statements));
            } else {
                auto body = VisitTSNodes(node->Body());
                blockNode = AllocNode<ir::BlockStatement>(funcScope,
                    std::move(body->AsTSModuleBlock()->Statements()));
            }
            tsModuleList_.pop_back();
            funcScope->AddBindsFromParam();
        }

        funcNode = AllocNode<ir::ScriptFunction>(funcScope, std::move(params), nullptr, blockNode, nullptr,
            ir::ScriptFunctionFlags::NONE, false, Extension() == ScriptExtension::TS);

        funcScope->BindNode(funcNode);
        funcParamScope->BindNode(funcNode);
    }

    auto *funcExpr = AllocNode<ir::FunctionExpression>(funcNode);

    ArenaVector<ir::Expression *> arguments(Allocator()->Adapter());
    ArenaVector<ir::Expression *> properties(Allocator()->Adapter());
    auto *objectExpression = AllocNode<ir::ObjectExpression>(ir::AstNodeType::OBJECT_EXPRESSION,
                                                             std::move(properties),
                                                             false);
    auto assignExpr = AllocNode<ir::AssignmentExpression>(CreateTsModuleParam(name, isExport),
                                                          objectExpression,
                                                          lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
    auto argument = AllocNode<ir::BinaryExpression>(CreateTsModuleParam(name, isExport),
                                                    assignExpr,
                                                    lexer::TokenType::PUNCTUATOR_LOGICAL_OR);
    if (isExport) {
        auto *id = CreateReferenceIdentifier(name);
        arguments.push_back(AllocNode<ir::AssignmentExpression>(id, argument,
            lexer::TokenType::PUNCTUATOR_SUBSTITUTION));
    } else {
        arguments.push_back(argument);
    }

    auto *callExpr = AllocNode<ir::CallExpression>(funcExpr, std::move(arguments), nullptr, false);

    return callExpr;
}

ir::Expression *Transformer::CreateTsModuleParam(util::StringView paramName, bool isExport)
{
    if (isExport) {
        auto moduleName = GetCurrentTSModuleName();
        auto *id = CreateReferenceIdentifier(moduleName);
        return AllocNode<ir::MemberExpression>(id, AllocNode<ir::Identifier>(paramName, Allocator()),
            ir::MemberExpression::MemberExpressionKind::PROPERTY_ACCESS, false, false);
    }

    auto *id = CreateReferenceIdentifier(paramName);
    return id;
}

void Transformer::AddExportLocalEntryItem(util::StringView name, const ir::Identifier *identifier)
{
    auto moduleRecord = GetSourceTextModuleRecord();
    auto *entry = moduleRecord->NewEntry<SourceTextModuleRecord::ExportEntry>(name, name, identifier, identifier);
    [[maybe_unused]] bool res = moduleRecord->AddLocalExportEntry(entry);
    ASSERT(res);
}

ir::UpdateNodes Transformer::VisitTsModuleDeclaration(ir::TSModuleDeclaration *node, bool isExport)
{
    std::vector<ir::AstNode *> res;

    util::StringView name = GetNameFromModuleDeclaration(node);

    auto findRes = Scope()->FindLocal(name, binder::ResolveBindingOptions::ALL);
    if (findRes == nullptr) {
        bool doExport = isExport && !IsTsModule();
        auto flag = VariableParsingFlags::VAR;
        if (IsTsModule()) {
            flag = VariableParsingFlags::LET;
        }
        auto *var = CreateVariableDeclarationWithIdentify(name, flag, node, doExport);
        if (doExport) {
            ArenaVector<ir::ExportSpecifier *> specifiers(Allocator()->Adapter());
            res.push_back(AllocNode<ir::ExportNamedDeclaration>(var, std::move(specifiers)));
            AddExportLocalEntryItem(name, node->Name()->AsIdentifier());
        } else {
            res.push_back(var);
        }
    }

    auto *callExpr = CreateCallExpressionForTsModule(node, name, isExport && IsTsModule());
    auto *exprStatementNode = AllocNode<ir::ExpressionStatement>(callExpr);
    res.push_back(exprStatementNode);

    return res;
}

ir::Identifier *Transformer::CreateReferenceIdentifier(util::StringView name)
{
    auto *node = AllocNode<ir::Identifier>(name, Allocator());
    node->AsIdentifier()->SetReference();
    return node;
}

}  // namespace panda::es2panda::parser
