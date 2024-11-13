/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

#include "compiler/lowering/ets/topLevelStmts/globalDeclTransformer.h"

namespace ark::es2panda::compiler {

void GlobalDeclTransformer::FilterDeclarations(ArenaVector<ir::Statement *> &stmts)
{
    const auto isDeclCb = [&types = typeDecl_](const ir::AstNode *node) {
        return types.count(node->Type()) == 0U || (node->IsExportNamedDeclaration());
    };
    stmts.erase(std::remove_if(stmts.begin(), stmts.end(), isDeclCb), stmts.end());
}

GlobalDeclTransformer::ResultT GlobalDeclTransformer::TransformStatements(const ArenaVector<ir::Statement *> &stmts,
                                                                          bool addInitializer)
{
    addInitializer_ = addInitializer;
    result_.classProperties.clear();
    result_.initStatements.clear();
    for (auto stmt : stmts) {
        stmt->Accept(this);
    }
    return std::move(result_);
}

void GlobalDeclTransformer::VisitFunctionDeclaration(ir::FunctionDeclaration *funcDecl)
{
    auto *funcExpr = util::NodeAllocator::ForceSetParent<ir::FunctionExpression>(allocator_, funcDecl->Function());
    funcDecl->Function()->SetStart(funcDecl->Function()->Id()->Start());
    funcExpr->SetRange(funcDecl->Function()->Range());
    ir::MethodDefinitionKind methodKind;
    if (funcDecl->Function()->IsExtensionMethod()) {
        methodKind = ir::MethodDefinitionKind::EXTENSION_METHOD;
    } else {
        methodKind = ir::MethodDefinitionKind::METHOD;
    }
    auto *method = util::NodeAllocator::ForceSetParent<ir::MethodDefinition>(
        allocator_, methodKind, funcDecl->Function()->Id()->Clone(allocator_, nullptr), funcExpr,
        funcDecl->Function()->Modifiers(), allocator_, false);
    method->SetRange(funcDecl->Range());
    method->Function()->SetAnnotations(std::move(funcDecl->Annotations()));

    if (funcDecl->Function()->IsExported() && funcDecl->Function()->HasExportAlias()) {
        method->AddAstNodeFlags(ir::AstNodeFlags::HAS_EXPORT_ALIAS);
    }

    result_.classProperties.emplace_back(method);
}

void GlobalDeclTransformer::VisitVariableDeclaration(ir::VariableDeclaration *varDecl)
{
    for (auto declarator : varDecl->Declarators()) {
        auto id = declarator->Id()->AsIdentifier();
        auto typeAnn = id->TypeAnnotation();
        id->SetTsTypeAnnotation(nullptr);
        auto *field = util::NodeAllocator::ForceSetParent<ir::ClassProperty>(allocator_, id->Clone(allocator_, nullptr),
                                                                             declarator->Init(), typeAnn,
                                                                             varDecl->Modifiers(), allocator_, false);
        field->SetRange(declarator->Range());

        if (varDecl->IsExported() && varDecl->HasExportAlias()) {
            field->AddAstNodeFlags(ir::AstNodeFlags::HAS_EXPORT_ALIAS);
        }

        result_.classProperties.emplace_back(field);
        if (auto stmt = InitTopLevelProperty(field); stmt != nullptr) {
            result_.initStatements.emplace_back(stmt);
        }
    }
}

ir::Identifier *GlobalDeclTransformer::RefIdent(const util::StringView &name)
{
    auto *const callee = util::NodeAllocator::Alloc<ir::Identifier>(allocator_, name, allocator_);
    return callee;
}

ir::ExpressionStatement *GlobalDeclTransformer::InitTopLevelProperty(ir::ClassProperty *classProperty)
{
    ir::ExpressionStatement *initStmt = nullptr;
    const auto initializer = classProperty->Value();
    if (addInitializer_ && !classProperty->IsConst() && initializer != nullptr) {
        auto *ident = RefIdent(classProperty->Id()->Name());
        ident->SetRange(classProperty->Id()->Range());

        initializer->SetParent(nullptr);
        auto *assignmentExpression = util::NodeAllocator::Alloc<ir::AssignmentExpression>(
            allocator_, ident, initializer, lexer::TokenType::PUNCTUATOR_SUBSTITUTION);
        assignmentExpression->SetRange({ident->Start(), initializer->End()});
        assignmentExpression->SetTsType(initializer->TsType());

        auto expressionStatement =
            util::NodeAllocator::Alloc<ir::ExpressionStatement>(allocator_, assignmentExpression);
        expressionStatement->SetRange(classProperty->Range());

        classProperty->SetRange({ident->Start(), initializer->End()});

        if (classProperty->TypeAnnotation() != nullptr) {
            classProperty->SetValue(nullptr);
        } else {
            // Code will be ignored, but checker is going to deduce the type.
            classProperty->SetValue(initializer->Clone(allocator_, classProperty)->AsExpression());
        }
        initStmt = expressionStatement;
    } else {
        classProperty->SetStart(classProperty->Id()->Start());
    }
    return initStmt;
}

void GlobalDeclTransformer::HandleNode(ir::AstNode *node)
{
    ASSERT(node->IsStatement());
    if (typeDecl_.count(node->Type()) == 0U) {
        ASSERT(!propertiesDecl_.count(node->Type()));
        result_.initStatements.emplace_back(node->AsStatement());
    }
}

}  // namespace ark::es2panda::compiler
