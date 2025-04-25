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

#include "class_hierarchy.h"
#include "compiler/lowering/util.h"
#include "public/public.h"
#include "lsp/include/internal_api.h"

namespace ark::es2panda::lsp {

std::string GetHierarchyDeclarationFileName(const ir::AstNode *node)
{
    if (node == nullptr) {
        return "";
    }
    if (node->IsClassDeclaration()) {
        return std::string(node->AsClassDeclaration()->Definition()->Ident()->Range().start.Program()->AbsoluteName());
    }
    if (node->IsTSInterfaceDeclaration()) {
        return std::string(node->AsTSInterfaceDeclaration()->Id()->Range().start.Program()->AbsoluteName());
    }
    return "";
}

std::string GetHierarchyDeclarationName(const ir::AstNode *node)
{
    if (node == nullptr) {
        return "";
    }
    if (node->IsClassDeclaration()) {
        return std::string(node->AsClassDeclaration()->Definition()->Ident()->Name());
    }
    if (node->IsTSInterfaceDeclaration()) {
        return std::string(node->AsTSInterfaceDeclaration()->Id()->Name());
    }
    return "";
}

HierarchyType GetHierarchyType(const ir::AstNode *node)
{
    if (node == nullptr) {
        return HierarchyType::OTHERS;
    }
    if (node->IsClassDeclaration()) {
        return HierarchyType::CLASS;
    }
    if (node->IsTSInterfaceDeclaration()) {
        return HierarchyType::INTERFACE;
    }
    return HierarchyType::OTHERS;
}

size_t GetPosition(const ir::AstNode *node)
{
    if (node == nullptr) {
        return 0;
    }
    return node->Start().index;
}

const ir::AstNode *GetEffectiveBaseTypeNode(const ir::AstNode *node)
{
    if (node == nullptr || !node->IsClassDeclaration()) {
        return nullptr;
    }
    auto super = node->AsClassDeclaration()->Definition()->Super();
    if (super == nullptr || !super->IsETSTypeReference()) {
        return nullptr;
    }
    auto id = super->AsETSTypeReference()->Part()->Name();
    if (id == nullptr || !id->IsIdentifier()) {
        return nullptr;
    }
    auto result = compiler::DeclarationFromIdentifier(id->AsIdentifier());
    if (result == nullptr || !result->IsClassDefinition()) {
        return nullptr;
    }
    return result->Parent();
}

std::vector<const ir::AstNode *> GetInterfaceExtendsHeritageElement(const ir::AstNode *node)
{
    std::vector<const ir::AstNode *> result;
    if (node == nullptr || !node->IsTSInterfaceDeclaration()) {
        return result;
    }
    auto extends = node->AsTSInterfaceDeclaration()->Extends();
    for (auto e : extends) {
        auto id = e->Expr()->AsETSTypeReference()->Part()->Name();
        result.push_back(compiler::DeclarationFromIdentifier(id->AsIdentifier()));
    }
    return result;
}

void FindSuper(const ir::AstNode *node, TypeHierarchies &typeHierarchies, std::set<TypeHierarchies> &superLists)
{
    auto name = GetHierarchyDeclarationName(node);
    if (name.empty()) {
        return;
    }
    TypeHierarchies subOrSuper(GetHierarchyDeclarationFileName(node), name, GetHierarchyType(node), GetPosition(node));
    if (superLists.find(subOrSuper) != superLists.end()) {
        return;
    }
    superLists.insert(subOrSuper);
    GetSuperTypeHierarchies(node, subOrSuper, superLists);
    typeHierarchies.subOrSuper.emplace_back(subOrSuper);
}

std::vector<ir::AstNode *> GetEffectiveImplementsTypeNodes(const ir::AstNode *node)
{
    std::vector<ir::AstNode *> result;
    if (node == nullptr || !node->IsClassDeclaration()) {
        return result;
    }
    auto implements = node->AsClassDeclaration()->Definition()->Implements();
    for (auto imp : implements) {
        result.emplace_back(compiler::DeclarationFromIdentifier(
            imp->AsTSClassImplements()->Expr()->AsETSTypeReference()->Part()->Name()->AsIdentifier()));
    }
    return result;
}

void GetSuperTypeHierarchies(const ir::AstNode *node, TypeHierarchies &typeHierarchies,
                             std::set<TypeHierarchies> &superLists)
{
    std::set<TypeHierarchies> currentList;
    auto extendsNode = GetEffectiveBaseTypeNode(node);
    if (extendsNode != nullptr) {
        currentList = superLists;
        FindSuper(extendsNode, typeHierarchies, currentList);
    }
    auto implementsNodes = GetEffectiveImplementsTypeNodes(node);
    for (auto n : implementsNodes) {
        currentList = superLists;
        FindSuper(n, typeHierarchies, currentList);
    }
    auto extendsNodes = GetInterfaceExtendsHeritageElement(node);
    for (auto n : extendsNodes) {
        currentList = superLists;
        FindSuper(n, typeHierarchies, currentList);
    }
}

ir::AstNode *GetCurrentClassOrInterfaceDeclaration(ir::AstNode *node)
{
    auto tmp = node;
    while (tmp != nullptr) {
        if (tmp->IsClassDeclaration() || tmp->IsTSInterfaceDeclaration()) {
            return tmp;
        }
        tmp = tmp->Parent();
    }
    return nullptr;
}

ir::AstNode *GetTargetDeclarationNodeByPosition(es2panda_Context *context, size_t pos)
{
    auto node = ark::es2panda::lsp::GetTouchingToken(context, pos, false);
    if (node == nullptr) {
        return nullptr;
    }
    return GetCurrentClassOrInterfaceDeclaration(node);
}

bool IsChildNode(const ir::AstNode *child, const ir::AstNode *parent)
{
    std::vector<const ir::AstNode *> parentList = GetInterfaceExtendsHeritageElement(child);
    auto baseNode = GetEffectiveBaseTypeNode(child);
    if (baseNode != nullptr) {
        parentList.emplace_back(baseNode);
    }
    auto parentName = GetHierarchyDeclarationName(parent);
    auto parentFileName = GetHierarchyDeclarationFileName(parent);
    auto parentPosition = GetPosition(parent);
    auto result = std::find_if(parentList.begin(), parentList.end(), [&](const ir::AstNode *n) {
        auto p = GetPosition(n);
        return parentName == GetHierarchyDeclarationName(n) && parentFileName == GetHierarchyDeclarationFileName(n) &&
               p == parentPosition;
    });
    return result != parentList.end();
}

std::vector<ir::AstNode *> GetImplementationReferenceEntries(es2panda_Context *context, const ir::AstNode *node,
                                                             std::set<TypeHierarchies> &subLists)
{
    std::vector<ir::AstNode *> result;
    if (context == nullptr) {
        return result;
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return result;
    }
    auto astNode = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    astNode->IterateRecursively([&subLists, node, &result](ir::AstNode *ast) {
        if (ast == nullptr || !ast->IsIdentifier()) {
            return;
        }
        auto child = compiler::DeclarationFromIdentifier(ast->AsIdentifier());
        if (child == nullptr || (!child->IsClassDeclaration() && !child->IsTSInterfaceDeclaration())) {
            return;
        }
        auto name = GetHierarchyDeclarationName(child);
        if (name.empty()) {
            return;
        }
        TypeHierarchies childTypeHierarchies(GetHierarchyDeclarationFileName(child), name, GetHierarchyType(child),
                                             GetPosition(child));
        if (subLists.find(childTypeHierarchies) != subLists.end()) {
            return;
        }
        if (!IsChildNode(child, node)) {
            return;
        }
        result.emplace_back(child);
        subLists.insert(childTypeHierarchies);
    });
    return result;
}

void GetSubTypeHierarchies(es2panda_Context *context, const ir::AstNode *node, TypeHierarchies &typeHierarchies,
                           std::set<TypeHierarchies> &subLists)
{
    if (node == nullptr || (!node->IsTSInterfaceDeclaration() && !node->IsClassDeclaration())) {
        return;
    }
    auto name = GetHierarchyDeclarationName(node);
    if (name.empty()) {
        return;
    }
    auto childList = GetImplementationReferenceEntries(context, node, subLists);
    for (auto child : childList) {
        TypeHierarchies childType(GetHierarchyDeclarationFileName(child), GetHierarchyDeclarationName(child),
                                  GetHierarchyType(child), GetPosition(child));
        std::set<TypeHierarchies> curList;
        curList.insert(childType);
        GetSubTypeHierarchies(context, child, childType, curList);
        typeHierarchies.subOrSuper.emplace_back(childType);
    }
}

void InitHierarchies(TypeHierarchies &typeHierarchies, std::string &fileName, std::string &name, HierarchyType type,
                     size_t pos)
{
    typeHierarchies.fileName = fileName;
    typeHierarchies.name = name;
    typeHierarchies.type = type;
    typeHierarchies.pos = pos;
}

TypeHierarchiesInfo GetTypeHierarchiesImpl(es2panda_Context *context, const ClassHierarchyInfoType &declInfo,
                                           const ir::AstNode *declaration)
{
    TypeHierarchiesInfo result;
    if (context == nullptr) {
        return result;
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return result;
    }
    if (declaration == nullptr) {
        declaration = GetTargetDeclarationNodeByPosition(context, std::get<0>(declInfo));
    }
    if (declaration == nullptr || (!declaration->IsTSInterfaceDeclaration() && !declaration->IsClassDeclaration())) {
        return result;
    }
    result.fileName = GetHierarchyDeclarationFileName(declaration);
    result.name = GetHierarchyDeclarationName(declaration);
    result.type = GetHierarchyType(declaration);
    result.pos = GetPosition(declaration);
    InitHierarchies(result.superHierarchies, result.fileName, result.name, result.type, result.pos);
    InitHierarchies(result.subHierarchies, result.fileName, result.name, result.type, result.pos);
    std::set<TypeHierarchies> superLists;
    superLists.insert(result.superHierarchies);
    GetSuperTypeHierarchies(declaration, result.superHierarchies, superLists);
    std::set<TypeHierarchies> subLists;
    subLists.insert(result.subHierarchies);
    GetSubTypeHierarchies(context, declaration, result.subHierarchies, subLists);
    return result;
}
}  // namespace ark::es2panda::lsp