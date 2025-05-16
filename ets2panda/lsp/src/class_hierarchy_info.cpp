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

#include "class_hierarchy_info.h"
#include "internal_api.h"
#include "public/public.h"
#include "compiler/lowering/util.h"

namespace ark::es2panda::lsp {
std::string GetNameFromIdentifierNode(const ir::AstNode *node)
{
    if (node == nullptr || !node->IsIdentifier()) {
        return "";
    }
    return std::string(node->AsIdentifier()->Name());
}

// Currently only considering enum scenarios.
bool IsClassLiteralDefinition(const ir::AstNode *node)
{
    return !(compiler::ClassDefinitionIsEnumTransformed(node));
}

ir::ClassDefinition *GetClassDefinitionFromIdentifierNode(const ir::AstNode *node)
{
    auto decl = compiler::DeclarationFromIdentifier(node->AsIdentifier());
    if (decl == nullptr) {
        return nullptr;
    }
    if (decl->IsClassDeclaration()) {
        decl = decl->AsClassDeclaration()->Definition();
    }
    if (!IsClassLiteralDefinition(decl)) {
        return nullptr;
    }
    return decl->AsClassDefinition();
}

std::string SpliceFunctionDetailStr(const std::string &functionName, const std::vector<FunctionParamStyle> &params,
                                    const std::string &returnType)
{
    std::string result;
    if (functionName.empty()) {
        return result;
    }
    result.append(functionName).append("(");
    auto iter = params.cbegin();
    while (iter != params.cend()) {
        auto name = iter->GetParamName();
        auto kind = iter->GetParamKind();
        if (name.empty() || kind.empty()) {
            ++iter;
            continue;
        }
        result.append(name).append(": ").append(kind);
        ++iter;
        if (iter != params.cend()) {
            result.append(", ");
        }
    }
    result.append(")");
    if (!returnType.empty()) {
        result.append(": ").append(returnType);
    }
    return result;
}

std::string GetFunctionNameFromScriptFunction(const ir::ScriptFunction *function)
{
    if (function == nullptr) {
        return "";
    }
    return function->Id()->ToString();
}

std::vector<FunctionParamStyle> GetParamListFromScriptFunction(const ir::ScriptFunction *function)
{
    std::vector<FunctionParamStyle> params;
    if (function == nullptr) {
        return params;
    }
    auto nodeParams = function->Params();
    for (const auto &nodeParam : nodeParams) {
        std::string paramName;
        std::string paramKind;
        if (!nodeParam->IsETSParameterExpression()) {
            continue;
        }
        paramName = std::string(nodeParam->AsETSParameterExpression()->Name());
        nodeParam->AsETSParameterExpression()->FindChild([&paramKind](ir::AstNode *childNode) {
            if (childNode->IsETSTypeReference()) {
                paramKind = childNode->AsETSTypeReference()->Part()->Name()->ToString();
            }
            return false;
        });
        FunctionParamStyle tmp(paramName, paramKind);
        params.emplace_back(std::move(tmp));
    }
    return params;
}

std::string GetReturnTypeFromScriptFunction(const ir::ScriptFunction *function)
{
    if (function == nullptr) {
        return "";
    }
    auto nodeReturn = function->ReturnTypeAnnotation();
    if (nodeReturn == nullptr || !nodeReturn->IsETSTypeReference()) {
        return "";
    }
    auto ident = nodeReturn->AsETSTypeReference()->Part()->Name();
    if (ident == nullptr || !ident->IsIdentifier()) {
        return "";
    }
    return std::string(ident->AsIdentifier()->Name());
}

SetterStyle CreateSetterStyle(ir::MethodDefinitionKind kind)
{
    SetterStyle setter = SetterStyle::METHOD;
    switch (kind) {
        case ir::MethodDefinitionKind::GET:
        case ir::MethodDefinitionKind::EXTENSION_GET:
            setter = SetterStyle::GETTER;
            break;
        case ir::MethodDefinitionKind::SET:
        case ir::MethodDefinitionKind::EXTENSION_SET:
            setter = SetterStyle::SETTER;
            break;
        default:
            break;
    }
    return setter;
}

std::shared_ptr<ClassMethodItem> CreateClassMethodItem(const ir::MethodDefinition *methodDefinition,
                                                       const std::string &funcName, std::string detail)
{
    if (methodDefinition == nullptr || funcName.empty() || detail.empty()) {
        return nullptr;
    }

    auto setter = CreateSetterStyle(methodDefinition->Kind());
    AccessModifierStyle access = AccessModifierStyle::PUBLIC;
    if (methodDefinition->IsProtected()) {
        access = AccessModifierStyle::PROTECTED;
    }
    auto item = std::make_shared<ClassMethodItem>(std::move(detail), setter, access);
    item->SetFunctionName(funcName);
    return item;
}

std::shared_ptr<ClassMethodItem> ParseFunctionStyleWithCreateItem(const ir::MethodDefinition *methodDefinition,
                                                                  bool isCurrentToken)
{
    if (methodDefinition == nullptr) {
        return nullptr;
    }
    if ((isCurrentToken && methodDefinition->IsStatic()) ||
        (!isCurrentToken &&
         (methodDefinition->IsPrivate() || methodDefinition->IsStatic() || methodDefinition->IsConstructor()))) {
        return nullptr;
    }
    auto function = methodDefinition->Function();
    auto functionName = GetFunctionNameFromScriptFunction(function);
    if (functionName.empty()) {
        return nullptr;
    }
    auto paramList = GetParamListFromScriptFunction(function);
    auto returnType = GetReturnTypeFromScriptFunction(function);
    auto functionDetail = SpliceFunctionDetailStr(functionName, paramList, returnType);
    return CreateClassMethodItem(methodDefinition, functionName, functionDetail);
}

ClassHierarchyInfo CreateClassHierarchyInfoFromBody(const ir::ClassDefinition *classDefinition,
                                                    const std::string &className, bool isCurrentToken)
{
    ClassHierarchyInfo result;
    if (classDefinition == nullptr) {
        return result;
    }
    result.SetClassName(className);
    auto bodyNodes = classDefinition->Body();
    for (const auto &node : bodyNodes) {
        if (node == nullptr || !node->IsMethodDefinition()) {
            continue;
        }
        auto methodDefinition = node->AsMethodDefinition();
        if (methodDefinition == nullptr) {
            continue;
        }
        auto item = ParseFunctionStyleWithCreateItem(methodDefinition, isCurrentToken);
        if (item != nullptr) {
            result.AddClassMethodItem(item);
        }
        auto overLoads = methodDefinition->Overloads();
        for (const auto *overLoadMethodDefinition : overLoads) {
            auto overLoadItem = ParseFunctionStyleWithCreateItem(overLoadMethodDefinition, isCurrentToken);
            if (overLoadItem != nullptr) {
                result.AddClassMethodItem(overLoadItem);
            }
        }
    }
    return result;
}

ir::AstNode *GetSuperClassNode(const ir::ClassDefinition *classDefinition)
{
    if (classDefinition == nullptr) {
        return nullptr;
    }
    auto super = const_cast<ir::Expression *>(classDefinition->Super());
    if (super == nullptr) {
        return nullptr;
    }
    return GetIdentifierFromSuper(super);
}

void ComputeClassHierarchyInfo(const ClassHierarchyInfo &deriveInfo, ClassHierarchyInfo &superInfo)
{
    auto deriveMethods = deriveInfo.GetMethodList();
    for (const auto &method : deriveMethods) {
        superInfo.DeleteClassMethodItem(method.second);
    }
}

void ProcessClassHierarchy(const ir::AstNode *token, const ClassHierarchyInfo &baseInfo, ClassHierarchy &result)
{
    if (token == nullptr || !token->IsIdentifier()) {
        return;
    }
    std::string className = GetNameFromIdentifierNode(token);
    auto classDefinition = GetClassDefinitionFromIdentifierNode(token);
    if (classDefinition == nullptr) {
        return;
    }
    auto info = CreateClassHierarchyInfoFromBody(classDefinition, className, false);
    if (!className.empty()) {
        // Calculate the difference between the obtained parent class info and the current clicked node class info.
        ComputeClassHierarchyInfo(baseInfo, info);
        if (info.GetClassName() == className && !info.GetMethodList().empty()) {
            result.emplace_back(info);
        }
    }
    auto superClass = GetSuperClassNode(classDefinition);
    if (superClass == nullptr) {
        return;
    }
    ProcessClassHierarchy(superClass, baseInfo, result);
}

ClassHierarchyInfo GetCurrentTokenClassHierarchyInfo(const ir::AstNode *token)
{
    ClassHierarchyInfo currentInfo;
    auto classDefinition = GetClassDefinitionFromIdentifierNode(token);
    if (classDefinition == nullptr) {
        return currentInfo;
    }
    auto className = GetNameFromIdentifierNode(token);
    return CreateClassHierarchyInfoFromBody(classDefinition, className, true);
}

ClassHierarchy GetClassHierarchyInfoImpl(es2panda_Context *context, size_t position)
{
    ClassHierarchy result;
    if (context == nullptr) {
        return result;
    }
    auto token = GetTouchingToken(context, position, false);
    if (token == nullptr || !token->IsIdentifier()) {
        return result;
    }
    auto currentInfo = GetCurrentTokenClassHierarchyInfo(token);
    auto classDefinition = GetClassDefinitionFromIdentifierNode(token);
    auto superClass = GetSuperClassNode(classDefinition);
    if (superClass == nullptr) {
        return result;
    }
    ProcessClassHierarchy(superClass, currentInfo, result);
    return result;
}
}  // namespace ark::es2panda::lsp
