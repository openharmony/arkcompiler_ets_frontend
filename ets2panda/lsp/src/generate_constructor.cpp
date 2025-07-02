/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "generate_constructor.h"
#include "internal_api.h"
#include "compiler/lowering/util.h"
#include "public/public.h"
#include "class_hierarchy.h"
#include "completions.h"
#include "quick_info.h"

namespace ark::es2panda::lsp {

bool HasConstructorNode(ir::AstNode *classNode)
{
    size_t start = classNode->Start().index;
    size_t end = classNode->End().index;
    ir::AstNode *constructorNode = classNode->FindChild([start, end](ir::AstNode *node) {
        if (node == nullptr) {
            return false;
        }
        return node->Start().index >= start && node->End().index <= end && node->IsConstructor();
    });

    return constructorNode != nullptr;
}

std::vector<ir::AstNode *> GetClassProperties(ir::AstNode *classNode, const std::vector<std::string> &properties)
{
    std::vector<ir::AstNode *> classProperties = {};
    auto bodyNodes = classNode->AsClassDeclaration()->Definition()->Body();
    for (const auto &triggerWord : properties) {
        auto property = ark::es2panda::lsp::FilterFromBody(bodyNodes, triggerWord);
        for (const auto &node : property) {
            if (node->IsStatic() || !node->IsClassProperty()) {
                continue;
            }
            classProperties.emplace_back(node);
        }
    }

    return classProperties;
}

std::vector<ir::AstNode *> GetExtendedClassProperties(ir::AstNode *classNode)
{
    auto baseNode = ark::es2panda::lsp::GetEffectiveBaseTypeNode(classNode);
    if (baseNode == nullptr) {
        return {};
    }
    std::vector<ir::AstNode *> extendedClassProperties = {};
    auto baseNodeBody = baseNode->AsClassDeclaration()->Definition()->Body();
    for (auto node : baseNodeBody) {
        if (!node->IsClassProperty()) {
            continue;
        }
        auto tmp = node->AsClassProperty();
        if (tmp->IsStatic()) {
            continue;
        }

        extendedClassProperties.push_back(node);
    }
    return extendedClassProperties;
}

void RemoveTrailingChar(std::string &str, const std::string &lastChar)
{
    if (!str.empty()) {
        size_t lastPos = str.find_last_of(lastChar);
        if (lastPos != std::string::npos) {
            str.erase(lastPos);
        }
    }
}

void GetParameterListAndFunctionBody(std::string &parameterList, std::string &functionBody,
                                     const std::vector<ir::AstNode *> &nodeList, bool isSuper)
{
    if (nodeList.empty()) {
        return;
    }

    std::vector<std::string> strList1 = {};
    std::vector<std::string> strList2 = {};
    for (auto propertyNode : nodeList) {
        auto nodeName = GetIdentifierName(propertyNode);
        auto typeAnnotation = propertyNode->AsClassProperty()->TypeAnnotation();
        if (typeAnnotation->IsETSTypeReference()) {
            auto propertyType = GetNameForTypeReference(typeAnnotation);
            auto str = nodeName;
            str += ": ";
            str += propertyType;
            str += ", ";
            strList1.push_back(str);
            strList2.push_back(nodeName);
        }
    }

    for (const auto &str : strList1) {
        parameterList += str;
    }

    if (isSuper) {
        functionBody += "  super(";
        for (const auto &str : strList2) {
            functionBody += str;
            functionBody += ", ";
        }
        RemoveTrailingChar(functionBody, ",");
        functionBody += ");\n";
    } else {
        for (const auto &str : strList2) {
            functionBody += "  this.";
            functionBody += str;
            functionBody += " = ";
            functionBody += str;
            functionBody += ";\n";
        }
    }
}

std::string CollectConstructorInfo(const std::vector<ir::AstNode *> &classProperties,
                                   const std::vector<ir::AstNode *> &extendedClassProperties)
{
    std::string constructorInfoText = "constructor(";
    std::string parameterList;
    std::string functionBody;

    if (!extendedClassProperties.empty()) {
        GetParameterListAndFunctionBody(parameterList, functionBody, extendedClassProperties, true);
    }
    GetParameterListAndFunctionBody(parameterList, functionBody, classProperties, false);
    RemoveTrailingChar(parameterList, ",");
    constructorInfoText += parameterList;
    constructorInfoText += ") {\n";
    constructorInfoText += functionBody;
    constructorInfoText += "}";
    return constructorInfoText;
}

void GetInsertNodePosition(ir::AstNode *classNode, size_t &insertPosition)
{
    if (classNode == nullptr || !classNode->IsClassDeclaration()) {
        return;
    }

    bool isExitProperty = false;
    auto classBody = classNode->AsClassDeclaration()->Definition()->Body();
    for (auto node : classBody) {
        if (node->IsClassProperty() && !isExitProperty) {
            insertPosition = node->AsClassProperty()->Start().index;
            isExitProperty = true;
            break;
        }
    }

    if (!isExitProperty) {
        const int offset = 2;
        insertPosition = classNode->End().index - offset;
    }
}

std::vector<FileTextChanges> GetRefactorActionsToGenerateConstructor(es2panda_Context *context, size_t position,
                                                                     const std::vector<std::string> &properties)
{
    if (context == nullptr) {
        return {};
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return {};
    }

    ir::AstNode *classDeclaration = ark::es2panda::lsp::GetTargetDeclarationNodeByPosition(context, position);
    if (!IsDefinedClassOrStruct(classDeclaration)) {
        return {};
    }

    if (HasConstructorNode(classDeclaration)) {
        return {};
    }

    std::vector<ir::AstNode *> classProperties = GetClassProperties(classDeclaration, properties);
    std::vector<ir::AstNode *> extendedClassProperties = GetExtendedClassProperties(classDeclaration);

    std::string text = CollectConstructorInfo(classProperties, extendedClassProperties);
    size_t insertPosition = 0;
    GetInsertNodePosition(classDeclaration, insertPosition);

    std::vector<FileTextChanges> fileTextChanges;
    TextSpan span(insertPosition, text.size());
    std::vector<TextChange> textChanges;
    textChanges.emplace_back(TextChange(span, text));
    auto fileName = ctx->sourceFileName;
    FileTextChanges textChange(fileName, textChanges);
    fileTextChanges.push_back(textChange);

    return fileTextChanges;
}

}  // namespace ark::es2panda::lsp