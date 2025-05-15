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

#include "types.h"

SymbolDisplayPart CreatePunctuation(std::string punc)
{
    return SymbolDisplayPart(std::move(punc), "punctuation");
}

SymbolDisplayPart CreateKeyword(std::string keyword)
{
    return SymbolDisplayPart(std::move(keyword), "keyword");
}

SymbolDisplayPart CreateSpace()
{
    return SymbolDisplayPart(" ", "space");
}

SymbolDisplayPart CreateText(std::string text)
{
    return SymbolDisplayPart(std::move(text), "text");
}

SymbolDisplayPart CreateClassName(std::string className)
{
    return SymbolDisplayPart(std::move(className), "className");
}

SymbolDisplayPart CreateFunctionName(std::string functionName)
{
    return SymbolDisplayPart(std::move(functionName), "functionName");
}

SymbolDisplayPart CreateTypeName(std::string typeName)
{
    return SymbolDisplayPart(std::move(typeName), "typeName");
}

SymbolDisplayPart CreateEnumName(std::string enumName)
{
    return SymbolDisplayPart(std::move(enumName), "enumName");
}

SymbolDisplayPart CreateEnumMember(std::string enumMember)
{
    return SymbolDisplayPart(std::move(enumMember), "enumMember");
}

SymbolDisplayPart CreateInterface(std::string interface)
{
    return SymbolDisplayPart(std::move(interface), "interface");
}

SymbolDisplayPart CreateTypeParameter(std::string typeParameter)
{
    return SymbolDisplayPart(std::move(typeParameter), "typeParameter");
}

SymbolDisplayPart CreateFunctionParameter(std::string functionParameter)
{
    return SymbolDisplayPart(std::move(functionParameter), "functionParameter");
}

SymbolDisplayPart CreateOperator(std::string oper)
{
    return SymbolDisplayPart(std::move(oper), "operator");
}

SymbolDisplayPart CreateReturnType(std::string returnType)
{
    return SymbolDisplayPart(std::move(returnType), "returnType");
}

SymbolDisplayPart CreateProperty(std::string property)
{
    return SymbolDisplayPart(std::move(property), "property");
}

SymbolDisplayPart CreateNamespace(std::string name)
{
    return SymbolDisplayPart(std::move(name), "namespace");
}

SymbolDisplayPart SignatureCreateStructName(const std::string &name)
{
    return SymbolDisplayPart(name, "structName");
}

SymbolDisplayPart SignatureCreateParameterName(std::string &type)
{
    return SymbolDisplayPart(type, "paramName");
}