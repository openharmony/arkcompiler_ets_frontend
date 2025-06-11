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

#ifndef ES2PANDA_LSP_CLASS_HIERARCHY_ITEM_H
#define ES2PANDA_LSP_CLASS_HIERARCHY_ITEM_H

#include <string>

namespace ark::es2panda::lsp {
enum class SetterStyle { NONE = 0, SETTER, GETTER };

enum class AccessModifierStyle { PUBLIC = 0, PROTECTED, PRIVATE };

enum class ClassDefinitionStyle { FIELD = 0, METHOD };

class ClassHierarchyItem {
public:
    ClassHierarchyItem(AccessModifierStyle access, std::string detail)
        : accessModifier_(access), detail_(std::move(detail))
    {
    }

    virtual ~ClassHierarchyItem() = default;

    ClassHierarchyItem(const ClassHierarchyItem &other) = default;
    ClassHierarchyItem(ClassHierarchyItem &&other) = default;
    ClassHierarchyItem &operator=(const ClassHierarchyItem &other) = default;
    ClassHierarchyItem &operator=(ClassHierarchyItem &&other) = default;

    virtual ClassDefinitionStyle GetClassDefinitionStyle() const = 0;

    AccessModifierStyle GetAccessModifierStyle() const
    {
        return accessModifier_;
    }

    const std::string &GetDetail() const
    {
        return detail_;
    }

private:
    AccessModifierStyle accessModifier_;
    std::string detail_;
};

class ClassPropertyItem : public ClassHierarchyItem {
public:
    ClassPropertyItem(AccessModifierStyle access, std::string detail) : ClassHierarchyItem(access, std::move(detail)) {}

    ~ClassPropertyItem() override = default;

    ClassPropertyItem(const ClassPropertyItem &other) = default;
    ClassPropertyItem(ClassPropertyItem &&other) = default;
    ClassPropertyItem &operator=(const ClassPropertyItem &other) = default;
    ClassPropertyItem &operator=(ClassPropertyItem &&other) = default;

    ClassDefinitionStyle GetClassDefinitionStyle() const override
    {
        return ClassDefinitionStyle::FIELD;
    }

    void SetVariableName(const std::string &variableName)
    {
        if (variableName.empty()) {
            return;
        }
        variableName_ = variableName;
    }

    const std::string &GetVariableName() const
    {
        return variableName_;
    }

private:
    std::string variableName_;
};

class ClassMethodItem : public ClassHierarchyItem {
public:
    ClassMethodItem(AccessModifierStyle access, std::string detail, SetterStyle setter)
        : ClassHierarchyItem(access, std::move(detail)), setter_(setter)
    {
    }

    ~ClassMethodItem() override = default;

    ClassMethodItem(const ClassMethodItem &other) = default;
    ClassMethodItem(ClassMethodItem &&other) = default;
    ClassMethodItem &operator=(const ClassMethodItem &other) = default;
    ClassMethodItem &operator=(ClassMethodItem &&other) = default;

    ClassDefinitionStyle GetClassDefinitionStyle() const override
    {
        return ClassDefinitionStyle::METHOD;
    }

    void SetFunctionName(const std::string &functionName)
    {
        if (functionName.empty()) {
            return;
        }
        funcName_ = functionName;
    }

    const std::string &GetFunctionName() const
    {
        return funcName_;
    }

    SetterStyle GetSetterStyle() const
    {
        return setter_;
    }

private:
    std::string funcName_;
    SetterStyle setter_;
};
}  // namespace ark::es2panda::lsp

#endif
