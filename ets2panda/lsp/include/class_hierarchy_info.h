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

#ifndef ES2PANDA_LSP_CLASS_HIERARCHY_INFO_H
#define ES2PANDA_LSP_CLASS_HIERARCHY_INFO_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {
class FunctionParamStyle {
public:
    FunctionParamStyle(std::string paramName, std::string paramKind)
        : name_(std::move(paramName)), kind_(std::move(paramKind))
    {
    }

    std::string GetParamName() const
    {
        return name_;
    }

    std::string GetParamKind() const
    {
        return kind_;
    }

private:
    std::string name_;
    std::string kind_;
};

enum class SetterStyle { METHOD = 0, SETTER, GETTER };

enum class AccessModifierStyle { PUBLIC = 0, PROTECTED, PRIVATE };

class ClassMethodItem {
public:
    ClassMethodItem(std::string detail, SetterStyle setter, AccessModifierStyle access)
        : detail_(std::move(detail)), setter_(setter), accessMoodifier_(access)
    {
    }

    virtual ~ClassMethodItem() = default;

    ClassMethodItem(const ClassMethodItem &other) = default;
    ClassMethodItem(ClassMethodItem &&other) = default;
    ClassMethodItem &operator=(const ClassMethodItem &other) = default;
    ClassMethodItem &operator=(ClassMethodItem &&other) = default;

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

    const std::string &GetFunctionDetail() const
    {
        return detail_;
    }

    SetterStyle GetSetterStyle() const
    {
        return setter_;
    }

    AccessModifierStyle GetAccessModifierStyle() const
    {
        return accessMoodifier_;
    }

private:
    std::string funcName_;
    std::string detail_;
    SetterStyle setter_;
    AccessModifierStyle accessMoodifier_;
};

class ClassHierarchyInfo {
public:
    ClassHierarchyInfo() = default;

    virtual ~ClassHierarchyInfo() = default;

    ClassHierarchyInfo(const ClassHierarchyInfo &other) = default;
    ClassHierarchyInfo(ClassHierarchyInfo &&other) = default;
    ClassHierarchyInfo &operator=(const ClassHierarchyInfo &other) = default;
    ClassHierarchyInfo &operator=(ClassHierarchyInfo &&other) = default;

    void SetClassName(const std::string &className)
    {
        if (className.empty()) {
            return;
        }
        className_ = className;
    }

    const std::string &GetClassName() const
    {
        return className_;
    }

    const std::unordered_map<std::string, std::shared_ptr<ClassMethodItem>> &GetMethodList() const
    {
        return methods_;
    }

    bool AddClassMethodItem(const std::shared_ptr<ClassMethodItem> &item)
    {
        if (item == nullptr || IsItemExist(item)) {
            return false;
        }
        auto funcDetail = item->GetFunctionDetail();
        methods_[funcDetail] = item;
        return true;
    }

    void DeleteClassMethodItem(const std::shared_ptr<ClassMethodItem> &item)
    {
        if (item == nullptr) {
            return;
        }
        auto funcDetail = item->GetFunctionDetail();
        methods_.erase(funcDetail);
    }

    void DeleteAllClassMethodItem()
    {
        methods_.clear();
    }

    bool IsItemExist(const std::shared_ptr<ClassMethodItem> &item) const
    {
        if (item == nullptr) {
            return false;
        }
        auto func = item->GetFunctionDetail();
        auto iter = methods_.find(func);
        return iter != methods_.end();
    }

private:
    std::string className_;
    std::unordered_map<std::string, std::shared_ptr<ClassMethodItem>> methods_;
};

using ClassHierarchy = std::vector<ClassHierarchyInfo>;

/**
 * Retrieve the list of undefined virtual functions in the parent class.
 *
 * such as ets:
 * class Animal {
 *   private body_: string = '';
 *
 *   public action(): void {
 *       console.log("need Animal action");
 *   }
 *   public sleep(): void {
 *       console.log("need sleep");
 *   }
 * }
 *
 * class Bird extends Animal {
 *   action(): void {
 *       console.log("need Bird action");
 *   }
 *
 *   Drink(): void {
 *       console.log("need Bird Drink");
 *   }
 * }
 *
 * when clicking 'Bird'.
 * ClassHierarchy is [ { "Animal", { detail: sleep(), SetterStyle: METHOD, AccessModifierStyle: PUBLIC } } ].
 */
ClassHierarchy GetClassHierarchyInfoImpl(es2panda_Context *context, size_t position);
}  // namespace ark::es2panda::lsp

#endif
