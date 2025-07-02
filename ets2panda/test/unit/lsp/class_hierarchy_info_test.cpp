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

#include "lsp/include/class_hierarchy_info.h"
#include "lsp_api_test.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>

using ark::es2panda::lsp::Initializer;

namespace {

class LspScriptElementKindTests : public LSPAPITests {};

TEST_F(LSPAPITests, GetClassHierarchyInfo_1)
{
    LSPAPI const *lspApi = GetImpl();
    ASSERT_TRUE(lspApi != nullptr);
    const std::string text = R"(class Parent {
private privateMethod(): void {
  console.log("Parent method");
}
  public publicMethod(): void {
  console.log("Parent method");
}
  protected action(fileName: string, position: number): number {
  return position;
}
  static staticMethod(): void {
  console.log("Parent static method");
  }
}
  class Child extends Parent {
  public display(): void {
    console.log("need display");
  }
})";

    auto pos = text.find("Child");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext("class_hierarchy_info_1.ets", ES2PANDA_STATE_CHECKED, text.c_str());
    auto classHierarchy = lspApi->getClassHierarchyInfo(context, pos);

    ASSERT_EQ(classHierarchy.size(), 1);
    ASSERT_EQ(classHierarchy[0].GetClassName(), "Parent");
    auto methods = classHierarchy[0].GetMethodList();
    auto it = methods.find("publicMethod()");
    ASSERT_TRUE(it != methods.end());
    ASSERT_TRUE(it->second != nullptr);
    ASSERT_EQ(it->second->GetSetterStyle(), ark::es2panda::lsp::SetterStyle::METHOD);
    ASSERT_EQ(it->second->GetAccessModifierStyle(), ark::es2panda::lsp::AccessModifierStyle::PUBLIC);
    it = methods.find("action(fileName: string, position: number): number");
    ASSERT_TRUE(it != methods.end());
    ASSERT_TRUE(it->second != nullptr);
    ASSERT_EQ(it->second->GetSetterStyle(), ark::es2panda::lsp::SetterStyle::METHOD);
    ASSERT_EQ(it->second->GetAccessModifierStyle(), ark::es2panda::lsp::AccessModifierStyle::PROTECTED);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetClassHierarchyInfo_2)
{
    LSPAPI const *lspApi = GetImpl();
    ASSERT_TRUE(lspApi != nullptr);
    const std::string text = R"(class Animal {
private body_: string = '';

  protected action(): void {
    console.log("need Animal action");
  }
  protected sleep(): void {
    console.log("need Animal sleep");
  }
}

class Bird extends Animal {
  action(): void {
    console.log("need action");
  }

  Drink(): void {
    console.log("need Drink");
  }
}

class Magpie extends Bird {
  public action(): void {}
  Drink(): void {
    console.log("need Drink");
  }
})";

    auto pos = text.find("Magpie");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext("class_hierarchy_info_2.ets", ES2PANDA_STATE_CHECKED, text.c_str());
    auto classHierarchy = lspApi->getClassHierarchyInfo(context, pos);
    ASSERT_EQ(classHierarchy.size(), 1);
    ASSERT_EQ(classHierarchy[0].GetClassName(), "Animal");

    auto methods = classHierarchy[0].GetMethodList();
    auto it = methods.find("sleep()");
    ASSERT_TRUE(it != methods.end());
    ASSERT_TRUE(it->second != nullptr);
    ASSERT_EQ(it->second->GetSetterStyle(), ark::es2panda::lsp::SetterStyle::METHOD);
    ASSERT_EQ(it->second->GetAccessModifierStyle(), ark::es2panda::lsp::AccessModifierStyle::PROTECTED);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetClassHierarchyInfo_3)
{
    LSPAPI const *lspApi = GetImpl();
    ASSERT_TRUE(lspApi != nullptr);
    const std::string text = R"(class Animal {
  private body_: string = '';

  protected action(): void {
    console.log("need action");
  }
  protected sleep(): void {
    console.log("need sleep");
  }
})";

    auto pos = text.find("Animal");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext("class_hierarchy_info_3.ets", ES2PANDA_STATE_CHECKED, text.c_str());
    auto classHierarchy = lspApi->getClassHierarchyInfo(context, pos);
    ASSERT_TRUE(classHierarchy.empty());
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetClassHierarchyInfo_4)
{
    LSPAPI const *lspApi = GetImpl();
    ASSERT_TRUE(lspApi != nullptr);
    const std::string text = R"(class ii {
  private body_: string = '';

  action(): void {
    console.log("need sleep");
  }

  set Body(value: string) {
    this.body_ = value;
  }
  get Body(): string {
    return this.body_;
  }
}

  class jj extends ii {
  private age_: number = 18;
  public action(): void {
    console.log("need sleep and fly");
  }
})";

    auto pos = text.find("jj");
    ASSERT_NE(pos, std::string::npos);
    Initializer initializer = Initializer();
    auto context = initializer.CreateContext("class_hierarchy_info_4.ets", ES2PANDA_STATE_CHECKED, text.c_str());
    auto classHierarchy = lspApi->getClassHierarchyInfo(context, pos);
    ASSERT_EQ(classHierarchy.size(), 1);
    ASSERT_EQ(classHierarchy[0].GetClassName(), "ii");

    auto methods = classHierarchy[0].GetMethodList();
    auto it = methods.find("Body(): string");
    ASSERT_TRUE(it != methods.end());
    ASSERT_TRUE(it->second != nullptr);
    ASSERT_EQ(it->second->GetSetterStyle(), ark::es2panda::lsp::SetterStyle::GETTER);
    ASSERT_EQ(it->second->GetAccessModifierStyle(), ark::es2panda::lsp::AccessModifierStyle::PUBLIC);
    it = methods.find("Body(value: string)");
    ASSERT_TRUE(it != methods.end());
    ASSERT_TRUE(it->second != nullptr);
    ASSERT_EQ(it->second->GetSetterStyle(), ark::es2panda::lsp::SetterStyle::SETTER);
    ASSERT_EQ(it->second->GetAccessModifierStyle(), ark::es2panda::lsp::AccessModifierStyle::PUBLIC);
    initializer.DestroyContext(context);
}
}  // namespace
