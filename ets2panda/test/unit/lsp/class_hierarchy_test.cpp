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

#include <cstddef>
#include <cstdio>
#include <gtest/gtest.h>
#include <regex>
#include <string>
#include <vector>

#include "lsp_api_test.h"
#include "lsp/include/class_hierarchy.h"
#include "lsp/include/internal_api.h"

namespace {

class LspClassHierarchyTests : public LSPAPITests {};

TEST_F(LspClassHierarchyTests, GetTypeHierarchiesImpl_001)
{
    std::vector<std::string> fileNames = {"aa1.ets", "bb1.ets", "cc1.ets", "ii1.ets", "mm1.ets", "nn1.ets", "pp1.ets"};
    std::vector<std::string> fileContents = {
        R"(
        export class AAA {}
        )",
        R"(
        import { AAA } from "./aa1"
        export class BBB extends AAA {}
    )",
        R"(import { BBB } from "./bb1"
        import { NNN } from "./nn1"
        import { PPP } from "./pp1"
        class CCC extends BBB implements NNN, PPP {}
    )",
        R"(export interface III {}
    )",
        R"(
        export interface MMM {}
    )",
        R"(import { III } from "./ii1"
        import { MMM } from "./mm1"
        export interface NNN extends III, MMM {}
        export interface NNN2 extends III {}
        export interface NNN3 extends NNN2 {}
        export interface NNN4 extends NNN2 {}
    )",
        R"(export interface PPP {}
    )"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    const int position = 120;
    const int fileIndex = 2;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    auto res = ark::es2panda::lsp::GetTypeHierarchiesImpl(context, position);
    initializer.DestroyContext(context);
    const size_t parentNum1 = 3;
    const size_t parentNum2 = 1;
    ASSERT_EQ(res.superHierarchies.subOrSuper.size(), parentNum1);
    ASSERT_EQ(res.superHierarchies.subOrSuper[0].subOrSuper.size(), parentNum2);
}

TEST_F(LspClassHierarchyTests, GetTypeHierarchiesImpl_002)
{
    std::vector<std::string> fileNames = {"aa2.ets", "bb2.ets", "cc2.ets", "ii2.ets", "mm2.ets", "nn2.ets", "pp2.ets"};
    std::vector<std::string> fileContents = {
        R"(
        export class AAA {}
        )",
        R"(
        import { AAA } from "./aa2"
        export class BBB extends AAA {}
    )",
        R"(import { BBB } from "./bb2"
        import { NNN } from "./nn2"
        import { PPP } from "./pp2"
        class CCC extends BBB implements NNN, PPP {}
    )",
        R"(export interface III {}
    )",
        R"(
        export interface MMM {}
    )",
        R"(import { III } from "./ii2"
        import { MMM } from "./mm2"
        export interface NNN extends III, MMM {}
        export interface NNN2 extends III {}
        export interface NNN3 extends NNN2 {}
        export interface NNN4 extends NNN2 {}
    )",
        R"(export interface PPP {}
    )"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    const int position = 94;
    const int fileIndex = 5;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    auto res = ark::es2panda::lsp::GetTypeHierarchiesImpl(context, position);
    initializer.DestroyContext(context);
    const size_t parentNum1 = 2;
    ASSERT_EQ(res.superHierarchies.subOrSuper.size(), parentNum1);
}

TEST_F(LspClassHierarchyTests, GetTypeHierarchiesImpl_003)
{
    std::vector<std::string> fileNames = {"aa3.ets", "bb3.ets", "cc3.ets", "ii3.ets", "mm3.ets", "nn3.ets", "pp3.ets"};
    std::vector<std::string> fileContents = {
        R"(
        export class AAA {}
        )",
        R"(
        import { AAA } from "./aa3"
        export class BBB extends AAA {}
    )",
        R"(import { BBB } from "./bb3"
        import { NNN } from "./nn3"
        import { PPP } from "./pp3"
        class CCC extends BBB implements NNN, PPP {}
    )",
        R"(export interface III {}
    )",
        R"(
        export interface MMM {}
    )",
        R"(import { III } from "./ii3"
        import { MMM } from "./mm3"
        export interface NNN extends III, MMM {}
        export interface NNN2 extends III {}
        export interface NNN3 extends NNN2 {}
        export interface NNN4 extends NNN2 {}
    )",
        R"(export interface PPP {}
    )"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    const int position = 20;
    const int fileIndex = 3;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTargetDeclarationNodeByPosition(context, position);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    const int fileIndex5 = 5;
    auto context5 = initializer.CreateContext(filePaths[fileIndex5].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = ark::es2panda::lsp::GetTypeHierarchiesImpl(context5, position, node);
    initializer.DestroyContext(context);
    const size_t childNum1 = 2;
    const size_t childNum2 = 2;
    ASSERT_EQ(res.subHierarchies.subOrSuper.size(), childNum1);
    ASSERT_EQ(res.subHierarchies.subOrSuper[1].subOrSuper.size(), childNum2);
}

TEST_F(LspClassHierarchyTests, GetTypeHierarchiesImpl_004)
{
    std::vector<std::string> fileNames = {"aa4.ets", "bb4.ets", "cc4.ets", "dd4.ets"};
    std::vector<std::string> fileContents = {
        R"(
        export class AAA {}
        )",
        R"(
        import { AAA } from "./aa4"
        export class BBB extends AAA {}
    )",
        R"(import { AAA } from "./aa4"
        class CCC extends AAA {}
    )",
        R"(import { BBB } from "./bb4"
        class DDD extends BBB {}
    )"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    const int position = 26;
    const int fileIndex = 0;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTargetDeclarationNodeByPosition(context, position);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    const int fileIndex5 = 1;
    auto context5 = initializer.CreateContext(filePaths[fileIndex5].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = ark::es2panda::lsp::GetTypeHierarchiesImpl(context5, position, node);
    initializer.DestroyContext(context);
    const size_t childNum1 = 1;
    ASSERT_EQ(res.subHierarchies.subOrSuper.size(), childNum1);
}
}  // namespace