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

#include "lsp_api_test.h"

#include <gtest/gtest.h>
#include <cstddef>

#include "ir/astNode.h"
#include "lsp/include/internal_api.h"
#include "public/es2panda_lib.h"
#include "public/public.h"

using ark::es2panda::lsp::Initializer;

class LspGetReferenceLocationTests : public LSPAPITests {};

TEST_F(LspGetReferenceLocationTests, GetReferenceLocationAtPosition1)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"ref_loc_export1.ts", "ref_loc_export2.ts", "ref_loc_export3.ts",
                                      "ref_loc_export4.ts", "<ref-file.ets>"};
    std::vector<std::string> texts = {"function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);"};
    auto filePaths = CreateTempFile(files, texts);
    std::vector<std::string> autoGenerateFolders = {"export1.ts", "export2.ts"};

    ark::es2panda::lsp::RemoveFromFiles(files, autoGenerateFolders);
    const size_t fileCount = 3;
    ASSERT_EQ(files.size(), fileCount);
}

TEST_F(LspGetReferenceLocationTests, GetReferenceLocationAtPosition2)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> fileNames = {"firstFile.ets", "secondFile.ets", "thirdFile.ets"};
    std::vector<std::string> fileContents = {
        "export function abc(x: number): void {\n}\n\nexport function dummy(x: number): void {\n}\n"
        "\nexport class Foo {\nname: string = \"unassigned\";\nx: number = 1;\ny: number = 2;\nz: number = 3;"
        "\nconstructor(name: string, x: number, y: number, z: number) {\nthis.name = name;\nthis.x = x;\nthis.y = "
        "y;\nthis.z = z;\n}\n};",
        "import {dummy, abc} from \"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(1);\nabc(2);",
        "import { dummy, abc } from "
        "\"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(3);\nabc(4);\nabc(5);\n"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    Initializer initializer = Initializer();
    const int position = 17;
    const int fileIndex = 0;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    FileNodeInfo fileNameInfo(tokenName, tokenId);
    auto list = ReferenceLocationList();
    initializer.DestroyContext(context);
    for (const std::string &file : filePaths) {
        auto ctx = initializer.CreateContext(file.c_str(), ES2PANDA_STATE_CHECKED);
        ark::es2panda::lsp::GetReferenceLocationAtPositionImpl(fileNameInfo, ctx, &list);
        initializer.DestroyContext(ctx);
    }
    const size_t file1Location = 0;
    const size_t start1Index = 16;
    const size_t file2Location = 2;
    const size_t start2Index = 70;
    ASSERT_EQ(list.referenceLocation.at(file1Location).uri, filePaths[0]);
    ASSERT_EQ(list.referenceLocation.at(file1Location).start, start1Index);
    ASSERT_EQ(list.referenceLocation.at(file2Location).uri, filePaths[1]);
    ASSERT_EQ(list.referenceLocation.at(file2Location).start, start2Index);
}

TEST_F(LspGetReferenceLocationTests, GetReferenceLocationAtPosition3)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> fileNames = {"firstFile.ets", "secondFile.ets", "thirdFile.ets"};
    std::vector<std::string> fileContents = {
        "export function abc(x: number): void {\n}\n\nexport function dummy(x: number): void {\n}\n"
        "\nexport class Foo {\nname: string = \"unassigned\";\nx: number = 1;\ny: number = 2;\nz: number = 3;"
        "\nconstructor(name: string, x: number, y: number, z: number) {\nthis.name = name;\nthis.x = x;\nthis.y = "
        "y;\nthis.z = z;\n}\n};",
        "import {dummy, abc} from \"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(1);\nabc(2);",
        "import { dummy, abc } from "
        "\"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(3);\nabc(4);\nabc(5);\n"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    Initializer initializer = Initializer();
    const int position = 73;
    const int fileIndex = 1;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    FileNodeInfo fileNameInfo(tokenName, tokenId);
    auto list = ReferenceLocationList();
    initializer.DestroyContext(context);
    for (const std::string &file : filePaths) {
        auto ctx = initializer.CreateContext(file.c_str(), ES2PANDA_STATE_CHECKED);
        ark::es2panda::lsp::GetReferenceLocationAtPositionImpl(fileNameInfo, ctx, &list);

        initializer.DestroyContext(ctx);
    }
    const size_t file1Location = 0;
    const size_t start1Index = 16;
    const size_t file2Location = 2;
    const size_t start2Index = 70;
    ASSERT_EQ(list.referenceLocation.at(file1Location).uri, filePaths[0]);
    ASSERT_EQ(list.referenceLocation.at(file1Location).start, start1Index);
    ASSERT_EQ(list.referenceLocation.at(file2Location).uri, filePaths[1]);
    ASSERT_EQ(list.referenceLocation.at(file2Location).start, start2Index);
}

TEST_F(LspGetReferenceLocationTests, GetReferenceLocationAtPosition4)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> fileNames = {"firstFile.ets", "secondFile.ets", "thirdFile.ets"};
    std::vector<std::string> fileContents = {
        "export function abc(x: number): void {\n}\n\nexport function dummy(x: number): void {\n}\n"
        "\nexport class Foo {\nname: string = \"unassigned\";\nx: number = 1;\ny: number = 2;\nz: number = 3;"
        "\nconstructor(name: string, x: number, y: number, z: number) {\nthis.name = name;\nthis.x = x;\nthis.y = "
        "y;\nthis.z = z;\n}\n};",
        "import {dummy, abc} from \"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(1);\nabc(2);",
        "import { dummy, abc } from "
        "\"./firstFile.ets\";\n\ndummy(123);\ndummy(1992);\nabc(3);\nabc(4);\nabc(5);\n"};
    auto filePaths = CreateTempFile(fileNames, fileContents);
    ASSERT_TRUE(filePaths.size() == fileContents.size());
    Initializer initializer = Initializer();
    const int position = 58;
    const int fileIndex = 0;
    auto context = initializer.CreateContext(filePaths[fileIndex].c_str(), ES2PANDA_STATE_CHECKED);
    auto node = ark::es2panda::lsp::GetTouchingToken(context, position, false);
    auto tokenId = ark::es2panda::lsp::GetOwnerId(node);
    auto tokenName = ark::es2panda::lsp::GetIdentifierName(node);
    FileNodeInfo fileNameInfo(tokenName, tokenId);
    auto list = ReferenceLocationList();
    initializer.DestroyContext(context);
    for (const std::string &file : filePaths) {
        auto ctx = initializer.CreateContext(file.c_str(), ES2PANDA_STATE_CHECKED);
        ark::es2panda::lsp::GetReferenceLocationAtPositionImpl(fileNameInfo, ctx, &list);
        initializer.DestroyContext(ctx);
    }
    const size_t file1Location = 0;
    const size_t start1Index = 58;
    const size_t file2Location = 1;
    const size_t start2Index = 8;

    ASSERT_EQ(list.referenceLocation.at(file1Location).uri, filePaths[0]);
    ASSERT_EQ(list.referenceLocation.at(file1Location).start, start1Index);
    ASSERT_EQ(list.referenceLocation.at(file2Location).uri, filePaths[1]);
    ASSERT_EQ(list.referenceLocation.at(file2Location).start, start2Index);
}
