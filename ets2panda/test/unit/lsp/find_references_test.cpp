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
#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "es2panda.h"
#include "lsp/include/find_references.h"
#include "lsp/include/cancellation_token.h"
#include "lsp_api_test.h"

// NOLINTBEGIN
using ark::es2panda::SourceFile;
using ark::es2panda::lexer::SourcePosition;
using ark::es2panda::lsp::FindReferences;
using std::string;
using std::vector;

// Simple helper to get the index and line of occurences to a string
static vector<SourcePosition> GetTokenPositions(string source, string token)
{
    vector<SourcePosition> res;
    auto findLineNumber = [&source](string::size_type index) {
        string::size_type line = 0;
        for (size_t i = 0; i < index && i < source.size(); ++i) {
            if (source[i] == '\n') {
                ++line;
            }
        }
        return line;
    };
    auto pos = source.find(token);
    if (pos != string::npos)
        res.push_back({SourcePosition {pos, findLineNumber(pos)}});
    else {
        return {};
    }
    while (pos != string::npos && pos < source.size()) {
        pos = source.find(token, pos + 1);
        if (pos == string::npos) {
            break;
        }
        res.push_back({SourcePosition {pos, findLineNumber(pos)}});
    }
    return res;
}

static FileRefMap getExpectedRefMap(vector<SourceFile> &sourceFiles, string token)
{
    FileRefMap expected;
    for (auto src : sourceFiles) {
        auto filePath = string {src.filePath};
        auto fileContent = string {src.source};
        auto posList = GetTokenPositions(fileContent, token);
        expected.insert({filePath, posList});
    }
    return expected;
}

static auto testCase(vector<SourceFile> &sourceFiles, SourceFile selectedFile, string token, int tokenIndex,
                     FileRefMap expectedRefMap = {})
{
    auto cancellationToken = ark::es2panda::lsp::CancellationToken(123, nullptr);
    if (expectedRefMap.empty()) {
        expectedRefMap = getExpectedRefMap(sourceFiles, token);
    }
    auto posListSelectedFile = expectedRefMap[string {selectedFile.filePath}];
    auto selectedTokenPos = posListSelectedFile[tokenIndex].index;
    auto res = FindReferences(&cancellationToken, sourceFiles, selectedFile, selectedTokenPos);

    ASSERT_EQ(res.size(), expectedRefMap.size());

    for (auto entry : res) {
        auto fp = entry.first;
        auto posList = entry.second;
        auto expectedPosList = expectedRefMap[fp];

        string info;
        info += "Found References:\n";
        for (auto pos : posList) {
            info += "(" + std::to_string(pos.index) + "," + std::to_string(pos.line) + ") ";
        }
        info += "\n";

        info += "Expected References:\n";
        for (auto pos : expectedPosList) {
            info += "(" + std::to_string(pos.index) + "," + std::to_string(pos.line) + ") ";
        }
        info += "\n";

        ASSERT_EQ(posList.size(), expectedPosList.size()) << info;
        for (auto pos : posList) {
            // NOTE(muhammet): This is a buggy case, the identifier for import name specifiers returns the wrong
            // index once the bug is gone we shouldn't skip them anymore
            auto found =
                std::find_if(expectedPosList.begin(), expectedPosList.end(), [&pos](const SourcePosition &epos) {
                    return epos.index == pos.index && epos.line == pos.line;
                });
            ASSERT_NE(found, expectedPosList.end())
                << "Token at position (" << pos.index << ", " << pos.line << "), is not a valid reference in " << fp;
        }
    }
}

vector<string> fileNames = {"findReferencesOne.sts", "findReferencesTwo.sts"};
vector<string> fileContents = {
    R"(
        export function abc(x: number): void {
        }

        export function dummy(x: number): void {
        }

        export class Foo {
            name: string = "unassigned";
            x: number = 1;
            y: number = 2;
            z: number = 3;
            constructor(name: string, x: number, y: number, z: number) {
                this.name = name;
                this.x = x;
                this.y = y;
                this.z = z;
            }
        };

        export class Oranges {
            name: string = "unassigned";
            x: number = 1;
            y: number = 2;
            z: number = 3;
            constructor(name: string, x: number, y: number, z: number) {
                this.name = name;
                this.x = x;
                this.y = y;
                this.z = z;
            }
        };

        dummy(0);
        dummy(1);
        abc(2);
        abc(3);
        abc(4);
        )",
    R"(
        import { dummy, abc, Foo  } from "./findReferencesOne.sts";

        dummy(4);
        dummy(44);
        abc(5);
        abc(55);
        abc(555);

        let myfoo = new Foo("apples", 1, 2, 3);
        let otherfoo = new Foo("oranges", 4, 5, 6);

        console.log(myfoo)
        console.log(otherfoo)
        console.log(myfoo.name)
    )"};

class LspFindRefTests : public LSPAPITests {};

TEST_F(LspFindRefTests, FindReferencesMethodDefinition1)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 1: Search for the first occurance of "abc" within "findReferencesOne.sts" which is a method definition
    {
        auto srcIndex = 0;
        auto tknIndex = 0;
        testCase(sourceFiles, sourceFiles[srcIndex], "abc", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesMethodDefinition2)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 2: Search for the first occurance of "dummy" within "findReferencesOne.sts" which is a method definition
    {
        auto srcIndex = 0;
        auto tknIndex = 0;
        testCase(sourceFiles, sourceFiles[srcIndex], "dummy", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesImportSpecifier)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 3: Search for the first occurance of "abc" within "findReferencesTwo.sts" which is an import specifier
    {
        auto srcIndex = 1;
        auto tknIndex = 0;
        testCase(sourceFiles, sourceFiles[srcIndex], "abc", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesCallExpression1)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 4: Search for the second occurance of "abc" within "findReferencesTwo.sts" which is a function call
    // expression
    {
        auto srcIndex = 1;
        auto tknIndex = 1;
        testCase(sourceFiles, sourceFiles[srcIndex], "abc", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesCallExpression2)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 5: Search for the second occurance of "dummy" within "findReferencesTwo.sts" which is a function call
    // expression
    {
        auto srcIndex = 1;
        auto tknIndex = 1;
        testCase(sourceFiles, sourceFiles[srcIndex], "dummy", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesVariableDefinition)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 6: Search for the first occurance of "myfoo" within "findReferencesTwo.sts" which is a variable definition
    {
        auto srcIndex = 1;
        auto tknIndex = 0;
        testCase(sourceFiles, sourceFiles[srcIndex], "myfoo", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesInstanceCreation)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 7: Search for the first occurance of "Foo" within "findReferencesTwo.sts" which is a class instance creation
    {
        auto srcIndex = 1;
        auto tknIndex = 0;
        testCase(sourceFiles, sourceFiles[srcIndex], "Foo", tknIndex);
    }
}

TEST_F(LspFindRefTests, FindReferencesMemberAccess)
{
    // Create the files
    auto filePaths = CreateTempFile(fileNames, fileContents);
    vector<SourceFile> sourceFiles;
    for (size_t i = 0; i < filePaths.size(); ++i) {
        sourceFiles.emplace_back(SourceFile {filePaths[i], fileContents[i]});
    }
    ASSERT_TRUE(sourceFiles.size() == fileNames.size());

    // Case 7: Search for the first occurance of "name" within "findReferencesTwo.sts" which is a reference to a member
    {
        auto srcIndex = 1;
        auto tknIndex = 0;

        FileRefMap expectedRefMap;
        // First file references
        {
            auto fp = string {sourceFiles[0].filePath};
            expectedRefMap[fp] = {SourcePosition {158, 8}, SourcePosition {362, 13}};
        }
        // Second file references
        {
            auto fp = string {sourceFiles[1].filePath};
            expectedRefMap[fp] = {SourcePosition {343, 14}};
        }

        testCase(sourceFiles, sourceFiles[srcIndex], "name", tknIndex, expectedRefMap);
    }
}

// NOLINTEND
