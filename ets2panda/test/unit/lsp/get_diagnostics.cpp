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

#include "lsp/include/internal_api.h"
#include "lsp/include/classifier.h"
#include "lsp_api_test.h"
#include "public/es2panda_lib.h"

class LspDiagnosticsTests : public LSPAPITests {};

TEST_F(LspDiagnosticsTests, GetSemanticDiagnostics1)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError1.sts"};
    std::vector<std::string> texts = {R"delimiter(
function add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    DiagnosticReferences result = lspApi->getSemanticDiagnostics(filePaths[0].c_str());
    ASSERT_EQ(result.diagnostic.size(), 0);
}

TEST_F(LspDiagnosticsTests, GetSemanticDiagnostics2)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError2.sts"};
    std::vector<std::string> texts = {R"delimiter(
const a: number = "hello";
function add(a: number, b: number): number {
    return a + b;
}
add("1", 2);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    DiagnosticReferences result = lspApi->getSemanticDiagnostics(filePaths[0].c_str());
    auto const expectedErrorCount = 3;
    ASSERT_EQ(result.diagnostic.size(), expectedErrorCount);
    auto const expectedFirstStartLine = 2;
    auto const expectedFirstStartCharacter = 19;
    auto const expectedFirstEndLine = 2;
    auto const expectedFirstEndCharacter = 26;
    ASSERT_EQ(result.diagnostic[0].range_.start.line_, expectedFirstStartLine);
    ASSERT_EQ(result.diagnostic[0].range_.start.character_, expectedFirstStartCharacter);
    ASSERT_EQ(result.diagnostic[0].range_.end.line_, expectedFirstEndLine);
    ASSERT_EQ(result.diagnostic[0].range_.end.character_, expectedFirstEndCharacter);
    ASSERT_EQ(result.diagnostic[0].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[0].code_), 1);
    ASSERT_EQ(result.diagnostic[0].message_, R"(Type '"hello"' cannot be assigned to type 'double')");
    ASSERT_EQ(result.diagnostic[0].codeDescription_.href_, "test code description");
    auto const expectedSecondStartLine = 6;
    auto const expectedSecondStartCharacter = 5;
    auto const expectedSecondEndLine = 6;
    auto const expectedSecondEndCharacter = 8;
    ASSERT_EQ(result.diagnostic[1].range_.start.line_, expectedSecondStartLine);
    ASSERT_EQ(result.diagnostic[1].range_.start.character_, expectedSecondStartCharacter);
    ASSERT_EQ(result.diagnostic[1].range_.end.line_, expectedSecondEndLine);
    ASSERT_EQ(result.diagnostic[1].range_.end.character_, expectedSecondEndCharacter);
    ASSERT_EQ(result.diagnostic[1].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[1].code_), 1);
    ASSERT_EQ(result.diagnostic[1].message_, R"(Type '"1"' is not compatible with type 'double' at index 1)");
    ASSERT_EQ(result.diagnostic[1].codeDescription_.href_, "test code description");
}

TEST_F(LspDiagnosticsTests, GetSyntacticDiagnostics1)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError1.sts"};
    std::vector<std::string> texts = {R"delimiter(
function add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    auto result = lspApi->getSyntacticDiagnostics(filePaths[0].c_str());
    ASSERT_EQ(result.diagnostic.size(), 0);
}

TEST_F(LspDiagnosticsTests, GetSyntacticDiagnostics2)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError2.sts"};
    std::vector<std::string> texts = {R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    auto result = lspApi->getSyntacticDiagnostics(filePaths[0].c_str());
    auto const expectedErrorCount = 13;
    ASSERT_EQ(result.diagnostic.size(), expectedErrorCount);
    auto const expectedFirstStartLine = 2;
    auto const expectedFirstStartCharacter = 9;
    auto const expectedFirstEndLine = 2;
    auto const expectedFirstEndCharacter = 12;
    ASSERT_EQ(result.diagnostic[0].range_.start.line_, expectedFirstStartLine);
    ASSERT_EQ(result.diagnostic[0].range_.start.character_, expectedFirstStartCharacter);
    ASSERT_EQ(result.diagnostic[0].range_.end.line_, expectedFirstEndLine);
    ASSERT_EQ(result.diagnostic[0].range_.end.character_, expectedFirstEndCharacter);
    ASSERT_EQ(result.diagnostic[0].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[0].code_), 1);
    auto const expectedSecondStartLine = 3;
    auto const expectedSecondStartCharacter = 18;
    auto const expectedSecondEndLine = 3;
    auto const expectedSecondEndCharacter = 18;
    ASSERT_EQ(result.diagnostic[1].range_.start.line_, expectedSecondStartLine);
    ASSERT_EQ(result.diagnostic[1].range_.start.character_, expectedSecondStartCharacter);
    ASSERT_EQ(result.diagnostic[1].range_.end.line_, expectedSecondEndLine);
    ASSERT_EQ(result.diagnostic[1].range_.end.character_, expectedSecondEndCharacter);
    ASSERT_EQ(result.diagnostic[1].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[1].code_), 1);
    auto const thirdIndex = 2;
    auto const expectedThirdStartLine = 3;
    auto const expectedThirdStartCharacter = 18;
    auto const expectedThirdEndLine = 3;
    auto const expectedThirdEndCharacter = 18;
    ASSERT_EQ(result.diagnostic[thirdIndex].range_.start.line_, expectedThirdStartLine);
    ASSERT_EQ(result.diagnostic[thirdIndex].range_.start.character_, expectedThirdStartCharacter);
    ASSERT_EQ(result.diagnostic[thirdIndex].range_.end.line_, expectedThirdEndLine);
    ASSERT_EQ(result.diagnostic[thirdIndex].range_.end.character_, expectedThirdEndCharacter);
    ASSERT_EQ(result.diagnostic[thirdIndex].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[thirdIndex].code_), 1);
    ASSERT_EQ(result.diagnostic[thirdIndex].message_, R"(Unexpected token ':'.)");
}

TEST_F(LspDiagnosticsTests, GetSyntacticDiagnostics3)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError3.sts"};
    std::vector<std::string> texts = {R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    auto result = lspApi->getSyntacticDiagnostics(filePaths[0].c_str());
    auto const forthIndex = 5;
    auto const expectedForthStartLine = 3;
    auto const expectedForthStartCharacter = 18;
    auto const expectedForthEndLine = 3;
    auto const expectedForthEndCharacter = 18;
    ASSERT_EQ(result.diagnostic[forthIndex].range_.start.line_, expectedForthStartLine);
    ASSERT_EQ(result.diagnostic[forthIndex].range_.start.character_, expectedForthStartCharacter);
    ASSERT_EQ(result.diagnostic[forthIndex].range_.end.line_, expectedForthEndLine);
    ASSERT_EQ(result.diagnostic[forthIndex].range_.end.character_, expectedForthEndCharacter);
    ASSERT_EQ(result.diagnostic[forthIndex].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[forthIndex].code_), 1);
    ASSERT_EQ(result.diagnostic[forthIndex].message_, R"(Unexpected token ','.)");
    ASSERT_EQ(result.diagnostic[forthIndex].codeDescription_.href_, "test code description");
    auto const fifthIndex = 8;
    auto const expectedFifththStartLine = 2;
    auto const expectedFifthStartCharacter = 27;
    auto const expectedFifthEndLine = 2;
    auto const expectedFifthEndCharacter = 33;
    ASSERT_EQ(result.diagnostic[fifthIndex].range_.start.line_, expectedFifththStartLine);
    ASSERT_EQ(result.diagnostic[fifthIndex].range_.start.character_, expectedFifthStartCharacter);
    ASSERT_EQ(result.diagnostic[fifthIndex].range_.end.line_, expectedFifthEndLine);
    ASSERT_EQ(result.diagnostic[fifthIndex].range_.end.character_, expectedFifthEndCharacter);
    ASSERT_EQ(result.diagnostic[fifthIndex].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[fifthIndex].code_), 1);
    ASSERT_EQ(result.diagnostic[fifthIndex].message_, R"(Label must be followed by a loop statement)");
    ASSERT_EQ(result.diagnostic[fifthIndex].codeDescription_.href_, "test code description");
}

TEST_F(LspDiagnosticsTests, GetSyntacticDiagnosticsForFile4)
{
    std::vector<std::string> files = {"GetSemanticDiagnosticsNoError4.sts"};
    std::vector<std::string> texts = {R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    auto result = lspApi->getSyntacticDiagnostics(filePaths[0].c_str());
    auto const sixthIndex = 9;
    auto const expectedSixthStartLine = 3;
    auto const expectedSixthStartCharacter = 18;
    auto const expectedSixthEndLine = 3;
    auto const expectedSixthEndCharacter = 18;
    ASSERT_EQ(result.diagnostic[sixthIndex].range_.start.line_, expectedSixthStartLine);
    ASSERT_EQ(result.diagnostic[sixthIndex].range_.start.character_, expectedSixthStartCharacter);
    ASSERT_EQ(result.diagnostic[sixthIndex].range_.end.line_, expectedSixthEndLine);
    ASSERT_EQ(result.diagnostic[sixthIndex].range_.end.character_, expectedSixthEndCharacter);
    ASSERT_EQ(result.diagnostic[sixthIndex].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[sixthIndex].code_), 1);
    ASSERT_EQ(result.diagnostic[sixthIndex].message_, R"(Unexpected token ')'.)");
    ASSERT_EQ(result.diagnostic[sixthIndex].codeDescription_.href_, "test code description");
    auto const sevenIndex = 12;
    auto const expectedSeventhStartLine = 3;
    auto const expectedSeventhStartCharacter = 5;
    auto const expectedSeventhEndLine = 3;
    auto const expectedSeventhEndCharacter = 18;
    ASSERT_EQ(result.diagnostic[sevenIndex].range_.start.line_, expectedSeventhStartLine);
    ASSERT_EQ(result.diagnostic[sevenIndex].range_.start.character_, expectedSeventhStartCharacter);
    ASSERT_EQ(result.diagnostic[sevenIndex].range_.end.line_, expectedSeventhEndLine);
    ASSERT_EQ(result.diagnostic[sevenIndex].range_.end.character_, expectedSeventhEndCharacter);
    ASSERT_EQ(result.diagnostic[sevenIndex].severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(result.diagnostic[sevenIndex].code_), 1);
    ASSERT_EQ(result.diagnostic[sevenIndex].message_, R"(return keyword should be used in function body)");
    ASSERT_EQ(result.diagnostic[sevenIndex].codeDescription_.href_, "test code description");
}
