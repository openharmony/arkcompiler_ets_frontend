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
#include "lsp/include/internal_api.h"

namespace {

using ark::es2panda::lsp::Initializer;

class LSPClassInfoTests : public LSPAPITests {};

void AssertClassConstructorInfo(const std::vector<FileTextChanges> &fileTextChanges,
                                const std::vector<FileTextChanges> &expectedFileTextChanges)
{
    auto emptyCheck = fileTextChanges.empty();
    ASSERT_FALSE(emptyCheck) << "The result is empty.";

    auto curFileChanges = fileTextChanges.at(0);
    auto expectedFileChanges = expectedFileTextChanges.at(0);
    bool check = false;
    if (curFileChanges.fileName != expectedFileChanges.fileName) {
        check = true;
    }
    ASSERT_FALSE(check) << "The fileName is not expected.";

    auto textChangeEmptyCheck = curFileChanges.textChanges.empty();
    ASSERT_FALSE(textChangeEmptyCheck) << "The modified file content is empty.";

    auto curTextChange = curFileChanges.textChanges.at(0);
    auto expectedTextChange = expectedFileChanges.textChanges.at(0);
    if (curTextChange.span.start != expectedTextChange.span.start) {
        check = true;
    }
    ASSERT_FALSE(check) << "The insertPosition is not expected.";
    if (curTextChange.newText != expectedTextChange.newText) {
        check = true;
    }
    ASSERT_FALSE(check) << "The newText is not expected.";
}

TEST_F(LSPClassInfoTests, getClassConstructorInfo1)
{
    std::vector<std::string> fileNames = {"getClassConstructorInfo1.ets"};
    std::vector<std::string> fileContents = {
        R"(
class FooParent {
    f: number = 0;
    str: string = "aaa";
    constructor (f: number, str: string) {
        this.f = f;
        this.str = str;
    }
};

enum Colors {Red = "#FF0000", Green = "#00FF00", Blue = "#0000FF"};
export class Foo extends FooParent {
    name: string = "unassigned";
    isActive: boolean = true;
    items: string[] = ["aaa", "bbb"];
    point: [number, number] = [0, 0];
    primaryColor: Colors = Colors.Blue;
    optionalValue?:string|null|undefined;
    x: number = 1;
    static y: number = 2;
    z: number = 3;
};)"};
    auto filePaths = CreateTempFile(fileNames, fileContents);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 400;
    std::vector<std::string> properties = {"name", "x", "z"};
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getClassConstructorInfo(ctx, offset, properties);
    std::vector<FileTextChanges> expectedFileTextChanges;
    std::string text =
        "constructor(f: number, str: string, name: string, x: number, z: number) {\n  super(f, str);\n  this.name = "
        "name;\n  this.x = x;\n  this.z = z;\n}";
    size_t const insertPosition = 269;
    TextSpan span(insertPosition, text.size());
    std::vector<TextChange> textChanges;
    textChanges.emplace_back(TextChange(span, text));
    FileTextChanges textChange(filePaths.at(0), textChanges);
    expectedFileTextChanges.push_back(textChange);
    AssertClassConstructorInfo(res.GetFileTextChanges(), expectedFileTextChanges);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPClassInfoTests, getClassConstructorInfo2)
{
    std::vector<std::string> files = {"getClassConstructorInfo2.ets"};
    std::vector<std::string> texts = {
        R"(
class Foo {
    f: number = 0;
    str: string = "aaa";
};)"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 30;
    std::vector<std::string> properties = {"f", "str"};
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getClassConstructorInfo(ctx, offset, properties);
    std::vector<FileTextChanges> expectedFileTextChanges;
    std::string text = "constructor(f: number, str: string) {\n  this.f = f;\n  this.str = str;\n}";
    size_t const insertPosition = 17;
    TextSpan span(insertPosition, text.size());
    std::vector<TextChange> textChanges;
    textChanges.emplace_back(TextChange(span, text));
    FileTextChanges textChange(filePaths.at(0), textChanges);
    expectedFileTextChanges.push_back(textChange);
    AssertClassConstructorInfo(res.GetFileTextChanges(), expectedFileTextChanges);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPClassInfoTests, getClassConstructorInfo3)
{
    std::vector<std::string> files = {"getClassConstructorInfo3.ets"};
    std::vector<std::string> texts = {
        R"(
class Foo {
};)"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 10;
    std::vector<std::string> properties = {};
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getClassConstructorInfo(ctx, offset, properties);
    std::vector<FileTextChanges> expectedFileTextChanges;
    std::string text = "constructor() {\n}";
    size_t const insertPosition = 13;
    TextSpan span(insertPosition, text.size());
    std::vector<TextChange> textChanges;
    textChanges.emplace_back(TextChange(span, text));
    FileTextChanges textChange(filePaths.at(0), textChanges);
    expectedFileTextChanges.push_back(textChange);
    AssertClassConstructorInfo(res.GetFileTextChanges(), expectedFileTextChanges);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPClassInfoTests, getClassConstructorInfo4)
{
    std::vector<std::string> files = {"getClassConstructorInfo4.ets"};
    std::vector<std::string> texts = {
        R"(
namespace space {
    export class classInSpace {
        c: number = 2;

        function print() {
            return 2;
        }
    }
})"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 35;
    std::vector<std::string> properties = {"c"};
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getClassConstructorInfo(ctx, offset, properties);
    std::vector<FileTextChanges> expectedFileTextChanges;
    std::string text = "constructor(c: number) {\n  this.c = c;\n}";
    size_t const insertPosition = 59;
    TextSpan span(insertPosition, text.size());
    std::vector<TextChange> textChanges;
    textChanges.emplace_back(TextChange(span, text));
    FileTextChanges textChange(filePaths.at(0), textChanges);
    expectedFileTextChanges.push_back(textChange);
    AssertClassConstructorInfo(res.GetFileTextChanges(), expectedFileTextChanges);
    initializer.DestroyContext(ctx);
}

}  // namespace