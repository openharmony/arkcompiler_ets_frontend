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
#include "lsp/include/completions.h"
#include "lsp/include/internal_api.h"

class LSPCompletionsTests : public LSPAPITests {};

using ark::es2panda::lsp::CompletionEntry;
using ark::es2panda::lsp::CompletionEntryKind;
using ark::es2panda::lsp::Initializer;
using ark::es2panda::lsp::sort_text::CLASS_MEMBER_SNIPPETS;
using ark::es2panda::lsp::sort_text::GLOBALS_OR_KEYWORDS;
using ark::es2panda::lsp::sort_text::MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT;
using ark::es2panda::lsp::sort_text::SUGGESTED_CLASS_MEMBERS;

static void AssertCompletionsContainAndNotContainEntries(const std::vector<CompletionEntry> &entries,
                                                         const std::vector<CompletionEntry> &expectedEntries,
                                                         const std::vector<CompletionEntry> &unexpectedEntries)
{
    auto emptyCheck = expectedEntries.empty() && !entries.empty();
    ASSERT_FALSE(emptyCheck) << "Expected empty but the result is not. Actual account: " << entries.size();

    for (const auto &expectedEntry : expectedEntries) {
        bool found = false;
        for (const auto &entry : entries) {
            if (entry.GetName() == expectedEntry.GetName() &&
                entry.GetCompletionKind() == expectedEntry.GetCompletionKind()) {
                found = true;
                break;
            }
        }
        ASSERT_TRUE(found) << "Expected completion '" << expectedEntry.GetName() << "' not found";
    }

    for (const auto &unexpectedEntry : unexpectedEntries) {
        bool found = false;
        for (const auto &entry : entries) {
            if (entry.GetName() == unexpectedEntry.GetName() &&
                entry.GetCompletionKind() == unexpectedEntry.GetCompletionKind()) {
                found = true;
                break;
            }
        }
        ASSERT_FALSE(found) << "Unexpected completion '" << unexpectedEntry.GetName() << "' found";
    }
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition15)
{
    std::vector<std::string> files = {"getCompletionsAtPosition16.ets"};
    std::vector<std::string> texts = {R"delimiter(
export interface Method {
  get(value: number): this;
}
export interface CommonMethod {
  width(value: number): this;
  height(value: number): this;
}
export interface TextAttribute extends CommonMethod {
  font(value: number): this;
  fontColor(value: number): this;
}
export declare function Text(
  content?: string,
  value?: string
): TextAttribute
Text("Hello").font()._WILDCARD
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 385;  // after 'j._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("font", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("fontColor", ark::es2panda::lsp::CompletionEntryKind::METHOD,
                        std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("width", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("height", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition14)
{
    std::vector<std::string> files = {"getCompletionsAtPosition15.ets"};
    std::vector<std::string> texts = {R"delimiter(
export class MyClass0 {
  public property0: string = '0'
  public get0() {}
}
export class MyClass extends MyClass0 {
  public property: string = '1'
  public get() {}
}
export class MySonClass extends MyClass {
  public property2: string = '2'
}
let c = new MySonClass()
let p = c._WILDCARD
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 292;  // after 'j._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("property", ark::es2panda::lsp::CompletionEntryKind::PROPERTY,
                        std::string(SUGGESTED_CLASS_MEMBERS)),
        CompletionEntry("property", ark::es2panda::lsp::CompletionEntryKind::PROPERTY,
                        std::string(SUGGESTED_CLASS_MEMBERS)),
        CompletionEntry("property2", ark::es2panda::lsp::CompletionEntryKind::PROPERTY,
                        std::string(SUGGESTED_CLASS_MEMBERS)),
        CompletionEntry("get", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("get0", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition13)
{
    std::vector<std::string> files = {"getCompletionsAtPosition14.ets"};
    std::vector<std::string> texts = {R"delimiter(
export interface Method {
  get(value: number): this;
}
export interface CommonMethod {
  width(value: number): this;
  height(value: number): this;
}
export interface TextAttribute extends CommonMethod {
  font(value: number): this;
  fontColor(value: number): this;
}
export declare function Text(
  content?: string,
  value?: string
): TextAttribute
Text("Hello")._WILDCARD
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);

    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 378;  // after 'j._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("font", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("fontColor", ark::es2panda::lsp::CompletionEntryKind::METHOD,
                        std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("width", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS)),
        CompletionEntry("height", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition12)
{
    std::vector<std::string> files = {"getCompletionsAtPosition13.ets"};
    std::vector<std::string> texts = {R"delimiter(
class JSON {
  public static stringify(d: byte): String {
    return StringBuilder.toString(d)
  }
}
let j = new JSON()
let res = j._WILDCARD
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 142;  // after 'j._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {CompletionEntry(
        "stringify", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition11)
{
    std::vector<std::string> files = {"getCompletionsAtPosition12.ets"};
    std::vector<std::string> texts = {R"delimiter(
interface Inner { key : string; }
let i: Inner
i.k
let a = 1;)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 51;  // after 'i.k'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("key", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition10)
{
    std::vector<std::string> files = {"getCompletionsAtPosition11.ets"};
    std::vector<std::string> texts = {R"delimiter(
interface Inner { key : string; }
let i: Inner
i._WILDCARD
let a = 1;)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 59;  // after 'i._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("key", ark::es2panda::lsp::CompletionEntryKind::METHOD, std::string(CLASS_MEMBER_SNIPPETS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition7)
{
    std::vector<std::string> files = {"getCompletionsAtPosition10.ets"};
    std::vector<std::string> texts = {R"delimiter(
class MyClass {
  public myProp: number = 0;
  public prop: number = 0;
}
let obj = new MyClass();
let p = obj._WILDCARD
let a = 1;)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 121;  // after 'obj._WILDCARD' in 'let p = obj._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries =
        std::vector<CompletionEntry> {CompletionEntry("myProp", ark::es2panda::lsp::CompletionEntryKind::PROPERTY,
                                                      std::string(SUGGESTED_CLASS_MEMBERS)),
                                      CompletionEntry("prop", ark::es2panda::lsp::CompletionEntryKind::PROPERTY,
                                                      std::string(SUGGESTED_CLASS_MEMBERS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition8)
{
    std::vector<std::string> files = {"getCompletionsAtPosition11.ets"};
    std::vector<std::string> texts = {R"delimiter(
enum Color {
  Red = "red",
  Blue = "blue"
}
let myColor: Color = Color._WILDCARD)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 83;  // after 'Color._WILDCARD'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("Red", CompletionEntryKind::ENUM_MEMBER, std::string(MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT)),
        CompletionEntry("Blue", CompletionEntryKind::ENUM_MEMBER, std::string(MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, MemberCompletionsForClassTest9)
{
    std::vector<std::string> files = {"getCompletionsAtPosition12.ets"};
    std::vector<std::string> texts = {R"delimiter(
namespace space {
  export class classInSpace {
    public  c: number = 2;
  }
}
let numOfSpace: space._WILDCARD)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    const size_t offset = 113;
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto entries = res.GetEntries();
    std::string propertyName1 = "classInSpace";
    ASSERT_TRUE(entries.size() == 1);
    CompletionEntry entry1 =
        CompletionEntry(propertyName1, CompletionEntryKind::CLASS,
                        std::string(ark::es2panda::lsp::sort_text::MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT));
    initializer.DestroyContext(ctx);
    ASSERT_EQ(entry1, entries[0]);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition6)
{
    std::vector<std::string> files = {"getCompletionsAtPosition9.ets"};
    std::vector<std::string> texts = {R"delimiter(
let a: num
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 11;  // after 'n' in 'let a = n'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("number", ark::es2panda::lsp::CompletionEntryKind::KEYWORD, std::string(GLOBALS_OR_KEYWORDS))};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition5)
{
    std::vector<std::string> files = {"getCompletionsAtPosition8.ets"};
    std::vector<std::string> texts = {R"delimiter(
class
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 6;  // after 'ss' in 'class'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {};
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition0)
{
    std::vector<std::string> files = {"getCompletionsAtPosition7.ets"};
    std::vector<std::string> texts = {R"delimiter(
function num1() {
    return 1;
}

function num2() {
    return 2;
}

console.log(1);

let a = n
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 97;  // after 'n' in 'let a = n'
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("num1", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("num2", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
    initializer.DestroyContext(ctx);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition1)
{
    std::vector<std::string> files = {"getCompletionsAtPosition1.ets"};
    std::vector<std::string> texts = {R"delimiter(
function num1() {
    return 1;
}

function num2() {
    return 2;
}

let a = n
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 80;  // after 'n' in 'let a = n'
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("num1", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("num2", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    initializer.DestroyContext(ctx);
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition2)
{
    std::vector<std::string> files = {"getCompletionsAtPosition2.ets"};
    std::vector<std::string> texts = {R"delimiter(
let aaa = 123;
const abb = 333;

function axx() {
    return 444;
}

function foo() {
    let bbb = 222;
    let ccc = bbb + a
    return bbb + ccc;
}
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 127;  // after 'a' in 'let ccc = bbb + a'
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("aaa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("abb", ark::es2panda::lsp::CompletionEntryKind::CONSTANT, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("axx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    initializer.DestroyContext(ctx);
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, {});
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition3)
{
    std::vector<std::string> files = {"getCompletionsAtPosition3.ets"};
    std::vector<std::string> texts = {R"delimiter(
class Foo {
    bar: number = 1;
}

let foo = new Foo();
foo.bar = 2;
let baa = 3;
let bbb = 4;

function bxx() {
    return 5;
}

function fxx() {
    let bcc = 6;
    let axx = b
}
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 181;  // after 'b' in 'let axx = b'
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("baa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bbb", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bcc", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bxx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    auto unexpectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("bar", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
    };
    initializer.DestroyContext(ctx);
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, unexpectedEntries);
}

TEST_F(LSPCompletionsTests, getCompletionsAtPosition4)
{
    std::vector<std::string> files = {"getCompletionsAtPosition4.ets"};
    std::vector<std::string> texts = {R"delimiter(
class Foo {
    bar: number = 1;
}

let foo = new Foo();
foo.bar = 2;
let baa = 3;
let bbb = 4;

function bxx() {
    let bcc = 6;
    return 5;
}
let axx = b
)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 159;  // after 'b' in 'let axx = b'
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto expectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("baa", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bbb", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bxx", ark::es2panda::lsp::CompletionEntryKind::FUNCTION, std::string(GLOBALS_OR_KEYWORDS)),
    };
    auto unexpectedEntries = std::vector<CompletionEntry> {
        CompletionEntry("bar", ark::es2panda::lsp::CompletionEntryKind::PROPERTY, std::string(GLOBALS_OR_KEYWORDS)),
        CompletionEntry("bcc", ark::es2panda::lsp::CompletionEntryKind::VARIABLE, std::string(GLOBALS_OR_KEYWORDS)),
    };
    initializer.DestroyContext(ctx);
    AssertCompletionsContainAndNotContainEntries(res.GetEntries(), expectedEntries, unexpectedEntries);
}

TEST_F(LSPCompletionsTests, MemberCompletionsForClassTest1)
{
    std::vector<std::string> files = {"getCompletionsAtPosition5.ets"};
    std::vector<std::string> texts = {R"delimiter(
class MyClass1 {
  public myProp: number = 0;
  public prop: number = 1;
}
let obj1 = new MyClass1()
let prop = obj1.yp)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    const size_t offset = 120;
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto entries = res.GetEntries();
    ASSERT_TRUE(entries.size() == 1);

    std::string propertyName1 = "myProp";
    CompletionEntry entry1 = CompletionEntry(propertyName1, CompletionEntryKind::PROPERTY,
                                             std::string(ark::es2panda::lsp::sort_text::SUGGESTED_CLASS_MEMBERS));
    initializer.DestroyContext(ctx);
    ASSERT_EQ(entry1, entries[0]);
}

TEST_F(LSPCompletionsTests, MemberCompletionsForClassTest2)
{
    std::vector<std::string> files = {"getCompletionsAtPosition6.ets"};
    std::vector<std::string> texts = {R"delimiter(
namespace space {
  export class classInSpace {
    public  c: number = 2;
  }
}
let numOfSpace: space.classi)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    const size_t offset = 110;
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto entries = res.GetEntries();
    std::string propertyName1 = "classInSpace";
    ASSERT_TRUE(entries.size() == 1);
    CompletionEntry entry1 =
        CompletionEntry(propertyName1, CompletionEntryKind::CLASS,
                        std::string(ark::es2panda::lsp::sort_text::MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT));
    initializer.DestroyContext(ctx);
    ASSERT_EQ(entry1, entries[0]);
}

TEST_F(LSPCompletionsTests, MemberCompletionsForClassTest4)
{
    std::vector<std::string> files = {"getCompletionsAtPosition6.ets"};
    std::vector<std::string> texts = {R"delimiter(
enum Color {
  Red = "red",
  Blue = "blue"
}
let myColor: Color = Color.R)delimiter"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(filePaths[0].c_str(), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    const size_t offset = 75;
    auto res = lspApi->getCompletionsAtPosition(ctx, offset);
    auto entries = res.GetEntries();
    ASSERT_TRUE(entries.size() == 1);

    std::string propertyName1 = "Red";
    CompletionEntry entry1 =
        CompletionEntry(propertyName1, CompletionEntryKind::ENUM_MEMBER,
                        std::string(ark::es2panda::lsp::sort_text::MEMBER_DECLARED_BY_SPREAD_ASSIGNMENT));
    initializer.DestroyContext(ctx);
    ASSERT_EQ(entry1, entries[0]);
}
