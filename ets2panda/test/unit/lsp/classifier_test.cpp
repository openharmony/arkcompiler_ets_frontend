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

#include "lsp/include/classifier.h"
#include <cstddef>
#include <tuple>
#include "lsp_api_test.h"
#include "public/es2panda_lib.h"

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications1)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, R"(class A {};)", "class-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 6;
    size_t const length = 1;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "class name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications2)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, R"(enum Color {Red, Blue, Green};)",
                                                           "enum-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 5;
    size_t const length = 5;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "enum name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications3)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, R"(interface I {};)", "interface-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 10;
    size_t const length = 1;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "interface name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications4)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, R"(class Foo<T> {};)",
                                                           "type-parameter-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 10;
    size_t const length = 1;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "type parameter name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications5)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, R"(type tmp = Long|null;)",
                                                           "type-alias-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 5;
    size_t const length = 3;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "type alias name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications6)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, R"(function A(a:number) {};)",
                                                           "parameter-name.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 11;
    size_t const length = 1;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "parameter name";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications7)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, R"(let num = 1;)", "number-type.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 10;
    size_t const length = 1;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "number";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications8)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, R"(let str = "123";)", "string-type.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 10;
    size_t const length = 5;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    const size_t expectedCount = 1;
    const char *expectedName = "string";
    ASSERT_EQ(result.size(), expectedCount);
    ASSERT_EQ(result.at(0)->start, start);
    ASSERT_EQ(result.at(0)->length, length);
    ASSERT_EQ(*(result.at(0)->name), *expectedName);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications9)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, R"(let a = true;
let b = false;)",
                                                           "boolean-type.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 0;
    size_t const length = 28;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    // NOLINTBEGIN(readability-magic-numbers)
    std::vector<std::tuple<size_t, size_t, const char *>> expectedResult = {
        {0, 3, "keyword"},  {4, 1, "identifier"},  {6, 1, "punctuation"},  {8, 4, "boolean"},  {12, 1, "punctuation"},
        {14, 3, "keyword"}, {18, 1, "identifier"}, {20, 1, "punctuation"}, {22, 5, "boolean"}, {27, 1, "punctuation"}};
    // NOLINTEND(readability-magic-numbers)
    ASSERT_EQ(result.size(), expectedResult.size());

    for (size_t i = 0; i < result.size(); i++) {
        auto expectedStart = std::get<0>(expectedResult.at(i));
        auto expectedLength = std::get<1>(expectedResult.at(i));
        auto expectedName = *std::get<2>(expectedResult.at(i));
        ASSERT_EQ(result.at(i)->start, expectedStart);
        ASSERT_EQ(result.at(i)->length, expectedLength);
        ASSERT_EQ(*(result.at(i)->name), expectedName);
    }
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications10)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, R"(type tmp = null;)", "null-type.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    size_t const start = 0;
    size_t const length = 28;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    // NOLINTBEGIN(readability-magic-numbers)
    std::vector<std::tuple<size_t, size_t, const char *>> expectedResult = {
        {0, 4, "keyword"}, {5, 3, "type alias name"}, {9, 1, "punctuation"}, {11, 4, "null"}, {15, 1, "punctuation"}};
    // NOLINTEND(readability-magic-numbers)
    ASSERT_EQ(result.size(), expectedResult.size());

    for (size_t i = 0; i < result.size(); i++) {
        auto expectedStart = std::get<0>(expectedResult.at(i));
        auto expectedLength = std::get<1>(expectedResult.at(i));
        auto expectedName = *std::get<2>(expectedResult.at(i));
        ASSERT_EQ(result.at(i)->start, expectedStart);
        ASSERT_EQ(result.at(i)->length, expectedLength);
        ASSERT_EQ(*(result.at(i)->name), expectedName);
    }
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications11)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(
        impl_, cfg_,
        "let a = 1;\nlet b = 2;\nclass C {foo(){}};\nlet c = new C();\na + b;\na & b;\na += b;\na |= b;\na &= b;\na < "
        "b;\nc?.foo;\na - b;\na | b;\na -= b;\na ^= b;\na && b;\na > b;\n!a;\na * b;\na ^ b;\na *= b;\na <<= b;\na || "
        "b;\n",
        "punctuator-type1.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);
    size_t const start = 0;
    size_t const length = 428;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    // NOLINTBEGIN(readability-magic-numbers)
    std::vector<std::tuple<size_t, size_t, const char *>> expectedResult = {
        {0, 3, "keyword"},       {4, 1, "identifier"},    {6, 1, "punctuation"},   {8, 1, "number"},
        {9, 1, "punctuation"},   {11, 3, "keyword"},      {15, 1, "identifier"},   {17, 1, "punctuation"},
        {19, 1, "number"},       {20, 1, "punctuation"},  {22, 5, "keyword"},      {28, 1, "class name"},
        {30, 1, "punctuation"},  {31, 3, "identifier"},   {34, 1, "punctuation"},  {35, 1, "punctuation"},
        {36, 1, "punctuation"},  {37, 1, "punctuation"},  {38, 1, "punctuation"},  {39, 1, "punctuation"},
        {41, 3, "keyword"},      {45, 1, "identifier"},   {47, 1, "punctuation"},  {49, 3, "keyword"},
        {53, 1, "identifier"},   {54, 1, "punctuation"},  {55, 1, "punctuation"},  {56, 1, "punctuation"},
        {58, 1, "identifier"},   {60, 1, "punctuation"},  {62, 1, "identifier"},   {63, 1, "punctuation"},
        {65, 1, "identifier"},   {67, 1, "punctuation"},  {69, 1, "identifier"},   {70, 1, "punctuation"},
        {72, 1, "identifier"},   {74, 2, "punctuation"},  {77, 1, "identifier"},   {78, 1, "punctuation"},
        {80, 1, "identifier"},   {82, 2, "punctuation"},  {85, 1, "identifier"},   {86, 1, "punctuation"},
        {88, 1, "identifier"},   {90, 2, "punctuation"},  {93, 1, "identifier"},   {94, 1, "punctuation"},
        {96, 1, "identifier"},   {98, 1, "punctuation"},  {100, 1, "identifier"},  {101, 1, "punctuation"},
        {103, 1, "identifier"},  {104, 2, "punctuation"}, {106, 3, "identifier"},  {109, 1, "punctuation"},
        {111, 1, "identifier"},  {113, 1, "punctuation"}, {115, 1, "identifier"},  {116, 1, "punctuation"},
        {118, 1, "identifier"},  {120, 1, "punctuation"}, {122, 1, "identifier"},  {123, 1, "punctuation"},
        {125, 1, "identifier"},  {127, 2, "punctuation"}, {130, 1, "identifier"},  {131, 1, "punctuation"},
        {133, 1, "identifier"},  {135, 2, "punctuation"}, {138, 1, "identifier"},  {139, 1, "punctuation"},
        {141, 1, "identifier"},  {143, 2, "punctuation"}, {146, 1, "identifier"},  {147, 1, "punctuation"},
        {149, 1, "identifier"},  {151, 1, "punctuation"}, {153, 1, "identifier"},  {154, 1, "punctuation"},
        {156, 1, "punctuation"}, {157, 1, "identifier"},  {158, 1, "punctuation"}, {160, 1, "identifier"},
        {162, 1, "punctuation"}, {164, 1, "identifier"},  {165, 1, "punctuation"}, {167, 1, "identifier"},
        {169, 1, "punctuation"}, {171, 1, "identifier"},  {172, 1, "punctuation"}, {174, 1, "identifier"},
        {176, 2, "punctuation"}, {179, 1, "identifier"},  {180, 1, "punctuation"}, {182, 1, "identifier"},
        {184, 3, "punctuation"}, {188, 1, "identifier"},  {189, 1, "punctuation"}, {191, 1, "identifier"},
        {193, 2, "punctuation"}, {196, 1, "identifier"},  {197, 1, "punctuation"}};
    // NOLINTEND(readability-magic-numbers)
    ASSERT_EQ(result.size(), expectedResult.size());
    for (size_t i = 0; i < result.size(); i++) {
        auto expectedStart = std::get<0>(expectedResult.at(i));
        auto expectedLength = std::get<1>(expectedResult.at(i));
        auto expectedName = *std::get<2>(expectedResult.at(i));
        ASSERT_EQ(result.at(i)->start, expectedStart);
        ASSERT_EQ(result.at(i)->length, expectedLength);
        ASSERT_EQ(*(result.at(i)->name), expectedName);
    }
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetEncodeedSyntacticClassifications12)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(
        impl_, cfg_,
        "a === b;\na <= b;\na / b;\na >> b;\na /= b;\na >>= b;\na++;\na == b;\na >= b;\na % b;\na << b;\na %= "
        "b;\na >>>= b;\na--;\na = b;\nlet var1: [...number[]];\n(a);\nlet d:[];\n{a};\nc??b;\na != b;\na !== b;\n",
        "punctuator-type2.sts", ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);
    size_t const start = 0;
    size_t const length = 428;
    auto result = ark::es2panda::lsp::GetEncodedSyntacticClassifications(ctx, start, length);
    // NOLINTBEGIN(readability-magic-numbers)
    std::vector<std::tuple<size_t, size_t, const char *>> expectedResult = {
        {0, 1, "identifier"},    {2, 3, "punctuation"},   {6, 1, "identifier"},    {7, 1, "punctuation"},
        {9, 1, "identifier"},    {11, 2, "punctuation"},  {14, 1, "identifier"},   {15, 1, "punctuation"},
        {17, 1, "identifier"},   {19, 1, "punctuation"},  {21, 1, "identifier"},   {22, 1, "punctuation"},
        {24, 1, "identifier"},   {26, 2, "punctuation"},  {29, 1, "identifier"},   {30, 1, "punctuation"},
        {32, 1, "identifier"},   {34, 2, "punctuation"},  {37, 1, "identifier"},   {38, 1, "punctuation"},
        {40, 1, "identifier"},   {42, 3, "punctuation"},  {46, 1, "identifier"},   {47, 1, "punctuation"},
        {49, 1, "identifier"},   {50, 2, "punctuation"},  {52, 1, "punctuation"},  {54, 1, "identifier"},
        {56, 2, "punctuation"},  {59, 1, "identifier"},   {60, 1, "punctuation"},  {62, 1, "identifier"},
        {64, 2, "punctuation"},  {67, 1, "identifier"},   {68, 1, "punctuation"},  {70, 1, "identifier"},
        {72, 1, "punctuation"},  {74, 1, "identifier"},   {75, 1, "punctuation"},  {77, 1, "identifier"},
        {79, 2, "punctuation"},  {82, 1, "identifier"},   {83, 1, "punctuation"},  {85, 1, "identifier"},
        {87, 2, "punctuation"},  {90, 1, "identifier"},   {91, 1, "punctuation"},  {93, 1, "identifier"},
        {95, 4, "punctuation"},  {100, 1, "identifier"},  {101, 1, "punctuation"}, {103, 1, "identifier"},
        {104, 2, "punctuation"}, {106, 1, "punctuation"}, {108, 1, "identifier"},  {110, 1, "punctuation"},
        {112, 1, "identifier"},  {113, 1, "punctuation"}, {115, 3, "keyword"},     {119, 4, "identifier"},
        {123, 1, "punctuation"}, {125, 1, "punctuation"}, {126, 3, "punctuation"}, {129, 6, "identifier"},
        {135, 1, "punctuation"}, {136, 1, "punctuation"}, {137, 1, "punctuation"}, {138, 1, "punctuation"},
        {140, 1, "punctuation"}, {141, 1, "identifier"},  {142, 1, "punctuation"}, {143, 1, "punctuation"},
        {145, 3, "keyword"},     {149, 1, "identifier"},  {150, 1, "punctuation"}, {151, 1, "punctuation"},
        {152, 1, "punctuation"}, {153, 1, "punctuation"}, {155, 1, "punctuation"}, {156, 1, "identifier"},
        {157, 1, "punctuation"}, {158, 1, "punctuation"}, {160, 1, "identifier"},  {161, 2, "punctuation"},
        {163, 1, "identifier"},  {164, 1, "punctuation"}, {166, 1, "identifier"},  {168, 2, "punctuation"},
        {171, 1, "identifier"},  {172, 1, "punctuation"}, {174, 1, "identifier"},  {176, 3, "punctuation"},
        {180, 1, "identifier"},  {181, 1, "punctuation"}};
    // NOLINTEND(readability-magic-numbers)
    ASSERT_EQ(result.size(), expectedResult.size());
    for (size_t i = 0; i < result.size(); i++) {
        auto expectedStart = std::get<0>(expectedResult.at(i));
        auto expectedLength = std::get<1>(expectedResult.at(i));
        auto expectedName = *std::get<2>(expectedResult.at(i));
        ASSERT_EQ(result.at(i)->start, expectedStart);
        ASSERT_EQ(result.at(i)->length, expectedLength);
        ASSERT_EQ(*(result.at(i)->name), expectedName);
    }
    impl_->DestroyContext(ctx);
}
