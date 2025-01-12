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

#include "ir/astNode.h"
#include "ir/expressions/callExpression.h"
#include "lsp/include/api.h"
#include "lsp/include/internal_api.h"
#include <gtest/gtest.h>
#include <cstddef>
#include <vector>

#include "public/es2panda_lib.h"
#include "public/public.h"
#include "test/utils/ast_verifier_test.h"

class LSPAPITests : public test::utils::AstVerifierTest {
public:
    std::vector<std::string> CreateTempFile(std::vector<std::string> files, std::vector<std::string> texts)
    {
        std::vector<std::string> result = {};
        auto tempDir = testing::TempDir();
        for (size_t i = 0; i < files.size(); i++) {
            auto outPath = tempDir + files[i];
            std::ofstream outStream(outPath);
            if (outStream.fail()) {
                std::cerr << "Failed to open file: " << outPath << std::endl;
                return result;
            }
            outStream << texts[i];
            outStream.close();
            result.push_back(outPath);
        }
        return result;
    }
};

TEST_F(LSPAPITests, GetTouchingToken1)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "not-found-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 50;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    ASSERT_EQ(result, nullptr);

    auto result1 = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    ASSERT_EQ(result1, nullptr);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken2)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "nested-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(impl_, ctx);
    auto expectedNode = ast->FindChild(
        [](ark::es2panda::ir::AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "A"; });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken3)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "first-node.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(impl_, ctx);
    auto expectedNode = ast->FindChild([](ark::es2panda::ir::AstNode *node) { return node->IsExpressionStatement(); });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetDefinitionAtPosition)
{
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function main() {}", "file1.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);
    LSPAPI const *lspApi = GetImpl();
    size_t const offset = 5;
    DefinitionInfo *result = lspApi->getDefinitionAtPosition("file1.sts", offset);
    ASSERT_EQ(result, nullptr);
    impl_->DestroyContext(ctx);
}

Range CreateTestRange()
{
    int const endPos = 10;
    Position start(1, 0);
    Position end(1, endPos);
    return Range(start, end);
}

class DiagnosticTest : public ::testing::Test {
public:
    void SetUp() override
    {
        range_ = CreateTestRange();
        message_ = "Test message";
    }

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    Range range_;
    std::string message_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

TEST_F(DiagnosticTest, ConstructorAndField)
{
    int const errorCode = 404;
    int const defaultCharacter = 10;
    Diagnostic diagnostic(range_, DiagnosticSeverity::Error, errorCode, message_);

    EXPECT_EQ(diagnostic.range_.start.line_, 1);
    EXPECT_EQ(diagnostic.range_.end.character_, defaultCharacter);
    EXPECT_EQ(diagnostic.message_, message_);
    EXPECT_EQ(diagnostic.severity_, DiagnosticSeverity::Error);
    EXPECT_EQ(std::get<int>(diagnostic.code_), errorCode);
}

TEST_F(DiagnosticTest, CodeDescriptionOptional)
{
    CodeDescription codeDesc;
    codeDesc.href_ = "http://example.com/error/404";
    int const errorCode = 404;

    Diagnostic diagnostic(range_, DiagnosticSeverity::Error, errorCode, message_, codeDesc);

    const auto &codeDescription = diagnostic.codeDescription_;
    EXPECT_EQ(codeDescription.href_, "http://example.com/error/404");
}

TEST_F(DiagnosticTest, TagsAndRelatedInformation)
{
    std::vector<DiagnosticTag> tags = {DiagnosticTag::Unnecessary};
    std::vector<DiagnosticRelatedInformation> relatedInfoList;
    DiagnosticRelatedInformation relatedInfo;
    relatedInfo.location_ = Location {"www.test.uri", range_};
    relatedInfo.message_ = "Related information message";
    relatedInfoList.push_back(relatedInfo);
    int const errorCode = 200;

    Diagnostic diagnostic(range_, DiagnosticSeverity::Information, errorCode, message_, {}, "default", tags,
                          relatedInfoList);

    const auto &diagnosticTags = diagnostic.tags_;
    EXPECT_EQ(diagnosticTags.size(), 1);
    EXPECT_EQ(diagnosticTags[0], DiagnosticTag::Unnecessary);

    const auto &relatedInformation = diagnostic.relatedInformation_;
    EXPECT_EQ(relatedInformation.size(), 1);
    EXPECT_EQ(relatedInformation[0].message_, "Related information message");
}

TEST_F(DiagnosticTest, DataField)
{
    int const dataValue = 42;
    std::variant<int, std::string> data = dataValue;
    int const errorCode = 400;
    int const dataResult = 42;

    Diagnostic diagnostic(range_, DiagnosticSeverity::Error, errorCode, message_, {}, {}, {}, {}, data);

    const auto &diagnosticData = diagnostic.data_;
    EXPECT_EQ(std::get<int>(diagnosticData), dataResult);
}

TEST_F(LSPAPITests, GetFileReferencesImpl1)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"export1.sts", "ref-file.sts"};
    std::vector<std::string> texts = {
        R"(export function A(a:number, b:number): number {
  return a + b;
}
export function B(a:number, b:number): number {
  return a + b;
})",
        R"(import {A} from "./export1";
import {B} from "./export1.sts";
A(1, 2);
B(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *searchFileName = filePaths[0].c_str();
    char const *referenceFileName = filePaths[1].c_str();
    auto ctx = impl_->CreateContextFromFile(cfg_, searchFileName);
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto isPackageModule = reinterpret_cast<Context *>(ctx)->parserProgram->IsPackage();
    ASSERT_FALSE(isPackageModule);
    impl_->DestroyContext(ctx);

    auto ctx1 = impl_->CreateContextFromFile(cfg_, referenceFileName);
    impl_->ProceedToState(ctx1, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx1), ES2PANDA_STATE_CHECKED);

    auto result = reinterpret_cast<Context *>(ctx1)->allocator->New<FileReferences>();
    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx1, searchFileName, isPackageModule, result);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 11;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 45;
    size_t const expectedLength2 = 15;
    ASSERT_EQ(std::string(result->referenceInfos[0]->fileName), expectedFileName1);
    ASSERT_EQ(result->referenceInfos[0]->start, expectedStartPos1);
    ASSERT_EQ(result->referenceInfos[0]->length, expectedLength1);
    ASSERT_EQ(std::string(result->referenceInfos[1]->fileName), expectedFileName2);
    ASSERT_EQ(result->referenceInfos[1]->start, expectedStartPos2);
    ASSERT_EQ(result->referenceInfos[1]->length, expectedLength2);
    impl_->DestroyContext(ctx1);
}

TEST_F(LSPAPITests, GetFileReferencesImpl2)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"export2.ts", "ref-file.sts"};
    std::vector<std::string> texts = {
        R"(export function A(a:number, b:number): number {
  return a + b;
}
export function B(a:number, b:number): number {
  return a + b;
})",
        R"(import {A} from "./export2";
import {B} from "./export2.ts";
A(1, 2);
B(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *searchFileName = filePaths[0].c_str();
    char const *referenceFileName = filePaths[1].c_str();
    auto ctx = impl_->CreateContextFromFile(cfg_, searchFileName);
    impl_->ProceedToState(ctx, ES2PANDA_STATE_PARSED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_PARSED);

    auto isPackageModule = reinterpret_cast<Context *>(ctx)->parserProgram->IsPackage();
    ASSERT_FALSE(isPackageModule);
    impl_->DestroyContext(ctx);

    auto ctx1 = impl_->CreateContextFromFile(cfg_, referenceFileName);
    impl_->ProceedToState(ctx1, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx1), ES2PANDA_STATE_CHECKED);

    auto result = reinterpret_cast<Context *>(ctx1)->allocator->New<FileReferences>();
    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx1, searchFileName, isPackageModule, result);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 11;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 45;
    size_t const expectedLength2 = 14;
    ASSERT_EQ(std::string(result->referenceInfos[0]->fileName), expectedFileName1);
    ASSERT_EQ(result->referenceInfos[0]->start, expectedStartPos1);
    ASSERT_EQ(result->referenceInfos[0]->length, expectedLength1);
    ASSERT_EQ(std::string(result->referenceInfos[1]->fileName), expectedFileName2);
    ASSERT_EQ(result->referenceInfos[1]->start, expectedStartPos2);
    ASSERT_EQ(result->referenceInfos[1]->length, expectedLength2);
    impl_->DestroyContext(ctx1);
}

TEST_F(LSPAPITests, GetFileReferencesImpl3)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"package-module.sts"};
    std::vector<std::string> texts = {R"(import { PI } from "std/math";
console.log(PI);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *referenceFileName = filePaths[0].c_str();
    auto ctx = impl_->CreateContextFromFile(cfg_, referenceFileName);
    impl_->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto baseUrl = reinterpret_cast<Context *>(ctx)->config->options->ArkTSConfig()->BaseUrl();
    auto searchFileName = baseUrl + "/plugins/ets/stdlib/std/math/math.sts";
    auto result = reinterpret_cast<Context *>(ctx)->allocator->New<FileReferences>();
    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx, searchFileName.c_str(), true, result);
    auto expectedFileName = filePaths[0];
    size_t const expectedStartPos = 19;
    size_t const expectedLength = 10;

    ASSERT_EQ(result->referenceInfos[0]->fileName, expectedFileName);
    ASSERT_EQ(result->referenceInfos[0]->start, expectedStartPos);
    ASSERT_EQ(result->referenceInfos[0]->length, expectedLength);
    impl_->DestroyContext(ctx);
}
