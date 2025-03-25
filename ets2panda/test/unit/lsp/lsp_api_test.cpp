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

TEST_F(LSPAPITests, GetTouchingToken1)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("not-found-node.ets", ES2PANDA_STATE_CHECKED,
                                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 50;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    ASSERT_EQ(result, nullptr);

    auto result1 = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    ASSERT_EQ(result1, nullptr);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken2)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("nested-node.ets", ES2PANDA_STATE_CHECKED,
                                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, false);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    auto expectedNode = ast->FindChild(
        [](ark::es2panda::ir::AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "A"; });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTouchingToken3)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("first-node.ets", ES2PANDA_STATE_CHECKED,
                                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);
    size_t const offset = 51;
    auto result = ark::es2panda::lsp::GetTouchingToken(ctx, offset, true);
    auto ast = GetAstFromContext<ark::es2panda::ir::AstNode>(ctx);
    auto expectedNode = ast->FindChild([](ark::es2panda::ir::AstNode *node) { return node->IsExpressionStatement(); });
    ASSERT_EQ(result->DumpJSON(), expectedNode->DumpJSON());
    ASSERT_EQ(result->Start().index, expectedNode->Start().index);
    ASSERT_EQ(result->End().index, expectedNode->End().index);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, DiagnosticConstructorAndField)
{
    int const errorCode = 404;
    int const defaultCharacter = 10;
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};
    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_);

    EXPECT_EQ(diagnostic.range_.start.line_, 1);
    EXPECT_EQ(diagnostic.range_.end.character_, defaultCharacter);
    EXPECT_EQ(diagnostic.message_, message_);
    EXPECT_EQ(diagnostic.severity_, DiagnosticSeverity::Error);
    EXPECT_EQ(std::get<int>(diagnostic.code_), errorCode);
}

TEST_F(LSPAPITests, DiagnosticCodeDescriptionOptional)
{
    CodeDescription codeDesc;
    codeDesc.href_ = "http://example.com/error/404";
    int const errorCode = 404;
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_, codeDesc);

    const auto &codeDescription = diagnostic.codeDescription_;
    EXPECT_EQ(codeDescription.href_, "http://example.com/error/404");
}

TEST_F(LSPAPITests, DiagnosticTagsAndRelatedInformation)
{
    std::vector<DiagnosticTag> tags {};
    tags.push_back(DiagnosticTag::Unnecessary);
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};
    DiagnosticRelatedInformation relatedInfo;
    relatedInfo.location_ = Location {"www.test.uri", range_};
    relatedInfo.message_ = "Related information message";
    relatedInfoList.push_back(relatedInfo);
    int const errorCode = 200;
    CodeDescription des = {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Information, errorCode, message_, des,
                          "default");

    const auto &diagnosticTags = diagnostic.tags_;
    EXPECT_EQ(diagnosticTags.size(), 1);
    EXPECT_EQ(diagnosticTags[0], DiagnosticTag::Unnecessary);

    const auto &relatedInformation = diagnostic.relatedInformation_;
    EXPECT_EQ(relatedInformation.size(), 1);
    EXPECT_EQ(relatedInformation[0].message_, "Related information message");
}

TEST_F(LSPAPITests, DiagnosticDataField)
{
    int const dataValue = 42;
    std::variant<int, std::string> data = dataValue;
    int const errorCode = 400;
    int const dataResult = 42;
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_, {}, {}, data);

    const auto &diagnosticData = diagnostic.data_;
    EXPECT_EQ(std::get<int>(diagnosticData), dataResult);
}

TEST_F(LSPAPITests, CreateDiagnosticForNode1)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "function main() {}");
    auto astNode = GetAstFromContext<es2panda_AstNode>(ctx);
    int const dataValue = 42;
    std::variant<int, std::string> data = dataValue;
    int const errorCode = 400;
    std::string message = "Diagnostic";
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message, {}, {}, data);
    FileDiagnostic result = ark::es2panda::lsp::CreateDiagnosticForNode(astNode, diagnostic);

    int const startLine = 0;
    int const endLine = 0;
    int const startChar = 0;
    int const endChar = 18;
    ASSERT_EQ(result.diagnostic.message_, "Diagnostic");
    ASSERT_EQ(result.diagnostic.range_.start.line_, startLine);
    ASSERT_EQ(result.diagnostic.range_.end.line_, endLine);
    ASSERT_EQ(result.diagnostic.range_.start.character_, startChar);
    ASSERT_EQ(result.diagnostic.range_.end.character_, endChar);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, CreateDiagnosticForNode2)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "function main() {}");
    auto astNode = GetAstFromContext<es2panda_AstNode>(ctx);
    int const dataValue = 42;
    std::variant<int, std::string> data = dataValue;
    int const errorCode = 400;
    std::string message = "Diagnostic {0}, for the {1}, and {2}";
    std::vector<std::string> args = {"Error1", "Error2", "Error3"};
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message, {}, {}, data);
    FileDiagnostic result = ark::es2panda::lsp::CreateDiagnosticForNode(astNode, diagnostic, args);

    int const startLine = 0;
    int const endLine = 0;
    int const startChar = 0;
    int const endChar = 18;
    ASSERT_EQ(result.diagnostic.message_, "Diagnostic Error1, for the Error2, and Error3");
    ASSERT_EQ(result.diagnostic.range_.start.line_, startLine);
    ASSERT_EQ(result.diagnostic.range_.end.line_, endLine);
    ASSERT_EQ(result.diagnostic.range_.start.character_, startChar);
    ASSERT_EQ(result.diagnostic.range_.end.character_, endChar);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, CreateDiagnosticForNode3)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    Initializer initializer = Initializer();
    es2panda_Context *ctx =
        initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "let a =     () => {\n  return 1;\n}");
    auto astNode = reinterpret_cast<AstNode *>(GetAstFromContext<ark::es2panda::ir::AstNode>(ctx));
    astNode = astNode->FindChild([](ark::es2panda::ir::AstNode *child) { return child->IsArrowFunctionExpression(); });
    int const dataValue = 42;
    std::variant<int, std::string> data = dataValue;
    int const errorCode = 400;
    std::string message = "Diagnostic {0}, for the {1}, and {2}";
    std::vector<std::string> args = {"Error1", "Error2", "Error3"};
    std::vector<DiagnosticTag> tags {};
    std::vector<DiagnosticRelatedInformation> relatedInfoList {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message, {}, {}, data);
    FileDiagnostic result =
        ark::es2panda::lsp::CreateDiagnosticForNode(reinterpret_cast<es2panda_AstNode *>(astNode), diagnostic, args);

    int const startLine = 0;
    int const endLine = 2;
    int const startChar = 12;
    int const endChar = 33;
    ASSERT_EQ(result.diagnostic.message_, "Diagnostic Error1, for the Error2, and Error3");
    ASSERT_EQ(result.diagnostic.range_.start.line_, startLine);
    ASSERT_EQ(result.diagnostic.range_.end.line_, endLine);
    ASSERT_EQ(result.diagnostic.range_.start.character_, startChar);
    ASSERT_EQ(result.diagnostic.range_.end.character_, endChar);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetFileReferencesImpl1)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"lsp_api_test_export_1.ets", "lsp_api_test_file_1.ets"};
    std::vector<std::string> texts = {
        R"(export function A(a:number, b:number): number {
  return a + b;
}
export function B(a:number, b:number): number {
  return a + b;
})",
        R"(import {A} from "./lsp_api_test_export_1";
import {B} from "./lsp_api_test_export_1.ets";
A(1, 2);
B(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *searchFileName = filePaths[0].c_str();
    char const *referenceFileName = filePaths[1].c_str();
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(searchFileName, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto isPackageModule = reinterpret_cast<Context *>(ctx)->parserProgram->IsPackage();
    ASSERT_FALSE(isPackageModule);
    initializer.DestroyContext(ctx);

    auto ctx1 = initializer.CreateContext(referenceFileName, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx1), ES2PANDA_STATE_CHECKED);

    auto result = References();
    result = ark::es2panda::lsp::GetFileReferencesImpl(ctx1, searchFileName, isPackageModule);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 25;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 59;
    size_t const expectedLength2 = 29;
    ASSERT_EQ(result.referenceInfos.at(0).fileName, expectedFileName1);
    ASSERT_EQ(result.referenceInfos.at(0).start, expectedStartPos1);
    ASSERT_EQ(result.referenceInfos.at(0).length, expectedLength1);
    ASSERT_EQ(result.referenceInfos.at(1).fileName, expectedFileName2);
    ASSERT_EQ(result.referenceInfos.at(1).start, expectedStartPos2);
    ASSERT_EQ(result.referenceInfos.at(1).length, expectedLength2);
    initializer.DestroyContext(ctx1);
}

TEST_F(LSPAPITests, GetFileReferencesImpl2)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"lsp_api_test_export_2.ts", "lsp_api_test_file_2.ets"};
    std::vector<std::string> texts = {
        R"(export function A(a:number, b:number): number {
  return a + b;
}
export function B(a:number, b:number): number {
  return a + b;
})",
        R"(import {A} from "./lsp_api_test_export_2";
import {B} from "./lsp_api_test_export_2.ts";
A(1, 2);
B(1, 2);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 2;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *searchFileName = filePaths[0].c_str();
    char const *referenceFileName = filePaths[1].c_str();
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(searchFileName, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto isPackageModule = reinterpret_cast<Context *>(ctx)->parserProgram->IsPackage();
    ASSERT_FALSE(isPackageModule);
    initializer.DestroyContext(ctx);

    auto ctx1 = initializer.CreateContext(referenceFileName, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx1), ES2PANDA_STATE_CHECKED);

    auto result = References();
    result = ark::es2panda::lsp::GetFileReferencesImpl(ctx1, searchFileName, isPackageModule);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 25;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 59;
    size_t const expectedLength2 = 28;
    ASSERT_EQ(result.referenceInfos.at(0).fileName, expectedFileName1);
    ASSERT_EQ(result.referenceInfos.at(0).start, expectedStartPos1);
    ASSERT_EQ(result.referenceInfos.at(0).length, expectedLength1);
    ASSERT_EQ(result.referenceInfos.at(1).fileName, expectedFileName2);
    ASSERT_EQ(result.referenceInfos.at(1).start, expectedStartPos2);
    ASSERT_EQ(result.referenceInfos.at(1).length, expectedLength2);
    initializer.DestroyContext(ctx1);
}

TEST_F(LSPAPITests, GetFileReferencesImpl3)
{
    using ark::es2panda::public_lib::Context;
    std::vector<std::string> files = {"package-module.ets"};
    std::vector<std::string> texts = {R"(import { PI } from "std/math";
console.log(PI);)"};
    auto filePaths = CreateTempFile(files, texts);
    int const expectedFileCount = 1;
    ASSERT_EQ(filePaths.size(), expectedFileCount);

    char const *referenceFileName = filePaths[0].c_str();
    Initializer initializer = Initializer();
    auto ctx = initializer.CreateContext(referenceFileName, ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto baseUrl = reinterpret_cast<Context *>(ctx)->config->options->ArkTSConfig()->BaseUrl();
    auto searchFileName = baseUrl + "/plugins/ets/stdlib/std/math/math.ets";
    auto result = References();
    result = ark::es2panda::lsp::GetFileReferencesImpl(ctx, searchFileName.c_str(), true);
    auto expectedFileName = filePaths[0];
    size_t const expectedStartPos = 19;
    size_t const expectedLength = 10;

    ASSERT_EQ(result.referenceInfos.at(0).fileName, expectedFileName);
    ASSERT_EQ(result.referenceInfos.at(0).start, expectedStartPos);
    ASSERT_EQ(result.referenceInfos.at(0).length, expectedLength);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetPrecedingToken1)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext(

        "precedingtoken_literal.ets", ES2PANDA_STATE_CHECKED,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = "
        "\"foo\";\n");
    ASSERT_EQ(ContextState(context), ES2PANDA_STATE_CHECKED);
    auto ast = GetAstFromContext<AstNode>(context);

    size_t const numberLiteralOffset = 31;  // 31: position of '3' in '1234'
    size_t const stringLiteralOffset = 96;  // 96: position of first 'o' in 'foo'
    auto numberLiteral = ast->FindChild([](AstNode *node) { return node->IsExpressionStatement(); })
                             ->AsExpressionStatement()
                             ->GetExpression()
                             ->AsAssignmentExpression()
                             ->Right()
                             ->AsNumberLiteral();
    auto result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, numberLiteralOffset));
    ASSERT_EQ(result->DumpJSON(), numberLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, numberLiteral->Start().index);
    ASSERT_EQ(result->End().index, numberLiteral->End().index);
    auto stringLiteral = ast->FindChild(
        [](AstNode *node) { return node->IsStringLiteral() && node->AsStringLiteral()->ToString() == "foo"; });
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, stringLiteralOffset));
    ASSERT_EQ(result->DumpJSON(), stringLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, stringLiteral->Start().index);
    ASSERT_EQ(result->End().index, stringLiteral->End().index);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetPrecedingToken2)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    Initializer initializer = Initializer();
    es2panda_Context *context = initializer.CreateContext(
        "precedingtoken_function.ets", ES2PANDA_STATE_CHECKED,
        "    \n\n\n\nfunction f() {\n    le\n    let a = 123;\n}\n\n\n\nconst s = \"hello\";\n\n\n");
    auto ast = GetAstFromContext<AstNode>(context);

    size_t const startOfFile = 0;            // 0: position of start of file
    size_t const secondSpaceBeforeLe = 25;   // 25: position of second space before 'le'
    size_t const endOfLe = 29;               // 29: position of the end of 'le' identifier
    size_t const secondSpaceBeforeLet = 32;  // 32: position of second space before 'let'
    size_t const startOfLine10 = 50;         // 50: position of start of line 10
    size_t const startOfLine14 = 72;         // 72: position of start of line 14
    ASSERT_EQ(lspApi->getPrecedingToken(context, startOfFile), nullptr);
    ASSERT_EQ(lspApi->getPrecedingToken(context, secondSpaceBeforeLe), nullptr);
    auto leIdentifier =
        ast->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "le"; });
    auto result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, endOfLe));
    ASSERT_EQ(result->DumpJSON(), leIdentifier->DumpJSON());
    ASSERT_EQ(result->Start().index, leIdentifier->Start().index);
    ASSERT_EQ(result->End().index, leIdentifier->End().index);
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, secondSpaceBeforeLet));
    ASSERT_EQ(result->DumpJSON(), leIdentifier->DumpJSON());
    ASSERT_EQ(result->Start().index, leIdentifier->Start().index);
    ASSERT_EQ(result->End().index, leIdentifier->End().index);
    auto numberLiteral = ast->FindChild(
        [](AstNode *node) { return node->IsNumberLiteral() && node->AsNumberLiteral()->Str() == "123"; });
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, startOfLine10));
    ASSERT_EQ(result->DumpJSON(), numberLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, numberLiteral->Start().index);
    ASSERT_EQ(result->End().index, numberLiteral->End().index);
    auto stringLiteral = ast->FindChild([](AstNode *node) { return node->IsClassProperty(); })
                             ->AsClassProperty()
                             ->Value()
                             ->AsStringLiteral();
    result = reinterpret_cast<AstNode *>(lspApi->getPrecedingToken(context, startOfLine14));
    ASSERT_EQ(result->DumpJSON(), stringLiteral->DumpJSON());
    ASSERT_EQ(result->Start().index, stringLiteral->Start().index);
    ASSERT_EQ(result->End().index, stringLiteral->End().index);
    initializer.DestroyContext(context);
}

TEST_F(LSPAPITests, GetTypeOfSymbolAtLocation1)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    Initializer initializer = Initializer();
    es2panda_Context *ctx =
        initializer.CreateContext("types.ets", ES2PANDA_STATE_CHECKED,
                                  "let a: number;\nlet b: byte;\nlet c: short;\nlet d: int;\nlet e: long;\nlet f: "
                                  "float;\nlet g: double;\nlet h: char;\nlet i: boolean;");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto checker = reinterpret_cast<Context *>(ctx)->checker->AsETSChecker();
    auto astNode = GetAstFromContext<AstNode>(ctx);
    auto targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "a"; });
    auto type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsDoubleType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "b"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsByteType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "c"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsShortType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "d"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsIntType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "e"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsLongType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "f"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsFloatType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "g"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsDoubleType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "h"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsCharType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "i"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSBooleanType());
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTypeOfSymbolAtLocation2)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(
        "types.ets", ES2PANDA_STATE_CHECKED,
        "let j: object;\nlet k: string;\nlet l: [];\nlet m: bigint;\nlet n: never;\nlet o: null;\nlet p: "
        "undefined;\nlet tuple: [number, number] = [1, 2];\nlet union: int | null;");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto checker = reinterpret_cast<Context *>(ctx)->checker->AsETSChecker();
    auto astNode = GetAstFromContext<AstNode>(ctx);
    auto targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "j"; });
    auto type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSObjectType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "k"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSStringType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "l"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSTupleType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "m"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSBigIntType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "n"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSNeverType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "o"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSNullType());

    targetNode =
        astNode->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "p"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSUndefinedType());

    targetNode = astNode->FindChild(
        [](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "tuple"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSTupleType());

    targetNode = astNode->FindChild(
        [](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "union"; });
    type = ark::es2panda::lsp::GetTypeOfSymbolAtLocation(checker, targetNode);
    ASSERT_TRUE(type->IsETSUnionType());
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("current_token.ets", ES2PANDA_STATE_CHECKED, "ab");
    LSPAPI const *lspApi = GetImpl();
    size_t offset = 2;
    std::string result = lspApi->getCurrentTokenValue(ctx, offset);
    initializer.DestroyContext(ctx);
    ASSERT_EQ(result, "ab");
}

TEST_F(LSPAPITests, GetCurrentTokenValue1)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "\"ab\"");
    size_t offset = 3;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue2)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "\'ab\'");
    size_t offset = 3;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue3)
{
    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("file1.ets", ES2PANDA_STATE_CHECKED, "abc");
    size_t offset = 2;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTokenPosOfNode1)
{
    using ark::es2panda::ir::AstNode;

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("token-pos-identifier.ets", ES2PANDA_STATE_CHECKED,
                                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(ctx);
    auto targetNode =
        ast->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "A"; });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 51;
    ASSERT_EQ(result, pos);

    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTokenPosOfNode2)
{
    using ark::es2panda::ir::AstNode;

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext("token-pos-expression.ets", ES2PANDA_STATE_CHECKED,
                                                      "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(ctx);
    auto targetNode = ast->FindChild([](AstNode *node) { return node->IsExpressionStatement(); });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 51;
    ASSERT_EQ(result, pos);

    initializer.DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTokenPosOfNode3)
{
    using ark::es2panda::ir::AstNode;

    Initializer initializer = Initializer();
    es2panda_Context *ctx = initializer.CreateContext(
        "token-pos-literal.ets", ES2PANDA_STATE_CHECKED,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = "
        "\"foo\";\n");
    ASSERT_EQ(ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(ctx);
    auto targetNode = ast->FindChild(
        [](AstNode *node) { return node->IsNumberLiteral() && node->AsNumberLiteral()->Str() == "1234"; });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 29;
    ASSERT_EQ(result, pos);

    initializer.DestroyContext(ctx);
}
