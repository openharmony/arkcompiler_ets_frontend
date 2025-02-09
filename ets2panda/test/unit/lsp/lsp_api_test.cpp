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
#include "public/es2panda_lib.h"
#include "public/public.h"

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

TEST_F(LSPAPITests, DiagnosticConstructorAndField)
{
    int const errorCode = 404;
    int const defaultCharacter = 10;
    ark::ArenaVector<DiagnosticTag> tags(allocator_->Adapter());
    ark::ArenaVector<DiagnosticRelatedInformation> relatedInfoList(allocator_->Adapter());
    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_.c_str());

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
    ark::ArenaVector<DiagnosticTag> tags(allocator_->Adapter());
    ark::ArenaVector<DiagnosticRelatedInformation> relatedInfoList(allocator_->Adapter());

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_.c_str(),
                          codeDesc);

    const auto &codeDescription = diagnostic.codeDescription_;
    EXPECT_EQ(codeDescription.href_, "http://example.com/error/404");
}

TEST_F(LSPAPITests, DiagnosticTagsAndRelatedInformation)
{
    ark::ArenaVector<DiagnosticTag> tags(allocator_->Adapter());
    tags.push_back(DiagnosticTag::Unnecessary);
    ark::ArenaVector<DiagnosticRelatedInformation> relatedInfoList(allocator_->Adapter());
    DiagnosticRelatedInformation relatedInfo;
    relatedInfo.location_ = Location {"www.test.uri", range_};
    relatedInfo.message_ = "Related information message";
    relatedInfoList.push_back(relatedInfo);
    int const errorCode = 200;
    CodeDescription des = {};

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Information, errorCode, message_.c_str(),
                          des, "default");

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
    std::variant<int, const char *> data = dataValue;
    int const errorCode = 400;
    int const dataResult = 42;
    ark::ArenaVector<DiagnosticTag> tags(allocator_->Adapter());
    ark::ArenaVector<DiagnosticRelatedInformation> relatedInfoList(allocator_->Adapter());

    Diagnostic diagnostic(range_, tags, relatedInfoList, DiagnosticSeverity::Error, errorCode, message_.c_str(), {}, {},
                          data);

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

    ark::ArenaVector<FileReferenceInfo *> *referencesInfo =
        reinterpret_cast<Context *>(ctx1)->allocator->New<ark::ArenaVector<FileReferenceInfo *>>(
            reinterpret_cast<Context *>(ctx1)->allocator->Adapter());
    FileReferences *result = reinterpret_cast<Context *>(ctx1)->allocator->New<FileReferences>(referencesInfo);

    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx1, searchFileName, isPackageModule, result);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 11;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 45;
    size_t const expectedLength2 = 15;
    ASSERT_EQ(std::string(result->referenceInfos->at(0)->fileName), expectedFileName1);
    ASSERT_EQ(result->referenceInfos->at(0)->start, expectedStartPos1);
    ASSERT_EQ(result->referenceInfos->at(0)->length, expectedLength1);
    ASSERT_EQ(std::string(result->referenceInfos->at(1)->fileName), expectedFileName2);
    ASSERT_EQ(result->referenceInfos->at(1)->start, expectedStartPos2);
    ASSERT_EQ(result->referenceInfos->at(1)->length, expectedLength2);
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

    ark::ArenaVector<FileReferenceInfo *> *referencesInfo =
        reinterpret_cast<Context *>(ctx1)->allocator->New<ark::ArenaVector<FileReferenceInfo *>>(
            reinterpret_cast<Context *>(ctx1)->allocator->Adapter());
    FileReferences *result = reinterpret_cast<Context *>(ctx1)->allocator->New<FileReferences>(referencesInfo);
    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx1, searchFileName, isPackageModule, result);
    auto expectedFileName1 = filePaths[1];
    size_t const expectedStartPos1 = 16;
    size_t const expectedLength1 = 11;
    auto expectedFileName2 = filePaths[1];
    size_t const expectedStartPos2 = 45;
    size_t const expectedLength2 = 14;
    ASSERT_EQ(std::string(result->referenceInfos->at(0)->fileName), expectedFileName1);
    ASSERT_EQ(result->referenceInfos->at(0)->start, expectedStartPos1);
    ASSERT_EQ(result->referenceInfos->at(0)->length, expectedLength1);
    ASSERT_EQ(std::string(result->referenceInfos->at(1)->fileName), expectedFileName2);
    ASSERT_EQ(result->referenceInfos->at(1)->start, expectedStartPos2);
    ASSERT_EQ(result->referenceInfos->at(1)->length, expectedLength2);
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
    ark::ArenaVector<FileReferenceInfo *> *referencesInfo =
        reinterpret_cast<Context *>(ctx)->allocator->New<ark::ArenaVector<FileReferenceInfo *>>(
            reinterpret_cast<Context *>(ctx)->allocator->Adapter());
    FileReferences *result = reinterpret_cast<Context *>(ctx)->allocator->New<FileReferences>(referencesInfo);
    ark::es2panda::lsp::GetFileReferencesImpl(allocator_, ctx, searchFileName.c_str(), true, result);
    auto expectedFileName = filePaths[0];
    size_t const expectedStartPos = 19;
    size_t const expectedLength = 10;

    ASSERT_EQ(result->referenceInfos->at(0)->fileName, expectedFileName);
    ASSERT_EQ(result->referenceInfos->at(0)->start, expectedStartPos);
    ASSERT_EQ(result->referenceInfos->at(0)->length, expectedLength);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetPrecedingToken1)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = \"foo\";\n",
        "precedingtoken_literal.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(context), ES2PANDA_STATE_CHECKED);
    auto ast = GetAstFromContext<AstNode>(impl_, context);

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
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetPrecedingToken2)
{
    using ark::es2panda::ir::AstNode;

    LSPAPI const *lspApi = GetImpl();
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_, "    \n\n\n\nfunction f() {\n    le\n    let a = 123;\n}\n\n\n\nconst s = \"hello\";\n\n\n",
        "precedingtoken_function.sts", ES2PANDA_STATE_CHECKED);
    auto ast = GetAstFromContext<AstNode>(impl_, context);

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
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetTypeOfSymbolAtLocation1)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_,
                                       "let a: number;\nlet b: byte;\nlet c: short;\nlet d: int;\nlet e: long;\nlet f: "
                                       "float;\nlet g: double;\nlet h: char;\nlet i: boolean;",
                                       "types.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto checker = reinterpret_cast<Context *>(ctx)->checker->AsETSChecker();
    auto astNode = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));
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
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTypeOfSymbolAtLocation2)
{
    using ark::es2panda::ir::AstNode;
    using ark::es2panda::public_lib::Context;
    es2panda_Context *ctx = CreateContextAndProceedToState(
        impl_, cfg_,
        "let j: object;\nlet k: string;\nlet l: [];\nlet m: bigint;\nlet n: never;\nlet o: null;\nlet p: "
        "undefined;\nlet tuple: [number, number] = [1, 2];\nlet union: int | null;",
        "types.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto checker = reinterpret_cast<Context *>(ctx)->checker->AsETSChecker();
    auto astNode = reinterpret_cast<AstNode *>(impl_->ProgramAst(impl_->ContextProgram(ctx)));
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
    ASSERT_TRUE(type->IsETSArrayType());

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
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue1)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, "\"ab\"", "file1.sts", ES2PANDA_STATE_CHECKED);
    size_t offset = 3;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue2)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, "\'ab\'", "file1.sts", ES2PANDA_STATE_CHECKED);
    size_t offset = 3;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetCurrentTokenValue3)
{
    es2panda_Context *ctx = CreateContextAndProceedToState(impl_, cfg_, "abc", "file1.sts", ES2PANDA_STATE_CHECKED);
    size_t offset = 2;
    std::string result = ark::es2panda::lsp::GetCurrentTokenValueImpl(ctx, offset);
    std::string expect = "ab";
    ASSERT_EQ(result, expect);
    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetSemanticDiagnosticsForFile1)
{
    const char *source = R"delimiter(
function add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(impl_, cfg_, source, "GetSemanticDiagnosticsNoError.sts",
                                                               ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(context), ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto semanticDiagnostics = ark::es2panda::lsp::GetSemanticDiagnosticsForFile(context, allocator);
    ASSERT_EQ(semanticDiagnostics.size(), 0);
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetSemanticDiagnosticsForFile2)
{
    const char *source = R"delimiter(
const a: number = "hello";
function add(a: number, b: number): number {
    return a + b;
}
add("1", 2);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(impl_, cfg_, source, "GetSemanticDiagnosticsForFile.sts",
                                                               ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto semanticDiagnostics = ark::es2panda::lsp::GetSemanticDiagnosticsForFile(context, allocator);
    auto const expectedErrorCount = 3;
    ASSERT_EQ(semanticDiagnostics.size(), expectedErrorCount);
    auto const expectedFirstStartLine = 2;
    auto const expectedFirstStartCharacter = 19;
    auto const expectedFirstEndLine = 2;
    auto const expectedFirstEndCharacter = 26;
    ASSERT_EQ(semanticDiagnostics[0]->range_.start.line_, expectedFirstStartLine);
    ASSERT_EQ(semanticDiagnostics[0]->range_.start.character_, expectedFirstStartCharacter);
    ASSERT_EQ(semanticDiagnostics[0]->range_.end.line_, expectedFirstEndLine);
    ASSERT_EQ(semanticDiagnostics[0]->range_.end.character_, expectedFirstEndCharacter);
    ASSERT_EQ(semanticDiagnostics[0]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(semanticDiagnostics[0]->code_), 1);
    ASSERT_STREQ(semanticDiagnostics[0]->message_, R"(Type '"hello"' cannot be assigned to type 'double')");
    ASSERT_STREQ(semanticDiagnostics[0]->codeDescription_.href_, "test code description");
    auto const expectedSecondStartLine = 6;
    auto const expectedSecondStartCharacter = 5;
    auto const expectedSecondEndLine = 6;
    auto const expectedSecondEndCharacter = 8;
    ASSERT_EQ(semanticDiagnostics[1]->range_.start.line_, expectedSecondStartLine);
    ASSERT_EQ(semanticDiagnostics[1]->range_.start.character_, expectedSecondStartCharacter);
    ASSERT_EQ(semanticDiagnostics[1]->range_.end.line_, expectedSecondEndLine);
    ASSERT_EQ(semanticDiagnostics[1]->range_.end.character_, expectedSecondEndCharacter);
    ASSERT_EQ(semanticDiagnostics[1]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(semanticDiagnostics[1]->code_), 1);
    ASSERT_STREQ(semanticDiagnostics[1]->message_, R"(Type '"1"' is not compatible with type 'double' at index 1)");
    ASSERT_STREQ(semanticDiagnostics[1]->codeDescription_.href_, "test code description");
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetSyntacticDiagnosticsForFile1)
{
    const char *source = R"delimiter(
function add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_, source, "GetSyntacticDiagnosticsNoError.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(context), ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto syntacticDiagnostics = ark::es2panda::lsp::GetSyntacticDiagnosticsForFile(context, allocator);
    ASSERT_EQ(syntacticDiagnostics.size(), 0);
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetSyntacticDiagnosticsForFile2)
{
    const char *source = R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_, source, "GetSyntacticDiagnosticsForFile.sts", ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto syntacticDiagnostics = ark::es2panda::lsp::GetSyntacticDiagnosticsForFile(context, allocator);
    auto const expectedErrorCount = 13;
    ASSERT_EQ(syntacticDiagnostics.size(), expectedErrorCount);
    auto const expectedFirstStartLine = 2;
    auto const expectedFirstStartCharacter = 9;
    auto const expectedFirstEndLine = 2;
    auto const expectedFirstEndCharacter = 12;
    ASSERT_EQ(syntacticDiagnostics[0]->range_.start.line_, expectedFirstStartLine);
    ASSERT_EQ(syntacticDiagnostics[0]->range_.start.character_, expectedFirstStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[0]->range_.end.line_, expectedFirstEndLine);
    ASSERT_EQ(syntacticDiagnostics[0]->range_.end.character_, expectedFirstEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[0]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[0]->code_), 1);
    auto const expectedSecondStartLine = 3;
    auto const expectedSecondStartCharacter = 18;
    auto const expectedSecondEndLine = 3;
    auto const expectedSecondEndCharacter = 18;
    ASSERT_EQ(syntacticDiagnostics[1]->range_.start.line_, expectedSecondStartLine);
    ASSERT_EQ(syntacticDiagnostics[1]->range_.start.character_, expectedSecondStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[1]->range_.end.line_, expectedSecondEndLine);
    ASSERT_EQ(syntacticDiagnostics[1]->range_.end.character_, expectedSecondEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[1]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[1]->code_), 1);
    auto const thirdIndex = 2;
    auto const expectedThirdStartLine = 3;
    auto const expectedThirdStartCharacter = 18;
    auto const expectedThirdEndLine = 3;
    auto const expectedThirdEndCharacter = 18;
    ASSERT_EQ(syntacticDiagnostics[thirdIndex]->range_.start.line_, expectedThirdStartLine);
    ASSERT_EQ(syntacticDiagnostics[thirdIndex]->range_.start.character_, expectedThirdStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[thirdIndex]->range_.end.line_, expectedThirdEndLine);
    ASSERT_EQ(syntacticDiagnostics[thirdIndex]->range_.end.character_, expectedThirdEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[thirdIndex]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[thirdIndex]->code_), 1);
    ASSERT_STREQ(syntacticDiagnostics[thirdIndex]->message_, R"(Unexpected token ':'.)");
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetSyntacticDiagnosticsForFile3)
{
    const char *source = R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_, source, "GetSyntacticDiagnosticsForFile.sts", ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto syntacticDiagnostics = ark::es2panda::lsp::GetSyntacticDiagnosticsForFile(context, allocator);
    auto const forthIndex = 5;
    auto const expectedForthStartLine = 3;
    auto const expectedForthStartCharacter = 18;
    auto const expectedForthEndLine = 3;
    auto const expectedForthEndCharacter = 18;
    ASSERT_EQ(syntacticDiagnostics[forthIndex]->range_.start.line_, expectedForthStartLine);
    ASSERT_EQ(syntacticDiagnostics[forthIndex]->range_.start.character_, expectedForthStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[forthIndex]->range_.end.line_, expectedForthEndLine);
    ASSERT_EQ(syntacticDiagnostics[forthIndex]->range_.end.character_, expectedForthEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[forthIndex]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[forthIndex]->code_), 1);
    ASSERT_STREQ(syntacticDiagnostics[forthIndex]->message_, R"(Unexpected token ','.)");
    ASSERT_STREQ(syntacticDiagnostics[forthIndex]->codeDescription_.href_, "test code description");
    auto const fifthIndex = 8;
    auto const expectedFifththStartLine = 2;
    auto const expectedFifthStartCharacter = 27;
    auto const expectedFifthEndLine = 2;
    auto const expectedFifthEndCharacter = 33;
    ASSERT_EQ(syntacticDiagnostics[fifthIndex]->range_.start.line_, expectedFifththStartLine);
    ASSERT_EQ(syntacticDiagnostics[fifthIndex]->range_.start.character_, expectedFifthStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[fifthIndex]->range_.end.line_, expectedFifthEndLine);
    ASSERT_EQ(syntacticDiagnostics[fifthIndex]->range_.end.character_, expectedFifthEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[fifthIndex]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[fifthIndex]->code_), 1);
    ASSERT_STREQ(syntacticDiagnostics[fifthIndex]->message_, R"(Label must be followed by a loop statement)");
    ASSERT_STREQ(syntacticDiagnostics[fifthIndex]->codeDescription_.href_, "test code description");
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetSyntacticDiagnosticsForFile4)
{
    const char *source = R"delimiter(
functon add(a: number, b: number) {
    return a + b;
}
let n = 333;
let res = add(n, n);
)delimiter";
    es2panda_Context *context = CreateContextAndProceedToState(
        impl_, cfg_, source, "GetSyntacticDiagnosticsForFile.sts", ES2PANDA_STATE_CHECKED);
    auto allocator = reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->allocator;
    auto syntacticDiagnostics = ark::es2panda::lsp::GetSyntacticDiagnosticsForFile(context, allocator);
    auto const sixthIndex = 9;
    auto const expectedSixthStartLine = 3;
    auto const expectedSixthStartCharacter = 18;
    auto const expectedSixthEndLine = 3;
    auto const expectedSixthEndCharacter = 18;
    ASSERT_EQ(syntacticDiagnostics[sixthIndex]->range_.start.line_, expectedSixthStartLine);
    ASSERT_EQ(syntacticDiagnostics[sixthIndex]->range_.start.character_, expectedSixthStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[sixthIndex]->range_.end.line_, expectedSixthEndLine);
    ASSERT_EQ(syntacticDiagnostics[sixthIndex]->range_.end.character_, expectedSixthEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[sixthIndex]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[sixthIndex]->code_), 1);
    ASSERT_STREQ(syntacticDiagnostics[sixthIndex]->message_, R"(Unexpected token ')'.)");
    ASSERT_STREQ(syntacticDiagnostics[sixthIndex]->codeDescription_.href_, "test code description");
    auto const sevenIndex = 12;
    auto const expectedSeventhStartLine = 3;
    auto const expectedSeventhStartCharacter = 5;
    auto const expectedSeventhEndLine = 3;
    auto const expectedSeventhEndCharacter = 18;
    ASSERT_EQ(syntacticDiagnostics[sevenIndex]->range_.start.line_, expectedSeventhStartLine);
    ASSERT_EQ(syntacticDiagnostics[sevenIndex]->range_.start.character_, expectedSeventhStartCharacter);
    ASSERT_EQ(syntacticDiagnostics[sevenIndex]->range_.end.line_, expectedSeventhEndLine);
    ASSERT_EQ(syntacticDiagnostics[sevenIndex]->range_.end.character_, expectedSeventhEndCharacter);
    ASSERT_EQ(syntacticDiagnostics[sevenIndex]->severity_, DiagnosticSeverity::Error);
    ASSERT_EQ(std::get<int>(syntacticDiagnostics[sevenIndex]->code_), 1);
    ASSERT_STREQ(syntacticDiagnostics[sevenIndex]->message_, R"(return keyword should be used in function body)");
    ASSERT_STREQ(syntacticDiagnostics[sevenIndex]->codeDescription_.href_, "test code description");
    impl_->DestroyContext(context);
}

TEST_F(LSPAPITests, GetTokenPosOfNode1)
{
    using ark::es2panda::ir::AstNode;

    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "token-pos-identifier.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(impl_, ctx);
    auto targetNode =
        ast->FindChild([](AstNode *node) { return node->IsIdentifier() && node->AsIdentifier()->Name() == "A"; });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 51;
    ASSERT_EQ(result, pos);

    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTokenPosOfNode2)
{
    using ark::es2panda::ir::AstNode;

    es2panda_Context *ctx =
        CreateContextAndProceedToState(impl_, cfg_, "function A(a:number, b:number) {\n  return a + b;\n}\nA(1, 2);",
                                       "token-pos-expression.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(impl_, ctx);
    auto targetNode = ast->FindChild([](AstNode *node) { return node->IsExpressionStatement(); });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 51;
    ASSERT_EQ(result, pos);

    impl_->DestroyContext(ctx);
}

TEST_F(LSPAPITests, GetTokenPosOfNode3)
{
    using ark::es2panda::ir::AstNode;

    es2panda_Context *ctx = CreateContextAndProceedToState(
        impl_, cfg_,
        "let number_literal: number = 1234;\nlet string_literal: string = \"hello\";\nconst str_property = \"foo\";\n",
        "token-pos-literal.sts", ES2PANDA_STATE_CHECKED);
    ASSERT_EQ(impl_->ContextState(ctx), ES2PANDA_STATE_CHECKED);

    auto ast = GetAstFromContext<AstNode>(impl_, ctx);
    auto targetNode = ast->FindChild(
        [](AstNode *node) { return node->IsNumberLiteral() && node->AsNumberLiteral()->Str() == "1234"; });

    ASSERT_NE(targetNode, nullptr);
    auto result = ark::es2panda::lsp::GetTokenPosOfNode(targetNode);
    size_t const pos = 29;
    ASSERT_EQ(result, pos);

    impl_->DestroyContext(ctx);
}