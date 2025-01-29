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

#include <string>
#include "api.h"
#include "internal_api.h"
#include "checker/types/type.h"
#include "ir/astNode.h"
#include "macros.h"
#include "public/public.h"

namespace ark::es2panda::lsp {

Initializer::Initializer()
{
    impl_ = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
    auto buidDir = std::string(BUILD_FOLDER) + "/bin/";
    std::array<const char *, 1> argv = {buidDir.c_str()};
    cfg_ = impl_->CreateConfig(argv.size(), argv.data());
    allocator_ = new ark::ArenaAllocator(ark::SpaceType::SPACE_TYPE_COMPILER);
}

Initializer::~Initializer()
{
    impl_->DestroyConfig(cfg_);
}

ir::AstNode *GetTouchingToken(es2panda_Context *context, size_t pos, bool flagFindFirstMatch)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    auto checkFunc = [&pos](ir::AstNode *node) { return pos >= node->Start().index && pos < node->End().index; };
    auto found = ast->FindChild(checkFunc);
    while (found != nullptr && !flagFindFirstMatch) {
        auto *nestedFound = found->FindChild(checkFunc);
        if (nestedFound == nullptr) {
            break;
        }
        found = nestedFound;
    }
    return found;
}

__attribute__((unused)) char *StdStringToCString(ArenaAllocator *allocator, const std::string &str)
{
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
    char *res = reinterpret_cast<char *>(allocator->Alloc(str.length() + 1));
    [[maybe_unused]] auto err = memcpy_s(res, str.length() + 1, str.c_str(), str.length() + 1);
    ASSERT(err == EOK);
    return res;
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic, readability-simplify-subscript-expr)
}

void GetFileReferencesImpl(ark::ArenaAllocator *allocator, es2panda_Context *referenceFileContext,
                           char const *searchFileName, bool isPackageModule, FileReferences *fileReferences)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(referenceFileContext);
    auto statements = ctx->parserProgram->Ast()->Statements();
    for (auto statement : statements) {
        if (!statement->IsETSImportDeclaration()) {
            continue;
        }
        auto import = statement->AsETSImportDeclaration();
        auto importFileName = import->ResolvedSource()->ToString();
        if (!import->Source()->IsStringLiteral()) {
            continue;
        }
        auto start = import->Source()->Start().index;
        auto end = import->Source()->End().index;
        auto pos = std::string(searchFileName).rfind('/');
        auto fileDirectory = std::string(searchFileName).substr(0, pos);
        if ((!isPackageModule && importFileName == searchFileName) ||
            (isPackageModule && importFileName == fileDirectory)) {
            auto fileRef = allocator->New<FileReferenceInfo>();
            fileRef->fileName = StdStringToCString(allocator, ctx->sourceFileName);
            fileRef->start = start;
            fileRef->length = end - start;
            fileReferences->referenceInfos->push_back(fileRef);
        }
    }
}

bool IsToken(const ir::AstNode *node)
{
    /**
     * True if node is of some token node.
     * For example, this is true for an IDENTIFIER or NUMBER_LITERAL but not for BLOCK_STATEMENT or CallExpression.
     * Keywords like "if" and "of" exist as TOKEN_TYPE and cannot be recognized as AstNode, so returning nodes like
     * IfKeyword or OfKeyword is not supported.
     */
    return node->Type() == ir::AstNodeType::BIGINT_LITERAL || node->Type() == ir::AstNodeType::BOOLEAN_LITERAL ||
           node->Type() == ir::AstNodeType::CHAR_LITERAL || node->Type() == ir::AstNodeType::IDENTIFIER ||
           node->Type() == ir::AstNodeType::NULL_LITERAL || node->Type() == ir::AstNodeType::UNDEFINED_LITERAL ||
           node->Type() == ir::AstNodeType::NUMBER_LITERAL || node->Type() == ir::AstNodeType::REGEXP_LITERAL ||
           node->Type() == ir::AstNodeType::STRING_LITERAL || node->Type() == ir::AstNodeType::TS_NUMBER_KEYWORD ||
           node->Type() == ir::AstNodeType::TS_ANY_KEYWORD || node->Type() == ir::AstNodeType::TS_BOOLEAN_KEYWORD ||
           node->Type() == ir::AstNodeType::TS_VOID_KEYWORD || node->Type() == ir::AstNodeType::TS_UNDEFINED_KEYWORD ||
           node->Type() == ir::AstNodeType::TS_UNKNOWN_KEYWORD || node->Type() == ir::AstNodeType::TS_OBJECT_KEYWORD ||
           node->Type() == ir::AstNodeType::TS_BIGINT_KEYWORD || node->Type() == ir::AstNodeType::TS_NEVER_KEYWORD ||
           node->Type() == ir::AstNodeType::TS_NULL_KEYWORD || node->Type() == ir::AstNodeType::TEMPLATE_ELEMENT;
}

bool IsNonWhitespaceToken(const ir::AstNode *node)
{
    return IsToken(node);
}

bool NodeHasTokens(const ir::AstNode *node)
{
    return node->Start().index != node->End().index;
}

ir::AstNode *FindRightmostChildNodeWithTokens(const ArenaVector<ir::AstNode *> &nodes, int exclusiveStartPosition)
{
    for (int i = exclusiveStartPosition - 1; i >= 0; --i) {
        if (NodeHasTokens(nodes[i])) {
            return nodes[i];
        }
    }
    return nullptr;
}

ArenaVector<ir::AstNode *> GetChildren(const ir::AstNode *node, ArenaAllocator *allocator)
{
    ArenaVector<ir::AstNode *> children(allocator->Adapter());
    if (node->Type() == ir::AstNodeType::ETS_MODULE) {
        // ETS_MODULE is the root node, need to get the definition of global class
        auto globalClass =
            node->FindChild([](ir::AstNode *child) { return child->IsClassDeclaration(); })->AsClassDeclaration();
        node = globalClass->Definition();
    }
    node->Iterate([&children](ir::AstNode *child) { children.push_back(child); });
    return children;
}

ir::AstNode *FindRightmostToken(const ir::AstNode *node, ArenaAllocator *allocator)
{
    if (node == nullptr) {
        return nullptr;
    }
    if (IsNonWhitespaceToken(node)) {
        return const_cast<ir::AstNode *>(node);
    }
    auto children = GetChildren(node, allocator);
    if (children.empty()) {
        return const_cast<ir::AstNode *>(node);
    }
    auto candidate = FindRightmostChildNodeWithTokens(children, children.size());
    return FindRightmostToken(candidate, allocator);
}

ir::AstNode *FindNodeBeforePosition(const ArenaVector<ir::AstNode *> &children, size_t pos)
{
    if (children.empty()) {
        return nullptr;
    }
    size_t left = 0;
    size_t right = children.size() - 1;
    size_t mid = 0;
    while (left <= right) {
        mid = left + ((right - left) >> 1U);
        if (pos < children[mid]->End().index) {
            if (mid == 0 || pos >= children[mid - 1]->End().index) {
                break;
            }
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return FindRightmostChildNodeWithTokens(children, mid);
}

ir::AstNode *FindPrecedingToken(const size_t pos, const ir::AstNode *startNode, ArenaAllocator *allocator)
{
    auto checkFunc = [&pos](ir::AstNode *node) { return node->Start().index <= pos && pos <= node->End().index; };
    auto found = startNode->FindChild(checkFunc);
    if (found != nullptr) {
        auto nestedFound = found->FindChild(checkFunc);
        while (nestedFound != nullptr) {
            // try to find the minimum node that embraces position
            found = nestedFound;
            nestedFound = found->FindChild(checkFunc);
        }

        // position is 0, found does not has any tokens
        if (!NodeHasTokens(found)) {
            return nullptr;
        }

        if (IsNonWhitespaceToken(found)) {
            return found;
        }

        // found embraces the position, but none of its children do
        // (ie: in a comment or whitespace preceding `child node`)
        auto children = GetChildren(found, allocator);
        auto candidate = FindNodeBeforePosition(children, pos);
        return FindRightmostToken(candidate, allocator);
    }

    // position is in the global scope but not 0, found will be nullptr.
    auto children = GetChildren(startNode, allocator);
    auto candidate = FindNodeBeforePosition(children, pos);
    return FindRightmostToken(candidate, allocator);
}

ir::AstNode *GetOriginalNode(ir::AstNode *astNode)
{
    while (astNode != nullptr && astNode->OriginalNode() != nullptr) {
        astNode = astNode->OriginalNode();
    }
    return astNode;
}

checker::VerifiedType GetTypeOfSymbolAtLocation(checker::ETSChecker *checker, ir::AstNode *astNode)
{
    ASSERT(astNode);
    auto originalNode = GetOriginalNode(astNode);
    return originalNode->Check(checker);
}

std::string ReplaceQuotation(ark::es2panda::util::StringView strView)
{
    std::string str = std::string {strView};
    str.erase(std::remove(str.begin(), str.end(), '\"'), str.end());
    str.erase(std::remove(str.begin(), str.end(), '\''), str.end());
    return str;
}

std::string GetCurrentTokenValueImpl(es2panda_Context *context, size_t position)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto program = ctx->parserProgram;
    auto ast = program->Ast();
    ir::AstNode *node = FindPrecedingToken(position, ast, ctx->allocator);
    return node != nullptr ? ReplaceQuotation(program->SourceCode().Substr(node->Start().index, position)) : "";
}

ir::AstNode *FindLeftToken(const size_t pos, const ArenaVector<ir::AstNode *> &nodes)
{
    int left = 0;
    int right = nodes.size() - 1;
    ir::AstNode *result = nullptr;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (nodes[mid]->End().index <= pos) {
            result = nodes[mid];
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return result;
}

ir::AstNode *FindRightToken(const size_t pos, const ArenaVector<ir::AstNode *> &nodes)
{
    int left = 0;
    int right = nodes.size() - 1;
    ir::AstNode *result = nullptr;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (nodes[mid]->Start().index > pos) {
            result = nodes[mid];
            right = mid - 1;
        } else {
            left = mid + 1;
        }
    }
    return result;
}

CommentRange *GetRangeOfCommentFromContext(std::string const &sourceCode, size_t leftPos, size_t rightPos, size_t pos,
                                           ArenaAllocator *allocator)
{
    constexpr size_t BLOCK_COMMENT_START_LENGTH = 2;
    std::vector<CommentRange> commentRanges;
    size_t startIndex = 0;
    while (startIndex < sourceCode.size()) {
        size_t blockCommentStart = sourceCode.find("/*", startIndex);
        size_t lineCommentStart = sourceCode.find("//", startIndex);
        if (blockCommentStart == std::string::npos && lineCommentStart == std::string::npos) {
            break;
        }
        if (blockCommentStart < lineCommentStart || lineCommentStart == std::string::npos) {
            if (blockCommentStart > rightPos) {
                break;
            }
            size_t blockCommentEnd = sourceCode.find("*/", blockCommentStart + BLOCK_COMMENT_START_LENGTH);
            if (blockCommentEnd == std::string::npos) {
                break;
            }
            commentRanges.emplace_back(
                CommentRange(blockCommentStart, blockCommentEnd + BLOCK_COMMENT_START_LENGTH, CommentKind::MULTI_LINE));
            startIndex = blockCommentEnd + BLOCK_COMMENT_START_LENGTH;
            continue;
        }
        if (lineCommentStart > rightPos) {
            break;
        }
        size_t lineCommentEnd = sourceCode.find('\n', lineCommentStart);
        if (lineCommentEnd == std::string::npos) {
            lineCommentEnd = sourceCode.size();
        }
        commentRanges.emplace_back(CommentRange(lineCommentStart, lineCommentEnd, CommentKind::SINGLE_LINE));
        startIndex = lineCommentEnd;
    }
    for (const auto &range : commentRanges) {
        if (range.GetPos() <= pos && range.GetEnd() >= pos && range.GetPos() >= leftPos && range.GetEnd() <= rightPos) {
            return allocator->New<CommentRange>(range.GetPos(), range.GetEnd(), range.GetKind());
        }
    }
    return nullptr;
}

CommentRange *GetRangeOfEnclosingComment(es2panda_Context *context, size_t pos, ArenaAllocator *allocator)
{
    auto touchingNode = GetTouchingToken(context, pos, false);
    if (touchingNode != nullptr && IsToken(touchingNode)) {
        return nullptr;
    }
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto ast = reinterpret_cast<ir::AstNode *>(ctx->parserProgram->Ast());
    ir::AstNode *parent = touchingNode != nullptr ? touchingNode : ast;
    auto children = GetChildren(parent, allocator);
    std::sort(children.begin(), children.end(), [](ir::AstNode *a, ir::AstNode *b) {
        if (a->Start().index < b->Start().index) {
            return true;
        }
        if (a->Start().index == b->Start().index) {
            return a->End().index < b->End().index;
        }
        return false;
    });
    ir::AstNode *leftToken = FindLeftToken(pos, children);
    ir::AstNode *rightToken = FindRightToken(pos, children);
    size_t leftPos = leftToken != nullptr ? leftToken->End().index : parent->Start().index;
    size_t rightPos = rightToken != nullptr ? rightToken->Start().index : parent->End().index;
    std::string sourceCode(ctx->parserProgram->SourceCode());
    CommentRange *result = GetRangeOfCommentFromContext(sourceCode, leftPos, rightPos, pos, allocator);
    return result;
}

// convert from es2panda error type to LSP severity
DiagnosticSeverity GetSeverity(ErrorType errorType)
{
    ASSERT(errorType != ErrorType::INVALID);
    if (errorType == ErrorType::ETS_WARNING) {
        return DiagnosticSeverity::Warning;
    }
    if (errorType == ErrorType::SYNTAX || errorType == ErrorType::TYPE || errorType == ErrorType::GENERIC) {
        return DiagnosticSeverity::Error;
    }
    throw std::runtime_error("Unknown error type!");
}

const char *GetCategory(ErrorType errorType)
{
    switch (errorType) {
        case ErrorType::SYNTAX:
            return "syntax";
        case ErrorType::TYPE:
            return "semantic";
        default:
            return "invailde";
    }
}

Diagnostic *CreateDiagnosticForError(es2panda_Context *context, const Error &error, ArenaAllocator *allocator)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto index = lexer::LineIndex(ctx->parserProgram->SourceCode());
    auto offset = index.GetOffset(lexer::SourceLocation(error.Line(), error.Col()));
    auto touchingToken = GetTouchingToken(context, offset, false);
    auto sourceRange = touchingToken->Range();
    auto sourceStartLocation = index.GetLocation(sourceRange.start);
    auto sourceEndLocation = index.GetLocation(sourceRange.end);
    auto range = Range(Position(sourceStartLocation.line, sourceStartLocation.col),
                       Position(sourceEndLocation.line, sourceEndLocation.col));
    auto severity = GetSeverity(error.Type());
    auto code = error.ErrorCode();
    const char *message = StdStringToCString(allocator, error.Message());
    auto codeDescription = CodeDescription("test code description");
    auto source = StdStringToCString(allocator, touchingToken->DumpEtsSrc());
    auto tags = ArenaVector<DiagnosticTag>(allocator->Adapter());
    auto relatedInformation = ArenaVector<DiagnosticRelatedInformation>(allocator->Adapter());
    auto data = GetCategory(error.Type());
    auto diagnostic = allocator->New<Diagnostic>(range, tags, relatedInformation, severity, code, message,
                                                 codeDescription, source, data);
    return diagnostic;
}

ArenaVector<Diagnostic *> CreateDiagnostics(es2panda_Context *context, ArenaAllocator *allocator)
{
    auto ctx = reinterpret_cast<public_lib::Context *>(context);
    auto &errors = ctx->checker->ErrorLogger()->Log();
    ArenaVector<Diagnostic *> diagnostics(allocator->Adapter());
    diagnostics.reserve(errors.size());
    for (auto &error : errors) {
        diagnostics.push_back(CreateDiagnosticForError(context, error, allocator));
    }
    return diagnostics;
}

ArenaVector<Diagnostic *> GetSemanticDiagnosticsForFile(es2panda_Context *context, ArenaAllocator *allocator)
{
    ArenaVector<Diagnostic *> semanticDiagnostics(allocator->Adapter());
    auto diagnostics = CreateDiagnostics(context, allocator);
    for (auto diagnostic : diagnostics) {
        auto category = std::get_if<const char *>(&diagnostic->data_);
        if (category != nullptr && strcmp(*category, "semantic") == 0) {
            semanticDiagnostics.push_back(diagnostic);
        }
    }
    return semanticDiagnostics;
}

size_t GetTokenPosOfNode(const ir::AstNode *astNode)
{
    ASSERT(astNode);

    return astNode->Start().index;
}

}  // namespace ark::es2panda::lsp
