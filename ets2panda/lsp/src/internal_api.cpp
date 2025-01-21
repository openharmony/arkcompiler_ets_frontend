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

}  // namespace ark::es2panda::lsp
