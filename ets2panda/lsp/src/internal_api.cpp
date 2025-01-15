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
            fileReferences->referenceInfos.push_back(fileRef);
        }
    }
}

}  // namespace ark::es2panda::lsp
