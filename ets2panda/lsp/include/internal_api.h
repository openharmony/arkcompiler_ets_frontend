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

#ifndef ES2PANDA_LSP_INCLUDE_INTERNAL_API_H
#define ES2PANDA_LSP_INCLUDE_INTERNAL_API_H

#include "api.h"
#include "checker/types/type.h"
#include "ir/astNode.h"
#include "public/es2panda_lib.h"

namespace ark::es2panda::lsp {

class Initializer {
public:
    Initializer();

    ~Initializer();

    ark::ArenaAllocator *Allocator()
    {
        return allocator_;
    }

    es2panda_Context *CreateContext(char const *fileName, es2panda_ContextState state, char const *fileSource = nullptr)
    {
        es2panda_Context *ctx = nullptr;
        if (fileSource != nullptr) {
            ctx = impl_->CreateContextFromString(cfg_, fileSource, fileName);
        } else {
            ctx = impl_->CreateContextFromFile(cfg_, fileName);
        }
        impl_->ProceedToState(ctx, state);
        return ctx;
    }

    void DestroyContext(es2panda_Context *context)
    {
        impl_->DestroyContext(context);
    }

    NO_COPY_SEMANTIC(Initializer);
    NO_MOVE_SEMANTIC(Initializer);

private:
    es2panda_Impl const *impl_;
    es2panda_Config *cfg_;
    ark::ArenaAllocator *allocator_;
};

ir::AstNode *GetTouchingToken(es2panda_Context *context, size_t pos, bool flagFindFirstMatch);
void GetFileReferencesImpl(es2panda_Context *referenceFileContext, char const *searchFileName, bool isPackageModule,
                           References *fileReferences);
ir::AstNode *FindPrecedingToken(const size_t pos, const ir::AstNode *startNode, ArenaAllocator *allocator);
ir::AstNode *GetOriginalNode(ir::AstNode *astNode);
checker::VerifiedType GetTypeOfSymbolAtLocation(checker::ETSChecker *checker, ir::AstNode *astNode);
std::string GetCurrentTokenValueImpl(es2panda_Context *context, size_t position);
void GetRangeOfEnclosingComment(es2panda_Context *context, size_t pos, CommentRange *result);
Diagnostic CreateDiagnosticForError(es2panda_Context *context, const Error &error);
size_t GetTokenPosOfNode(const ir::AstNode *astNode);

}  // namespace ark::es2panda::lsp

#endif