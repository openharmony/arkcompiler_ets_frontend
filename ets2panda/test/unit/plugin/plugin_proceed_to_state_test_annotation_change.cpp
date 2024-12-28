/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <vector>
#include <utility>
#include "public/es2panda_lib.h"
#include "os/library_loader.h"

// NOLINTBEGIN

static const char *LIBNAME = "es2panda-public";
constexpr int MIN_ARGC = 3;
constexpr int NUMBER_OF_ANNO_DECLARATIONS = 2;
constexpr int NULLPTR_IMPL_ERROR_CODE = 2;
constexpr int PROCEED_ERROR_CODE = 3;
constexpr int TEST_ERROR_CODE = 4;

static es2panda_Impl *impl = nullptr;

es2panda_Impl *GetImpl()
{
    std::string soName = ark::os::library_loader::DYNAMIC_LIBRARY_PREFIX + std::string(LIBNAME) +
                         ark::os::library_loader::DYNAMIC_LIBRARY_SUFFIX;
    auto libraryRes = ark::os::library_loader::Load(soName);
    if (!libraryRes.HasValue()) {
        std::cout << "Error in load lib" << std::endl;
        return nullptr;
    }

    auto library = std::move(libraryRes.Value());
    auto getImpl = ark::os::library_loader::ResolveSymbol(library, "es2panda_GetImpl");
    if (!getImpl.HasValue()) {
        std::cout << "Error in load func get impl" << std::endl;
        return nullptr;
    }

    auto getImplFunc = reinterpret_cast<const es2panda_Impl *(*)(int)>(getImpl.Value());
    if (getImplFunc != nullptr) {
        return const_cast<es2panda_Impl *>(getImplFunc(ES2PANDA_LIB_VERSION));
    }
    return nullptr;
}

static std::string source = R"(
// Annotation declaration:
@interface FuncAuthor {
   authorName: string = "Jim"
}
@interface Major {
   authorName: string = "Tom"
}
// Annotation use:
@FuncAuthor ()
function foo():void {}
)";

static std::vector<es2panda_AstNode *> annotationDeclarations;
static std::vector<es2panda_AstNode *> functionDeclarations;

static void CollectDeclarations(es2panda_AstNode *node)
{
    if (impl->IsAnnotationDeclaration(node)) {
        annotationDeclarations.push_back(node);
    }
    if (impl->IsFunctionDeclaration(node)) {
        functionDeclarations.push_back(node);
    }
}

static es2panda_AstNode *GetAnnotationUsage(es2panda_Context *context, es2panda_AstNode *functionDecl)
{
    size_t n;
    auto **annotations = impl->AnnotationAllowedAnnotations(context, functionDecl, &n);
    if (n != 1) {
        return nullptr;
    }
    return impl->AnnotationUsageIrExpr(context, annotations[0]);
}

static bool IsAnnotationUsageName(es2panda_Context *context, es2panda_AstNode *annotationUsage,
                                  std::string_view expected)
{
    auto *annotationName = impl->IdentifierName(context, annotationUsage);
    return std::string(annotationName) == expected;
}

static bool ChangeAnnotationName(es2panda_Context *context)
{
    if (functionDeclarations.size() != 1) {
        return false;
    }
    auto *funcDecl = functionDeclarations.front();
    if (annotationDeclarations.size() != NUMBER_OF_ANNO_DECLARATIONS) {
        return false;
    }
    auto *newAnnoDecl = annotationDeclarations.back();
    auto *newAnnoName = impl->IdentifierName(context, impl->AnnotationDeclarationExpr(context, newAnnoDecl));
    auto *annotationUsage = GetAnnotationUsage(context, funcDecl);
    if (!IsAnnotationUsageName(context, annotationUsage, "FuncAuthor")) {
        return false;
    }
    impl->IdentifierSetName(context, annotationUsage, newAnnoName);
    return true;
}

int main(int argc, char **argv)
{
    if (argc < MIN_ARGC) {
        return 1;
    }

    impl = GetImpl();
    if (impl == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }
    auto config = impl->CreateConfig(argc - 1, argv + 1);
    auto context = impl->CreateContextFromString(config, source.data(), argv[argc - 1]);
    if (context == nullptr) {
        return NULLPTR_IMPL_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_PARSED);

    auto *ast = impl->ProgramAst(impl->ContextProgram(context));
    impl->AstNodeIterateConst(context, ast, CollectDeclarations);

    if (!ChangeAnnotationName(context)) {
        return TEST_ERROR_CODE;
    }

    if (!IsAnnotationUsageName(context, GetAnnotationUsage(context, functionDeclarations.front()), "Major")) {
        return TEST_ERROR_CODE;
    }

    impl->ProceedToState(context, ES2PANDA_STATE_BIN_GENERATED);
    if (impl->ContextState(context) == ES2PANDA_STATE_ERROR) {
        return PROCEED_ERROR_CODE;
    }
    impl->DestroyConfig(config);

    return 0;
}

// NOLINTEND
