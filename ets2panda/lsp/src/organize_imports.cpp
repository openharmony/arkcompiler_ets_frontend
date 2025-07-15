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

#include <map>
#include <set>
#include <algorithm>
#include <sstream>

#include "public/public.h"
#include "lsp/include/api.h"
#include "lsp/include/organize_imports.h"

namespace ark::es2panda::lsp {

bool IsImportUsed(es2panda_Context *ctx, const ImportSpecifier &spec)
{
    auto *context = reinterpret_cast<public_lib::Context *>(ctx);
    auto *ast = context->parserProgram->Ast();
    bool found = false;

    ast->FindChild([&](ir::AstNode *node) {
        if (node->IsETSImportDeclaration() || node->IsImportSpecifier()) {
            return false;
        }

        if (spec.type == ImportType::NAMESPACE) {
            if (node->IsTSQualifiedName()) {
                auto *qname = node->AsTSQualifiedName();
                found = qname->Left()->IsIdentifier() &&
                        (std::string(qname->Left()->AsIdentifier()->Name()) == spec.localName);
                return found;
            }

            if (node->IsMemberExpression()) {
                auto *member = node->AsMemberExpression();
                found = member->Object()->IsIdentifier() &&
                        (std::string(member->Object()->AsIdentifier()->Name()) == spec.localName);
                return found;
            }
            return false;
        }

        if (!node->IsIdentifier() || std::string(node->AsIdentifier()->Name()) != spec.localName) {
            return false;
        }

        auto *parent = node->Parent();
        bool isProperty =
            parent != nullptr && parent->IsMemberExpression() && (parent->AsMemberExpression()->Property() == node);
        bool isImportSpecifier = parent != nullptr && parent->IsImportSpecifier();
        if (!isProperty && !isImportSpecifier) {
            found = true;
            return true;
        }
        return false;
    });

    return found;
}

void ProcessImportSpecifier(ir::AstNode *spec, bool isTypeOnly, ImportInfo &info)
{
    if (!spec->IsImportSpecifier() && !spec->IsImportDefaultSpecifier() && !spec->IsImportNamespaceSpecifier()) {
        return;
    }

    ImportSpecifier specInfo {};
    ir::Identifier *local = nullptr;
    if (spec->IsImportSpecifier()) {
        auto *importSpec = spec->AsImportSpecifier();
        local = importSpec->Local();
        auto *imported = importSpec->Imported();
        specInfo.importedName = imported != nullptr ? std::string(imported->Name()) : std::string(local->Name());
        specInfo.type = isTypeOnly ? ImportType::TYPE_ONLY : ImportType::NORMAL;
    } else if (spec->IsImportDefaultSpecifier()) {
        auto *defaultSpec = spec->AsImportDefaultSpecifier();
        local = defaultSpec->Local();
        specInfo.importedName = std::string(local->Name());
        specInfo.type = ImportType::DEFAULT;
    } else {
        auto *nsSpec = spec->AsImportNamespaceSpecifier();
        local = nsSpec->Local();
        specInfo.importedName = std::string(local->Name());
        specInfo.type = ImportType::NAMESPACE;
    }

    if (local == nullptr) {
        return;
    }

    specInfo.localName = std::string(local->Name());
    specInfo.start = local->Start().index;
    specInfo.length = local->End().index - local->Start().index;

    info.namedImports.push_back(specInfo);
}

void CollectImports(es2panda_Context *context, std::vector<ImportInfo> &imports)
{
    auto *ctx = reinterpret_cast<public_lib::Context *>(context);
    if (ctx == nullptr || ctx->parserProgram == nullptr || ctx->parserProgram->Ast() == nullptr) {
        return;
    }

    std::vector<ir::AstNode *> importsNode;
    ctx->parserProgram->Ast()->Iterate([&importsNode](ir::AstNode *node) {
        if (node->IsETSImportDeclaration()) {
            importsNode.push_back(node);
        }
    });

    std::sort(importsNode.begin(), importsNode.end(),
              [](ir::AstNode *a, ir::AstNode *b) { return a->Start().index < b->Start().index; });

    for (auto *importNode : importsNode) {
        auto *importDecl = importNode->AsETSImportDeclaration();
        if (importDecl == nullptr || importDecl->Source() == nullptr) {
            continue;
        }

        auto *declInfo = static_cast<ir::ImportDeclaration *>(importNode);
        if (declInfo == nullptr) {
            continue;
        }

        ImportInfo info {};
        info.moduleName = std::string(importDecl->Source()->Str());

        bool isTypeOnly = declInfo->IsTypeKind();
        auto &specifiers = importDecl->Specifiers();

        for (auto *spec : specifiers) {
            ProcessImportSpecifier(spec, isTypeOnly, info);
        }

        info.startIndex = importDecl->Start().index;
        info.endIndex = importDecl->End().index;
        imports.push_back(std::move(info));
    }
}

void RemoveUnusedImports(std::vector<ImportInfo> &imports, es2panda_Context *ctx)
{
    for (auto &import : imports) {
        std::vector<ImportSpecifier> used;

        for (auto &namedImport : import.namedImports) {
            if (IsImportUsed(ctx, namedImport)) {
                used.push_back(namedImport);
            }
        }

        import.namedImports = used;
    }
}

std::vector<TextChange> GenerateTextChanges(const std::vector<ImportInfo> &imports)
{
    if (imports.empty()) {
        return {};
    }

    size_t start = imports.front().startIndex;
    size_t end = imports.back().endIndex;
    std::ostringstream oss;

    auto generateImportBlock = [](const ImportInfo &imp, std::ostringstream &osst, const std::string &prefix) {
        osst << prefix;
        size_t index = 0;
        for (auto &namedImport : imp.namedImports) {
            const auto &spec = namedImport;
            if (spec.importedName != spec.localName) {
                osst << spec.importedName << " as " << spec.localName;
            } else {
                osst << spec.localName;
            }
            if (index + 1 < imp.namedImports.size()) {
                osst << ", ";
            }
            index++;
        }
        osst << " } from \'" << imp.moduleName << "\';\n";
    };

    for (const auto &imp : imports) {
        if (imp.namedImports.empty()) {
            continue;
        }

        switch (imp.namedImports[0].type) {
            case ImportType::NORMAL:
                generateImportBlock(imp, oss, "import { ");
                break;
            case ImportType::DEFAULT:
                oss << "import " << imp.namedImports[0].localName << " from \'" << imp.moduleName << "\';\n";
                break;
            case ImportType::NAMESPACE:
                oss << "import * as " << imp.namedImports[0].localName << " from \'" << imp.moduleName << "\';\n";
                break;
            case ImportType::TYPE_ONLY:
                generateImportBlock(imp, oss, "import type { ");
                break;
        }
    }

    return {TextChange(TextSpan(start, end - start), oss.str())};
}

std::vector<FileTextChanges> OrganizeImports::Organize(es2panda_Context *context, const std::string &fileName)
{
    std::vector<ImportInfo> imports;

    CollectImports(context, imports);
    RemoveUnusedImports(imports, context);

    return {FileTextChanges(fileName, GenerateTextChanges(imports))};
}
}  // namespace ark::es2panda::lsp
