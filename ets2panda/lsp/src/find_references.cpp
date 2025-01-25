/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at*
 *
 * http://www.apache.org/licenses/LICENSE-2.0*
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <utility>

#include "find_references.h"
#include "ir/astNode.h"
#include "parser/program/program.h"
#include "public/public.h"
#include "public/es2panda_lib.h"
#include "compiler/lowering/util.h"
#include "internal_api.h"

namespace {
ark::es2panda::ir::AstNode *GetIdentifier(ark::es2panda::ir::AstNode *node)
{
    if (!node->IsIdentifier()) {
        return node->FindChild([](ark::es2panda::ir::AstNode *child) { return child->IsIdentifier(); });
    }
    return node;
}

std::string GetIdentifierName(ark::es2panda::ir::AstNode *node)
{
    auto id = GetIdentifier(node);
    if (id == nullptr) {
        return "";
    }
    return std::string {id->AsIdentifier()->Name()};
}

ark::es2panda::ir::AstNode *GetOwner(ark::es2panda::ir::AstNode *node)
{
    auto id = GetIdentifier(node);
    if (id == nullptr) {
        return nullptr;
    }
    return ark::es2panda::compiler::DeclarationFromIdentifier(id->AsIdentifier());
}

// NOTE(muhammet): This may be wrong/inconsistent (slow for sure) for comparison, have to investigate
// The Type of the Node and identifier name are not enough they don't account for edge cases like
// functions with the same name and signature in different namespaces
using OwnerId = std::string;
OwnerId GetOwnerId(ark::es2panda::ir::AstNode *node, ark::es2panda::parser::Program *program)
{
    auto owner = GetOwner(node);
    if (owner == nullptr) {
        return "";
    }
    // Find which file the node belongs to
    std::string absPath;
    if (program->Ast() == owner->GetTopStatement()) {
        absPath = std::string {program->AbsoluteName()};
    }
    auto externals = program->DirectExternalSources();
    auto top = owner->GetTopStatement();
    for (const auto &entry : externals) {
        for (const auto &p : entry.second) {
            auto programAbsPath = std::string {p->AbsoluteName()};
            auto ast = p->Ast();
            if (ast == top) {
                absPath = programAbsPath;
                break;
            }
        }
    }
    // Should uniquely identify a token using it's sourceFile path, start and end positions
    auto id = absPath + ":" + std::to_string(owner->Start().index) + ":" + std::to_string(owner->Start().line) + ":" +
              std::to_string(owner->End().index) + ":" + std::to_string(owner->End().line);
    return id;
}

// Used because '<' is defined automatically for pair {Index, Line}
using Pos = std::pair<size_t, size_t>;
using PosList = std::set<Pos>;
ark::es2panda::lexer::SourcePosition ToSourcePos(Pos pos)
{
    return ark::es2panda::lexer::SourcePosition {pos.first, pos.second};
}

FileRefMap FindReferences(const ark::es2panda::SourceFile &srcFile, OwnerId tokenId, std::string tokenName)
{
    ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
    auto filePath = std::string {srcFile.filePath};
    auto fileContent = std::string {srcFile.source};
    auto context = initializer.CreateContext(filePath.c_str(), ES2PANDA_STATE_CHECKED, fileContent.c_str());

    // Clear before searching each file
    PosList posList;
    ark::es2panda::parser::Program *origin = nullptr;
    auto cb = [&posList, &tokenId, &tokenName, &origin](ark::es2panda::ir::AstNode *node) {
        auto nodeId = GetIdentifier(node);
        if (nodeId == nullptr) {
            return false;
        }
        auto nodeName = GetIdentifierName(nodeId);
        if (nodeName != tokenName) {
            return false;
        }
        auto ownerId = GetOwnerId(node, origin);
        if (ownerId == tokenId) {
            posList.insert({nodeId->Start().index, nodeId->Start().line});
        }
        return false;
    };

    // Search an ast
    auto search = [&posList, &cb](ark::es2panda::parser::Program *program) -> PositionList {
        if (program == nullptr) {
            return {};
        }
        posList.clear();
        auto ast = program->Ast();
        ast->FindChild(cb);
        PositionList res;
        for (auto pos : posList) {
            res.push_back(ToSourcePos(pos));
        }
        return res;
    };

    // Search the file
    FileRefMap res;
    auto pctx = reinterpret_cast<ark::es2panda::public_lib::Context *>(context);
    auto pprogram = pctx->parserProgram;
    {
        origin = pprogram;
        auto list = search(pprogram);
        res[std::string {pprogram->SourceFile().GetPath()}] = list;
    }

    initializer.DestroyContext(context);
    return res;
}
}  // namespace

namespace ark::es2panda::lsp {
FileRefMap FindReferences(CancellationToken *tkn, const std::vector<ark::es2panda::SourceFile> &srcFiles,
                          const ark::es2panda::SourceFile &srcFile, size_t position)
{
    std::string tokenName;
    OwnerId tokenId;
    // Part 1: Determine the type of token function/variable
    {
        ark::es2panda::lsp::Initializer initializer = ark::es2panda::lsp::Initializer();
        auto filePath = std::string {srcFile.filePath};
        auto fileContent = std::string {srcFile.source};
        auto context = initializer.CreateContext(filePath.c_str(), ES2PANDA_STATE_CHECKED, fileContent.c_str());

        auto touchingToken = GetTouchingToken(context, position, false);
        tokenName = GetIdentifierName(touchingToken);
        tokenId =
            ::GetOwnerId(touchingToken, reinterpret_cast<ark::es2panda::public_lib::Context *>(context)->parserProgram);
        initializer.DestroyContext(context);
    }

    if (tokenId.empty()) {
        return {};
    }

    std::map<std::string, PositionList> res;
    // NOTE(muhammet): The process is very wasteful, it creates a new context for each file even if they're dependent on
    // one another
    for (auto fl : srcFiles) {
        // NOTE(muhammet): Need for more fine grained cancellation check but for now doing it before context creations
        // should be good enough, thats where it's slowest
        if (tkn->IsCancellationRequested()) {
            return res;
        }
        auto posMap = ::FindReferences(fl, tokenId, tokenName);
        for (const auto &entry : posMap) {
            res.insert(entry);
        }
    }

    return res;
}
}  // namespace ark::es2panda::lsp
