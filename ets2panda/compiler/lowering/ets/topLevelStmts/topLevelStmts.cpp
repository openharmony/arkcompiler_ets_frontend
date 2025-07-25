/*
 * Copyright (c) 2023 - 2025 Huawei Device Co., Ltd.
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

#include "compiler/lowering/ets/topLevelStmts/topLevelStmts.h"

#include "compiler/lowering/ets/topLevelStmts/globalClassHandler.h"

namespace ark::es2panda::compiler {

static bool CheckSourceConsistency(util::StringView name, ArenaVector<parser::Program *> const &programs)
{
    if (programs.size() == 1) {
        return true;
    }
    if (std::all_of(programs.begin(), programs.end(), [](auto p) { return p->IsPackage(); })) {
        return true;
    }
    std::stringstream ss;
    ss << "Module name \"" << name << "\" is assigned to multiple compilation units:";
    std::for_each(programs.begin(), programs.end(), [&ss](parser::Program *p) {
        ss << std::endl << "  at " << p->SourceFilePath().Mutf8();
    });
    std::cerr << ss.str() << std::endl;
    return false;
}

static bool CheckProgramSourcesConsistency(parser::Program *program)
{
    bool success = true;
    for (auto const &[name, programs] : program->ExternalSources()) {
        success &= CheckSourceConsistency(name, programs);
    }
    for (auto const &[name, programs] : program->DirectExternalSources()) {
        success &= CheckSourceConsistency(name, programs);
    }
    return success;
}

static void CheckFileHeaderFlag(parser::Program *program)
{
    auto &statements = program->Ast()->Statements();
    if (statements.empty()) {
        return;
    }

    if (!statements.front()->IsExpressionStatement()) {
        return;
    }

    // If further processing based on "use static" is required later, such as throwing a warning or modifying the node,
    // perform the operation here.
    auto *expansion = statements.front()->AsExpressionStatement()->GetExpression();
    if (expansion->IsStringLiteral() && expansion->AsStringLiteral()->Str() == Signatures::STATIC_PROGRAM_FLAG) {
        statements.erase(statements.begin());
        return;
    }
}

bool TopLevelStatements::Perform(public_lib::Context *ctx, parser::Program *program)
{
    CheckFileHeaderFlag(program);
    auto imports = ImportExportDecls(program->VarBinder()->AsETSBinder(), ctx->parser->AsETSParser());
    imports.ParseDefaultSources();
    if (!CheckProgramSourcesConsistency(program)) {
        // NOTE(vpukhov): enforce compilation failure
    }

    GlobalClassHandler globalClass(ctx->parser->AsETSParser(), ctx->Allocator());
    for (auto &[package, extPrograms] : program->ExternalSources()) {
        auto moduleDependencies = imports.HandleGlobalStmts(extPrograms);
        globalClass.SetupGlobalClass(extPrograms, &moduleDependencies);
    }

    ArenaVector<parser::Program *> mainModule(ctx->Allocator()->Adapter());
    mainModule.emplace_back(program);
    auto moduleDependencies = imports.HandleGlobalStmts(mainModule);
    globalClass.SetupGlobalClass(mainModule, &moduleDependencies);
    return true;
}

}  // namespace ark::es2panda::compiler
