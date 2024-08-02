/*
 * Copyright (c) 2023 - 2024 Huawei Device Co., Ltd.
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

bool TopLevelStatements::Perform(public_lib::Context *ctx, parser::Program *program)
{
    GlobalClassHandler globalClass(program->Allocator());
    auto imports = ImportExportDecls(program->VarBinder()->AsETSBinder(), ctx->parser->AsETSParser());
    imports.ParseDefaultSources();
    auto extSrcs = program->ExternalSources();
    for (auto &[package, extPrograms] : extSrcs) {
        auto triggeringCCtorMethodsAndPrograms = imports.HandleGlobalStmts(extPrograms, &globalClass);
        globalClass.InitGlobalClass(extPrograms, &triggeringCCtorMethodsAndPrograms);
    }

    ArenaVector<parser::Program *> mainModule(program->Allocator()->Adapter());
    mainModule.emplace_back(program);
    auto triggeringCCtorMethodsAndPrograms = imports.HandleGlobalStmts(mainModule, &globalClass);
    globalClass.InitGlobalClass(mainModule, &triggeringCCtorMethodsAndPrograms);
    return true;
}

}  // namespace ark::es2panda::compiler
