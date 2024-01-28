/**
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CORE_SAVED_BINDINGS_CTX_H
#define ES2PANDA_COMPILER_CORE_SAVED_BINDINGS_CTX_H

#include "varbinder/varbinder.h"
#include "ir/module/importDeclaration.h"

namespace ark::es2panda::compiler {
class SavedBindingsContext {
public:
    explicit SavedBindingsContext(varbinder::VarBinder *varbinder)
        : varbinder_(varbinder), savedBindings_(varbinder_->GetScope()->Bindings())
    {
    }
    NO_COPY_SEMANTIC(SavedBindingsContext);
    NO_MOVE_SEMANTIC(SavedBindingsContext);
    ~SavedBindingsContext() = default;

protected:
    ArenaAllocator *Allocator() const
    {
        return varbinder_->Allocator();
    }

    varbinder::VarBinder *VarBinder() const
    {
        return varbinder_;
    }

    const varbinder::Scope::VariableMap &SavedBindings() const
    {
        return savedBindings_;
    }

private:
    varbinder::VarBinder *varbinder_;
    varbinder::Scope::VariableMap savedBindings_;
};

class ExportDeclarationContext : public SavedBindingsContext {
public:
    explicit ExportDeclarationContext(varbinder::VarBinder *varbinder) : SavedBindingsContext(varbinder) {}
    NO_COPY_SEMANTIC(ExportDeclarationContext);
    NO_MOVE_SEMANTIC(ExportDeclarationContext);
    ~ExportDeclarationContext() = default;

    void BindExportDecl(ir::AstNode *exportDecl);

protected:
    static constexpr std::string_view DEFAULT_EXPORT = "*default*";
};

class ImportDeclarationContext : public SavedBindingsContext {
public:
    explicit ImportDeclarationContext(varbinder::VarBinder *varbinder) : SavedBindingsContext(varbinder) {}

    NO_COPY_SEMANTIC(ImportDeclarationContext);
    NO_MOVE_SEMANTIC(ImportDeclarationContext);

    ~ImportDeclarationContext() = default;

    void BindImportDecl(ir::ImportDeclaration *importDecl);

private:
};
}  // namespace ark::es2panda::compiler

#endif
