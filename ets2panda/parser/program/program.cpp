/**
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "program.h"

#include "compiler/core/CFG.h"
#include "generated/signatures.h"
#include "varbinder/varbinder.h"
#include "varbinder/ETSBinder.h"
#include "ir/astDump.h"
#include "ir/base/classDefinition.h"
#include "ir/statements/blockStatement.h"

namespace ark::es2panda::parser {

Program::Program(ArenaAllocator *allocator, varbinder::VarBinder *varbinder)
    : allocator_(allocator),
      varbinder_(varbinder),
      externalSources_(allocator_->Adapter()),
      directExternalSources_(allocator_->Adapter()),
      extension_(varbinder->Extension()),
      etsnolintCollection_(allocator_->Adapter()),
      cfg_(allocator_->New<compiler::CFG>(allocator_))
{
}

std::string Program::Dump() const
{
    ir::AstDumper dumper {ast_, SourceCode()};
    return dumper.Str();
}

void Program::DumpSilent() const
{
    [[maybe_unused]] ir::AstDumper dumper {ast_, SourceCode()};
    ES2PANDA_ASSERT(!dumper.Str().empty());
}

varbinder::ClassScope *Program::GlobalClassScope()
{
    return globalClass_->Scope()->AsClassScope();
}

const varbinder::ClassScope *Program::GlobalClassScope() const
{
    return globalClass_->Scope()->AsClassScope();
}

varbinder::GlobalScope *Program::GlobalScope()
{
    ES2PANDA_ASSERT(ast_->Scope()->IsGlobalScope() || ast_->Scope()->IsModuleScope());
    return static_cast<varbinder::GlobalScope *>(ast_->Scope());
}

const varbinder::GlobalScope *Program::GlobalScope() const
{
    ES2PANDA_ASSERT(ast_->Scope()->IsGlobalScope() || ast_->Scope()->IsModuleScope());
    return static_cast<const varbinder::GlobalScope *>(ast_->Scope());
}

void Program::SetPackageInfo(const util::StringView &name, util::ModuleKind kind)
{
    moduleInfo_.moduleName = name;
    moduleInfo_.modulePrefix =
        name.Empty()
            ? ""
            : util::UString(std::string(name).append(compiler::Signatures::METHOD_SEPARATOR), allocator_).View();

    moduleInfo_.kind = kind;
}

// NOTE(vpukhov): part of ongoing design
void Program::MaybeTransformToDeclarationModule()
{
    if (IsPackage() || ast_->Statements().empty()) {
        return;
    }
    for (auto stmt : ast_->Statements()) {
        if (!(stmt->IsDeclare() || stmt->IsTSTypeAliasDeclaration())) {
            return;
        }
    }
    moduleInfo_.kind = util::ModuleKind::DECLARATION;
}

void Program::AddNodeToETSNolintCollection(const ir::AstNode *node, const std::set<ETSWarnings> &warningsCollection)
{
    ArenaSet<ETSWarnings> tmp(allocator_->Adapter());
    tmp.insert(warningsCollection.begin(), warningsCollection.end());
    etsnolintCollection_.insert({node, tmp});
}

bool Program::NodeContainsETSNolint(const ir::AstNode *node, ETSWarnings warning)
{
    auto nodeEtsnolints = etsnolintCollection_.find(node);
    if (nodeEtsnolints == etsnolintCollection_.end()) {
        return false;
    }

    return nodeEtsnolints->second.find(warning) != nodeEtsnolints->second.end();
}

Program::~Program()  // NOLINT(modernize-use-equals-default)
{
#ifndef NDEBUG
    poisonValue_ = 0;
#endif
}

compiler::CFG *Program::GetCFG()
{
    return cfg_;
}

const compiler::CFG *Program::GetCFG() const
{
    return cfg_;
}

}  // namespace ark::es2panda::parser
