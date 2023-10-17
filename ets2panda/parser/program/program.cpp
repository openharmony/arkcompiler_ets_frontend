/**
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "binder/binder.h"
#include "binder/ETSBinder.h"
#include "ir/astDump.h"
#include "ir/base/classDefinition.h"
#include "ir/statements/blockStatement.h"

namespace panda::es2panda::parser {

std::string Program::Dump() const
{
    ir::AstDumper dumper {ast_, SourceCode()};
    return dumper.Str();
}

util::StringView Program::PackageClassName(util::StringView class_name)
{
    if (package_name_.Empty()) {
        return class_name;
    }

    util::UString name(package_name_, allocator_);
    name.Append('.');
    name.Append(class_name);
    return name.View();
}

binder::ClassScope *Program::GlobalClassScope()
{
    return global_class_->Scope()->AsClassScope();
}

const binder::ClassScope *Program::GlobalClassScope() const
{
    return global_class_->Scope()->AsClassScope();
}

binder::GlobalScope *Program::GlobalScope()
{
    ASSERT(ast_->Scope()->IsGlobalScope() || ast_->Scope()->IsModuleScope());
    return static_cast<binder::GlobalScope *>(ast_->Scope());
}

const binder::GlobalScope *Program::GlobalScope() const
{
    ASSERT(ast_->Scope()->IsGlobalScope() || ast_->Scope()->IsModuleScope());
    return static_cast<const binder::GlobalScope *>(ast_->Scope());
}

}  // namespace panda::es2panda::parser
