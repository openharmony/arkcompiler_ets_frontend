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

#include "recordTable.h"
#include "plugins/ecmascript/es2panda/parser/program/program.h"
#include "plugins/ecmascript/es2panda/binder/ETSBinder.h"
#include "plugins/ecmascript/es2panda/ir/base/classDefinition.h"
#include "plugins/ecmascript/es2panda/ir/expressions/identifier.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsEnumDeclaration.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsInterfaceDeclaration.h"
#include "generated/signatures.h"

namespace panda::es2panda::binder {
BoundContext::BoundContext(RecordTable *record_table, ir::ClassDefinition *class_def)
    : prev_(record_table->bound_ctx_), record_table_(record_table), saved_record_(record_table->record_)
{
    if (class_def == nullptr || !record_table_->class_definitions_.insert(class_def).second) {
        return;
    }

    record_table_->bound_ctx_ = this;
    record_table_->record_ = class_def;
    record_ident_ = class_def->Ident();
    class_def->SetInternalName(FormRecordName());
}

BoundContext::BoundContext(RecordTable *record_table, ir::TSInterfaceDeclaration *interface_decl)
    : prev_(record_table->bound_ctx_), record_table_(record_table), saved_record_(record_table->record_)
{
    if (interface_decl == nullptr || !record_table_->interface_declarations_.insert(interface_decl).second) {
        return;
    }

    record_table_->bound_ctx_ = this;
    record_table_->record_ = interface_decl;
    record_ident_ = interface_decl->Id();
    interface_decl->SetInternalName(FormRecordName());
}

BoundContext::~BoundContext()
{
    record_table_->record_ = saved_record_;
    record_table_->bound_ctx_ = prev_;
}

util::StringView BoundContext::FormRecordName() const
{
    const auto &package_name = record_table_->program_->GetPackageName();
    if (prev_ == nullptr) {
        if (package_name.Empty()) {
            return record_ident_->Name();
        }

        util::UString record_name(record_table_->program_->Allocator());
        record_name.Append(package_name);
        record_name.Append(compiler::Signatures::METHOD_SEPARATOR);
        record_name.Append(record_ident_->Name());
        return record_name.View();
    }

    util::UString record_name(record_table_->program_->Allocator());
    record_name.Append(prev_->FormRecordName());
    record_name.Append(compiler::Signatures::METHOD_SEPARATOR);
    record_name.Append(record_ident_->Name());
    return record_name.View();
}

util::StringView RecordTable::RecordName() const
{
    if (std::holds_alternative<ir::ClassDefinition *>(record_)) {
        return std::get<ir::ClassDefinition *>(record_)->InternalName();
    }

    ASSERT(std::holds_alternative<ir::TSInterfaceDeclaration *>(record_));
    return std::get<ir::TSInterfaceDeclaration *>(record_)->InternalName();
}

}  // namespace panda::es2panda::binder
