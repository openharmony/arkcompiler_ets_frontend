/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "parser/program/program.h"
#include "varbinder/ETSBinder.h"
#include "ir/base/classDefinition.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsEnumDeclaration.h"
#include "ir/ts/tsInterfaceDeclaration.h"
#include "checker/types/ets/etsObjectType.h"
#include "generated/signatures.h"

namespace ark::es2panda::varbinder {
BoundContext::BoundContext(RecordTable *recordTable, ir::ClassDefinition *classDef, bool force)
    : prev_(recordTable->boundCtx_),
      recordTable_(recordTable),
      currentRecord_(classDef),
      savedRecord_(recordTable->record_)
{
    if (classDef == nullptr || (!force && !recordTable_->classDefinitions_.insert(classDef).second)) {
        return;
    }

    recordTable_->boundCtx_ = this;
    recordTable_->record_ = classDef;
    recordIdent_ = classDef->Ident();
    if (classDef->InternalName().Empty()) {
        classDef->SetInternalName(FormRecordName());
    }
}

BoundContext::BoundContext(RecordTable *recordTable, ir::TSInterfaceDeclaration *interfaceDecl, bool force)
    : prev_(recordTable->boundCtx_),
      recordTable_(recordTable),
      currentRecord_(interfaceDecl),
      savedRecord_(recordTable->record_)
{
    if (interfaceDecl == nullptr || (!force && !recordTable_->interfaceDeclarations_.insert(interfaceDecl).second)) {
        return;
    }

    recordTable_->boundCtx_ = this;
    recordTable_->record_ = interfaceDecl;
    recordIdent_ = interfaceDecl->Id();
    if (interfaceDecl->InternalName() == "") {
        interfaceDecl->SetInternalName(FormRecordName());
    }
}

BoundContext::~BoundContext()
{
    recordTable_->record_ = savedRecord_;
    recordTable_->boundCtx_ = prev_;
}

util::StringView BoundContext::FormRecordName() const
{
    if (prev_ == nullptr) {
        if (recordTable_->program_->OmitModuleName()) {
            return recordIdent_->Name();
        }

        const auto &moduleName = recordTable_->program_->ModuleName();

        // concatenate the module name with the record ident
        return util::UString(moduleName.Mutf8() + compiler::Signatures::METHOD_SEPARATOR.data() +
                                 recordIdent_->Name().Mutf8(),
                             recordTable_->program_->Allocator())
            .View();
    }

    util::UString recordName(recordTable_->program_->Allocator());
    recordName.Append(prev_->FormRecordName());
    recordName.Append(compiler::Signatures::METHOD_SEPARATOR);
    if (std::holds_alternative<ir::ClassDefinition *>(currentRecord_)) {
        const auto *classDef = std::get<ir::ClassDefinition *>(currentRecord_);
        if (classDef->IsLocal()) {
            recordName.Append(classDef->LocalPrefix());
        }
    }

    recordName.Append(recordIdent_->Name());
    return recordName.View();
}

util::StringView RecordTable::RecordName() const
{
    if (std::holds_alternative<ir::ClassDefinition *>(record_)) {
        return std::get<ir::ClassDefinition *>(record_)->InternalName();
    }

    ASSERT(std::holds_alternative<ir::TSInterfaceDeclaration *>(record_));
    return std::get<ir::TSInterfaceDeclaration *>(record_)->InternalName();
}

}  // namespace ark::es2panda::varbinder
