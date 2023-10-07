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

#include "tsTupleType.h"

#include "util/helpers.h"
#include "binder/scope.h"
#include "checker/TSchecker.h"
#include "checker/types/ts/indexInfo.h"
#include "ir/astDump.h"
#include "ir/expressions/identifier.h"
#include "ir/ts/tsNamedTupleMember.h"

namespace panda::es2panda::ir {
void TSTupleType::TransformChildren(const NodeTransformer &cb)
{
    for (auto *&it : element_types_) {
        it = static_cast<TypeNode *>(cb(it));
    }
}

void TSTupleType::Iterate(const NodeTraverser &cb) const
{
    for (auto *it : element_types_) {
        cb(it);
    }
}

void TSTupleType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSTupleType"}, {"elementTypes", element_types_}});
}

void TSTupleType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSTupleType::GetType(checker::TSChecker *checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    checker::ObjectDescriptor *desc = checker->Allocator()->New<checker::ObjectDescriptor>(checker->Allocator());
    checker::NamedTupleMemberPool named_members(checker->Allocator()->Adapter());
    ArenaVector<checker::ElementFlags> element_flags(checker->Allocator()->Adapter());
    checker::ElementFlags combined_flags = checker::ElementFlags::NO_OPTS;
    uint32_t min_length = 0;
    uint32_t index = 0;
    ArenaVector<checker::Type *> number_index_types(checker->Allocator()->Adapter());
    for (auto *it : element_types_) {
        util::StringView member_index = util::Helpers::ToStringView(checker->Allocator(), index);

        auto *member_var =
            binder::Scope::CreateVar(checker->Allocator(), member_index, binder::VariableFlags::PROPERTY, it);

        checker::ElementFlags member_flag = checker::ElementFlags::NO_OPTS;
        if (it->IsTSNamedTupleMember()) {
            auto *named_member = it->AsTSNamedTupleMember();
            checker::Type *member_type = named_member->ElementType()->GetType(checker);

            if (named_member->IsOptional()) {
                member_var->AddFlag(binder::VariableFlags::OPTIONAL);
                member_flag = checker::ElementFlags::OPTIONAL;
            } else {
                member_flag = checker::ElementFlags::REQUIRED;
                min_length++;
            }

            member_type->SetVariable(member_var);
            member_var->SetTsType(member_type);
            number_index_types.push_back(member_type);
            named_members.insert({member_var, named_member->Label()->AsIdentifier()->Name()});
        } else {
            checker::Type *member_type = it->GetType(checker);
            member_type->SetVariable(member_var);
            member_var->SetTsType(member_type);
            member_flag = checker::ElementFlags::REQUIRED;
            number_index_types.push_back(member_type);
            min_length++;
        }

        combined_flags |= member_flag;

        element_flags.push_back(member_flag);
        desc->properties.push_back(member_var);
        index++;
    }

    uint32_t fixed_length = desc->properties.size();

    checker::Type *number_index_type = nullptr;

    if (number_index_types.empty()) {
        number_index_type = checker->GlobalNeverType();
    } else if (number_index_types.size() == 1) {
        number_index_type = number_index_types[0];
    } else {
        number_index_type = checker->CreateUnionType(std::move(number_index_types));
    }

    desc->number_index_info = checker->Allocator()->New<checker::IndexInfo>(number_index_type, "x", false);

    SetTsType(checker->CreateTupleType(desc, std::move(element_flags), combined_flags, min_length, fixed_length, false,
                                       std::move(named_members)));
    return TsType();
}

checker::Type *TSTupleType::Check(checker::TSChecker *checker)
{
    for (auto *it : element_types_) {
        it->Check(checker);
    }

    GetType(checker);
    return nullptr;
}

checker::Type *TSTupleType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
