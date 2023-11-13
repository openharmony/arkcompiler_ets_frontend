/**
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "etsTuple.h"

#include "checker/ETSchecker.h"
#include "checker/types/ets/etsTupleType.h"
#include "ir/astDump.h"

namespace panda::es2panda::ir {

void ETSTuple::TransformChildren([[maybe_unused]] const NodeTransformer &cb)
{
    for (auto *&it : GetTupleTypeAnnotationsList()) {
        it = static_cast<TypeNode *>(cb(it));
    }

    if (HasSpreadType()) {
        cb(spread_type_);
    }
}

void ETSTuple::Iterate([[maybe_unused]] const NodeTraverser &cb) const
{
    for (auto *const it : GetTupleTypeAnnotationsList()) {
        cb(it);
    }

    if (HasSpreadType()) {
        cb(spread_type_);
    }
}

void ETSTuple::Dump(ir::AstDumper *const dumper) const
{
    dumper->Add({{"type", "ETSTuple"},
                 {"types", AstDumper::Optional(type_annotation_list_)},
                 {"spreadType", AstDumper::Nullish(spread_type_)}});
}

void ETSTuple::Dump(ir::SrcDumper *const dumper) const
{
    dumper->Add("[");
    for (auto type_annot : type_annotation_list_) {
        type_annot->Dump(dumper);
        if (type_annot != type_annotation_list_.back() || spread_type_ != nullptr) {
            dumper->Add(", ");
        }
    }
    if (spread_type_ != nullptr) {
        dumper->Add("...");
        spread_type_->Dump(dumper);
    }
    dumper->Add(("]"));
}

void ETSTuple::Compile([[maybe_unused]] compiler::PandaGen *const pg) const {}
void ETSTuple::Compile([[maybe_unused]] compiler::ETSGen *const etsg) const {}

checker::Type *ETSTuple::Check([[maybe_unused]] checker::TSChecker *const checker)
{
    return nullptr;
}

checker::Type *ETSTuple::Check([[maybe_unused]] checker::ETSChecker *const checker)
{
    return GetType(checker);
}

checker::Type *ETSTuple::CalculateLUBForTuple(checker::ETSChecker *const checker,
                                              ArenaVector<checker::Type *> &type_list, checker::Type *const spread_type)
{
    if (type_list.empty()) {
        return spread_type == nullptr ? checker->GlobalETSObjectType() : spread_type;
    }

    bool all_elements_are_same = std::all_of(type_list.begin(), type_list.end(), [&checker, &type_list](auto *element) {
        return checker->Relation()->IsIdenticalTo(type_list[0], element);
    });

    if (spread_type != nullptr) {
        all_elements_are_same = all_elements_are_same && checker->Relation()->IsIdenticalTo(type_list[0], spread_type);
    }

    // If only one type present in the tuple, that will be the holder array type. If any two not identical types
    // present, primitives will be boxed, and LUB is calculated for all of them.
    // That makes it possible to assign eg. `[int, int, ...int[]]` tuple type to `int[]` array type. Because a `short[]`
    // array already isn't assignable to `int[]` array, that preserve that the `[int, short, ...int[]]` tuple type's
    // element type will be calculated to `Object[]`, which is not assignable to `int[]` array either.
    if (all_elements_are_same) {
        return type_list[0];
    }

    auto *const saved_relation_node = checker->Relation()->GetNode();
    checker->Relation()->SetNode(this);

    auto get_boxed_type_or_type = [&checker](checker::Type *const type) {
        auto *const boxed_type = checker->PrimitiveTypeAsETSBuiltinType(type);
        return boxed_type == nullptr ? type : boxed_type;
    };

    checker::Type *lub_type = get_boxed_type_or_type(type_list[0]);

    for (std::size_t idx = 1; idx < type_list.size(); ++idx) {
        lub_type = checker->FindLeastUpperBound(lub_type, get_boxed_type_or_type(type_list[idx]));
    }

    if (spread_type != nullptr) {
        lub_type = checker->FindLeastUpperBound(lub_type, get_boxed_type_or_type(spread_type));
    }

    checker->Relation()->SetNode(saved_relation_node);

    return lub_type;
}

checker::Type *ETSTuple::GetType(checker::ETSChecker *const checker)
{
    if (TsType() != nullptr) {
        return TsType();
    }

    ArenaVector<checker::Type *> type_list(checker->Allocator()->Adapter());

    for (auto *const type_annotation : GetTupleTypeAnnotationsList()) {
        auto *const checked_type = checker->GetTypeFromTypeAnnotation(type_annotation);
        type_list.emplace_back(checked_type);
    }

    if (HasSpreadType()) {
        ASSERT(spread_type_->IsTSArrayType());
        auto *const array_type = spread_type_->GetType(checker);
        ASSERT(array_type->IsETSArrayType());
        spread_type_->SetTsType(array_type->AsETSArrayType()->ElementType());
    }

    auto *const spread_element_type = spread_type_ != nullptr ? spread_type_->TsType() : nullptr;

    auto *const tuple_type = checker->Allocator()->New<checker::ETSTupleType>(
        type_list, CalculateLUBForTuple(checker, type_list, spread_element_type), spread_element_type);

    SetTsType(tuple_type);
    return TsType();
}

}  // namespace panda::es2panda::ir
