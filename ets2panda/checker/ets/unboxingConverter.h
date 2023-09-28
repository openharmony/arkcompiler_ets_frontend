/**
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ES2PANDA_COMPILER_CHECKER_ETS_UNBOXING_CONVERTER_H
#define ES2PANDA_COMPILER_CHECKER_ETS_UNBOXING_CONVERTER_H

#include "plugins/ecmascript/es2panda/checker/ets/typeConverter.h"
#include "plugins/ecmascript/es2panda/checker/types/ets/etsObjectType.h"

namespace panda::es2panda::checker {

class UnboxingConverter : public TypeConverter {
public:
    UnboxingConverter(ETSChecker *checker, TypeRelation *relation, Type *source)
        : TypeConverter(checker, relation, nullptr, source)
    {
        if (!source->IsETSObjectType()) {
            relation->Result(false);
            return;
        }

        SetResult(GlobalTypeFromSource(source->AsETSObjectType()->BuiltInKind()));
        relation->Result(source != Result());
    }

    UnboxingConverter(ETSChecker *checker, TypeRelation *relation, Type *source, Type *target)
        : TypeConverter(checker, relation, target, source)
    {
        SetResult(Source());

        if (!Source()->IsETSObjectType() || relation->IsTrue()) {
            return;
        }

        SetResult(GlobalTypeFromSource(Source()->AsETSObjectType()->BuiltInKind()));

        Relation()->Result(Result()->TypeFlags() == target->TypeFlags());
    }

    checker::Type *GlobalTypeFromSource(ETSObjectFlags type);
};
}  // namespace panda::es2panda::checker

#endif
