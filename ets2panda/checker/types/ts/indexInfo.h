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

#ifndef ES2PANDA_COMPILER_CHECKER_TYPES_TS_INDEX_INFO_H
#define ES2PANDA_COMPILER_CHECKER_TYPES_TS_INDEX_INFO_H

#include "checker/types/type.h"

namespace panda::es2panda::checker {
class IndexInfo {
public:
    IndexInfo(Type *type, util::StringView param_name, bool readonly)
        : type_(type), param_name_(param_name), readonly_(readonly)
    {
    }

    IndexInfo(Type *type, util::StringView param_name, bool readonly, const lexer::SourcePosition &pos)
        : type_(type), param_name_(param_name), readonly_(readonly), pos_(pos)
    {
    }

    ~IndexInfo() = default;
    NO_COPY_SEMANTIC(IndexInfo);
    NO_MOVE_SEMANTIC(IndexInfo);

    Type *GetType()
    {
        return type_;
    }

    const Type *GetType() const
    {
        return type_;
    }

    void SetType(Type *type)
    {
        type_ = type;
    }

    const util::StringView &ParamName()
    {
        return param_name_;
    }

    bool Readonly() const
    {
        return readonly_;
    }

    const lexer::SourcePosition &Pos()
    {
        return pos_;
    }

    void ToString(std::stringstream &ss, bool num_index = true) const;
    void Identical(TypeRelation *relation, IndexInfo *other);
    void AssignmentTarget(TypeRelation *relation, IndexInfo *source);
    IndexInfo *Copy(ArenaAllocator *allocator, TypeRelation *relation, GlobalTypesHolder *global_types);

private:
    Type *type_;
    util::StringView param_name_;
    bool readonly_;
    const lexer::SourcePosition pos_ {};
};
}  // namespace panda::es2panda::checker

#endif /* TYPESCRIPT_TYPES_INDEX_INFO_H */
