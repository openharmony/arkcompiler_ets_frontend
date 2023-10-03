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

#ifndef ES2PANDA_CHECKER_TS_TYPE_ELABORATION_CONTEXT_H
#define ES2PANDA_CHECKER_TS_TYPE_ELABORATION_CONTEXT_H

#include "checker/TSchecker.h"
#include "ir/expression.h"

#include <macros.h>

namespace panda::es2panda::ir {
class Expression;
class SpreadElement;
}  // namespace panda::es2panda::ir

namespace panda::es2panda::checker {
class Type;

class ElaborationContext {
public:
    ElaborationContext(TSChecker *checker, Type *target_type, Type *source_type, ir::Expression *source_node,
                       const lexer::SourcePosition &start_pos)
        : checker_(checker),
          target_type_(target_type),
          source_type_(source_type),
          source_node_(source_node),
          start_pos_(start_pos),
          potential_types_(checker->Allocator()->Adapter())
    {
    }

    virtual void Start() = 0;
    virtual void RemoveUnnecessaryTypes() = 0;

    Type *GetBestMatchingType(Type *index_type, ir::Expression *source_node);

protected:
    // NOLINTBEGIN(misc-non-private-member-variables-in-classes)
    TSChecker *checker_;
    Type *target_type_;
    Type *source_type_;
    ir::Expression *source_node_;
    const lexer::SourcePosition start_pos_;
    ArenaVector<Type *> potential_types_;
    // NOLINTEND(misc-non-private-member-variables-in-classes)
};

class ArrayElaborationContext : public ElaborationContext {
public:
    ArrayElaborationContext(TSChecker *checker, Type *target_type, Type *source_type, ir::Expression *source_node,
                            const lexer::SourcePosition &start_pos)
        : ElaborationContext(checker, target_type, source_type, source_node, start_pos)
    {
    }

    void Start() override;
    void RemoveUnnecessaryTypes() override;

private:
    uint32_t index_ {0};
};

class ObjectElaborationContext : public ElaborationContext {
public:
    ObjectElaborationContext(TSChecker *checker, Type *target_type, Type *source_type, ir::Expression *source_node,
                             const lexer::SourcePosition &start_pos)
        : ElaborationContext(checker, target_type, source_type, source_node, start_pos)
    {
    }

    void Start() override;
    void RemoveUnnecessaryTypes() override;
};
}  // namespace panda::es2panda::checker

#endif
