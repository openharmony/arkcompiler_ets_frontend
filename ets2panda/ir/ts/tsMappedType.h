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

#ifndef ES2PANDA_IR_TS_MAPPED_TYPE_H
#define ES2PANDA_IR_TS_MAPPED_TYPE_H

#include "plugins/ecmascript/es2panda/ir/typeNode.h"
#include "plugins/ecmascript/es2panda/ir/ts/tsTypeParameter.h"

namespace panda::es2panda::ir {
class TSMappedType : public TypeNode {
public:
    explicit TSMappedType(TSTypeParameter *type_parameter, TypeNode *type_annotation, MappedOption readonly,
                          MappedOption optional)
        : TypeNode(AstNodeType::TS_MAPPED_TYPE),
          type_parameter_(type_parameter),
          type_annotation_(type_annotation),
          readonly_(readonly),
          optional_(optional)
    {
    }

    TSTypeParameter *TypeParameter()
    {
        return type_parameter_;
    }

    TypeNode *TypeAnnotation()
    {
        return type_annotation_;
    }

    MappedOption Readonly()
    {
        return readonly_;
    }

    MappedOption Optional()
    {
        return optional_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    TSTypeParameter *type_parameter_;
    TypeNode *type_annotation_;
    MappedOption readonly_;
    MappedOption optional_;
};
}  // namespace panda::es2panda::ir

#endif
