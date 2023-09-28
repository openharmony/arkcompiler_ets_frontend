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

#ifndef ES2PANDA_IR_TS_IMPORT_TYPE_H
#define ES2PANDA_IR_TS_IMPORT_TYPE_H

#include "plugins/ecmascript/es2panda/ir/typeNode.h"

namespace panda::es2panda::ir {
class TSTypeParameterInstantiation;

class TSImportType : public TypeNode {
public:
    explicit TSImportType(Expression *param, TSTypeParameterInstantiation *type_params, Expression *qualifier,
                          bool is_typeof)
        : TypeNode(AstNodeType::TS_IMPORT_TYPE),
          param_(param),
          type_params_(type_params),
          qualifier_(qualifier),
          is_typeof_(is_typeof)
    {
    }

    const Expression *Param() const
    {
        return param_;
    }

    const TSTypeParameterInstantiation *TypeParams() const
    {
        return type_params_;
    }

    const Expression *Qualifier() const
    {
        return qualifier_;
    }

    bool IsTypeof() const
    {
        return is_typeof_;
    }

    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *GetType([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Expression *param_;
    TSTypeParameterInstantiation *type_params_;
    Expression *qualifier_;
    bool is_typeof_;
};
}  // namespace panda::es2panda::ir

#endif
