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

#ifndef ES2PANDA_IR_TS_IMPORT_EQUALS_DECLARATION_H
#define ES2PANDA_IR_TS_IMPORT_EQUALS_DECLARATION_H

#include "ir/statement.h"

namespace panda::es2panda::ir {
class Expression;

class TSImportEqualsDeclaration : public Statement {
public:
    explicit TSImportEqualsDeclaration(Identifier *id, Expression *module_reference, bool is_export)
        : Statement(AstNodeType::TS_IMPORT_EQUALS_DECLARATION),
          id_(id),
          module_reference_(module_reference),
          is_export_(is_export)
    {
    }

    const Identifier *Id() const
    {
        return id_;
    }

    const Expression *ModuleReference() const
    {
        return module_reference_;
    }

    bool IsExport() const
    {
        return is_export_;
    }

    void TransformChildren(const NodeTransformer &cb) override;
    void Iterate(const NodeTraverser &cb) const override;
    void Dump(ir::AstDumper *dumper) const override;
    void Compile([[maybe_unused]] compiler::PandaGen *pg) const override;
    checker::Type *Check([[maybe_unused]] checker::TSChecker *checker) override;
    checker::Type *Check([[maybe_unused]] checker::ETSChecker *checker) override;

private:
    Identifier *id_;
    Expression *module_reference_;
    bool is_export_;
};
}  // namespace panda::es2panda::ir

#endif
