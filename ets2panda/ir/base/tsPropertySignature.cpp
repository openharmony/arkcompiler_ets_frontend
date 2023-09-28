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

#include "tsPropertySignature.h"

#include "plugins/ecmascript/es2panda/ir/astDump.h"
#include "plugins/ecmascript/es2panda/ir/typeNode.h"

#include "plugins/ecmascript/es2panda/checker/TSchecker.h"

namespace panda::es2panda::ir {
void TSPropertySignature::Iterate(const NodeTraverser &cb) const
{
    cb(key_);

    if (TypeAnnotation() != nullptr) {
        cb(TypeAnnotation());
    }
}

void TSPropertySignature::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "TSPropertySignature"},
                 {"computed", computed_},
                 {"optional", optional_},
                 {"readonly", readonly_},
                 {"key", key_},
                 {"typeAnnotation", AstDumper::Optional(TypeAnnotation())}});
}

void TSPropertySignature::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

checker::Type *TSPropertySignature::Check([[maybe_unused]] checker::TSChecker *checker)
{
    if (TypeAnnotation() != nullptr) {
        TypeAnnotation()->Check(checker);
    }

    if (computed_) {
        checker->CheckComputedPropertyName(key_);
    }

    if (TypeAnnotation() != nullptr) {
        Variable()->SetTsType(TypeAnnotation()->GetType(checker));
        return nullptr;
    }

    checker->ThrowTypeError("Property implicitly has an 'any' type.", Start());
    return nullptr;
}

checker::Type *TSPropertySignature::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}
}  // namespace panda::es2panda::ir
