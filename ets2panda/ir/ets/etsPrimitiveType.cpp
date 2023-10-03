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

#include "etsPrimitiveType.h"

#include "ir/astDump.h"
#include "checker/TSchecker.h"
#include "checker/ETSchecker.h"
#include "compiler/core/ETSGen.h"

namespace panda::es2panda::ir {
void ETSPrimitiveType::Iterate([[maybe_unused]] const NodeTraverser &cb) const {}

void ETSPrimitiveType::Dump(ir::AstDumper *dumper) const
{
    dumper->Add({{"type", "ETSPrimitiveType"}});
}

void ETSPrimitiveType::Compile([[maybe_unused]] compiler::PandaGen *pg) const {}

void ETSPrimitiveType::Compile([[maybe_unused]] compiler::ETSGen *etsg) const
{
    UNREACHABLE();
}

checker::Type *ETSPrimitiveType::Check([[maybe_unused]] checker::TSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSPrimitiveType::GetType([[maybe_unused]] checker::TSChecker *checker)
{
    return checker->GlobalAnyType();
}

checker::Type *ETSPrimitiveType::Check([[maybe_unused]] checker::ETSChecker *checker)
{
    return nullptr;
}

checker::Type *ETSPrimitiveType::GetType([[maybe_unused]] checker::ETSChecker *checker)
{
    switch (type_) {
        case PrimitiveType::BYTE: {
            SetTsType(checker->GlobalByteType());
            return TsType();
        }
        case PrimitiveType::SHORT: {
            SetTsType(checker->GlobalShortType());
            return TsType();
        }
        case PrimitiveType::INT: {
            SetTsType(checker->GlobalIntType());
            return TsType();
        }
        case PrimitiveType::LONG: {
            SetTsType(checker->GlobalLongType());
            return TsType();
        }
        case PrimitiveType::FLOAT: {
            SetTsType(checker->GlobalFloatType());
            return TsType();
        }
        case PrimitiveType::DOUBLE: {
            SetTsType(checker->GlobalDoubleType());
            return TsType();
        }
        case PrimitiveType::BOOLEAN: {
            SetTsType(checker->GlobalETSBooleanType());
            return TsType();
        }
        case PrimitiveType::CHAR: {
            SetTsType(checker->GlobalCharType());
            return TsType();
        }
        default: {
            UNREACHABLE();
        }
    }
}
}  // namespace panda::es2panda::ir
