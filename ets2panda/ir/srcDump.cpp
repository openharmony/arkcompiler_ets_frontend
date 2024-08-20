/*
 * Copyright (c) Huawei Device Co., Ltd. 2021-2024. All rights reserved.
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

#include "srcDump.h"

#include <ir/astNode.h>

#include <cmath>
#include <iostream>

namespace ark::es2panda::ir {

SrcDumper::SrcDumper(const ir::AstNode *node)
{
    node->Dump(this);
}

void SrcDumper::IncrIndent()
{
    indent_.push_back(' ');
    indent_.push_back(' ');
}

void SrcDumper::DecrIndent()
{
    if (indent_.size() >= 2U) {
        indent_.pop_back();
        indent_.pop_back();
    }
}

void SrcDumper::Endl(size_t num)
{
    while (num != 0U) {
        ss_ << std::endl;
        --num;
    }
    ss_ << indent_;
}

void SrcDumper::Add(const std::string &str)
{
    ss_ << str;
}

void SrcDumper::Add(int32_t i)
{
    ss_ << i;
}

void SrcDumper::Add(int64_t l)
{
    ss_ << l;
}

void SrcDumper::Add(float f)
{
    ss_ << f;
}

void SrcDumper::Add(double d)
{
    ss_ << d;
}
}  // namespace ark::es2panda::ir
