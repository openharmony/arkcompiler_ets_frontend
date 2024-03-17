/**
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "public/es2panda_lib.h"
#include "public/public.h"
#include "declgenEts2Ts.h"

namespace ark::es2panda::declgen_ets2ts {

static int Run(int argc, const char **argv)
{
    const auto *impl = es2panda_GetImpl(ES2PANDA_LIB_VERSION);
    auto *cfg = impl->CreateConfig(argc, argv);
    if (cfg == nullptr) {
        return 1;
    }
    auto *cfgImpl = reinterpret_cast<ark::es2panda::public_lib::ConfigImpl *>(cfg);

    es2panda_Context *ctx = impl->CreateContextFromString(cfg, cfgImpl->options->ParserInput().c_str(),
                                                          cfgImpl->options->SourceFile().c_str());

    auto *ctxImpl = reinterpret_cast<ark::es2panda::public_lib::Context *>(ctx);
    auto *checker = reinterpret_cast<checker::ETSChecker *>(ctxImpl->checker);

    impl->ProceedToState(ctx, ES2PANDA_STATE_CHECKED);

    int res = 0;
    if (!GenerateTsDeclarations(checker, ctxImpl->parserProgram, cfgImpl->options->CompilerOutput())) {
        res = 1;
    }

    impl->DestroyContext(ctx);
    impl->DestroyConfig(cfg);

    return res;
}
}  // namespace ark::es2panda::declgen_ets2ts

int main(int argc, const char **argv)
{
    return ark::es2panda::declgen_ets2ts::Run(argc, argv);
}
