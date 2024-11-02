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

#include "bytecode_optimizer/bytecodeopt_options.h"
#include "bytecode_optimizer/optimize_bytecode.h"
#include "compiler/compiler_logger.h"
#include "mem/arena_allocator.h"
#include "mem/pool_manager.h"
#include "es2panda.h"
#include "util/arktsconfig.h"
#include "util/generateBin.h"
#include "util/options.h"
#include "util/plugin.h"

#include <iostream>
#include <memory>
#include <optional>

namespace ark::es2panda::aot {
using mem::MemConfig;

class MemManager {
public:
    explicit MemManager()
    {
        constexpr auto COMPILER_SIZE = sizeof(size_t) <= 4 ? 2_GB : 32_GB;

        MemConfig::Initialize(0, 0, COMPILER_SIZE, 0, 0, 0);
        PoolManager::Initialize(PoolType::MMAP);
    }

    NO_COPY_SEMANTIC(MemManager);
    NO_MOVE_SEMANTIC(MemManager);

    ~MemManager()
    {
        PoolManager::Finalize();
        MemConfig::Finalize();
    }
};

static int CompileFromSource(es2panda::Compiler &compiler, es2panda::SourceFile &input, const util::Options &options)
{
    auto program = std::unique_ptr<pandasm::Program> {compiler.Compile(input, options)};
    if (program == nullptr) {
        const auto &err = compiler.GetError();

        if (err.Type() == ErrorType::INVALID) {
            if (compiler.IsAnyError()) {
                return 1;
            }
            // Intentional exit or --parse-only option usage.
            return 0;
        }

        std::cout << err.TypeString() << ": " << err.Message();
        std::cout << " ["
                  << (err.File().empty() ? util::BaseName(options.SourceFileName()) : util::BaseName(err.File())) << ":"
                  << err.Line() << ":" << err.Col() << "]" << std::endl;

        return err.ErrorCode();
    }

    return util::GenerateProgram(program.get(), options, [](std::string const &str) { std::cerr << str << std::endl; });
}

static int CompileFromConfig(es2panda::Compiler &compiler, util::Options *options)
{
    auto compilationList = FindProjectSources(options->ArkTSConfig());
    if (compilationList.empty()) {
        std::cerr << "Error: No files to compile" << std::endl;
        return 1;
    }

    unsigned overallRes = 0;
    for (auto &[src, dst] : compilationList) {
        std::ifstream inputStream(src);
        if (inputStream.fail()) {
            std::cerr << "Error: Failed to open file: " << src << std::endl;
            return 1;
        }

        std::stringstream ss;
        ss << inputStream.rdbuf();
        std::string parserInput = ss.str();
        inputStream.close();
        es2panda::SourceFile input(src, parserInput, options->IsModule());
        options->SetOutput(dst);

        options->IsListFiles() && std::cout << "> es2panda: compiling from '" << src << "' to '" << dst << "'"
                                            << std::endl;
        auto res = CompileFromSource(compiler, input, *options);
        if (res != 0) {
            std::cout << "> es2panda: failed to compile from " << src << " to " << dst << std::endl;
            overallRes |= static_cast<unsigned>(res);
        }
    }

    return overallRes;
}

static std::optional<std::vector<util::Plugin>> InitializePlugins(std::vector<std::string> const &names)
{
    std::vector<util::Plugin> res;
    for (auto &name : names) {
        auto plugin = util::Plugin(util::StringView {name});
        if (!plugin.IsOk()) {
            std::cerr << "Error: Failed to load plugin " << name << std::endl;
            return {};
        }
        plugin.Initialize();
        res.push_back(std::move(plugin));
    }
    return {std::move(res)};
}

static int Run(Span<const char *const> args)
{
    auto options = std::make_unique<util::Options>(args[0]);
    if (!options->Parse(args)) {
        std::cerr << options->ErrorMsg() << std::endl;
        return 1;
    }

    ark::Logger::ComponentMask mask {};
    mask.set(ark::Logger::Component::ES2PANDA);
    ark::Logger::InitializeStdLogging(options->LogLevel(), mask);
    auto pluginsOpt = InitializePlugins(options->GetPlugins());
    if (!pluginsOpt.has_value()) {
        return 1;
    }
    es2panda::Compiler compiler(options->GetExtension(), options->GetThread(), std::move(pluginsOpt.value()));

    if (options->IsListPhases()) {
        std::cerr << "Available phases:" << std::endl;
        std::cerr << compiler.GetPhasesList();
        return 1;
    }

    if (options->GetCompilationMode() == CompilationMode::PROJECT) {
        return CompileFromConfig(compiler, options.get());
    }

    std::string sourceFile;
    std::string_view parserInput;
    if (options->GetCompilationMode() == CompilationMode::GEN_STD_LIB) {
        sourceFile = "etsstdlib.sts";
        parserInput = "";
    } else {
        sourceFile = options->SourceFileName();
        auto [buf, size] = options->CStrParserInputContents();
        parserInput = std::string_view(buf, size);
    }
    es2panda::SourceFile input(sourceFile, parserInput, options->IsModule());
    return CompileFromSource(compiler, input, *options.get());
}
}  // namespace ark::es2panda::aot

int main(int argc, const char *argv[])
{
    ark::es2panda::aot::MemManager mm;
    return ark::es2panda::aot::Run(ark::Span<const char *const>(argv, argc));
}
