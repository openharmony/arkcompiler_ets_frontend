/**
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "arktsconfig.h"
#include "libpandabase/utils/json_builder.h"
#include "libpandabase/utils/json_parser.h"
#include "libpandabase/os/filesystem.h"
#include "util/language.h"
#include "generated/signatures.h"

#include <fstream>
#include <regex>
#include <sstream>
#include <system_error>

#ifndef ARKTSCONFIG_USE_FILESYSTEM
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#else
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif
#endif

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define CHECK(cond, ret, msg)                                   \
    if (!cond) {                                                \
        std::cerr << "ArkTsConfig error: " << msg << std::endl; \
        return ret;                                             \
    }

namespace panda::es2panda {

static bool IsAbsolute(const std::string &path)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    return !path.empty() && path[0] == '/';
#else
    return fs::path(path).is_absolute();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

static std::string JoinPaths(const std::string &a, const std::string &b)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    return a + '/' + b;
#else
    return (fs::path(a) / b).string();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

static std::string ParentPath(const std::string &path)
{
#ifndef ARKTSCONFIG_USE_FILESYSTEM
    auto pos = path.find('/');
    return pos == std::string::npos ? path : path.substr(0, pos);
#else
    return fs::path(path).parent_path().string();
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

static std::string MakeAbsolute(const std::string &path, const std::string &base)
{
    return IsAbsolute(path) ? path : JoinPaths(base, path);
}

#ifdef ARKTSCONFIG_USE_FILESYSTEM

ArkTsConfig::Pattern::Pattern(std::string value, std::string base) : value_(std::move(value)), base_(std::move(base))
{
    ASSERT(fs::path(base_).is_absolute());
}

bool ArkTsConfig::Pattern::IsPattern() const
{
    return (value_.find('*') != std::string::npos) || (value_.find('?') != std::string::npos);
}

std::string ArkTsConfig::Pattern::GetSearchRoot() const
{
    fs::path relative;
    if (!IsPattern()) {
        relative = value_;
    } else {
        auto found_star = value_.find_first_of('*');
        auto found_question = value_.find_first_of('?');
        relative = value_.substr(0, std::min(found_star, found_question));
        relative = relative.parent_path();
    }
    return MakeAbsolute(relative.string(), base_);
}

bool ArkTsConfig::Pattern::Match(const std::string &path) const
{
    ASSERT(fs::path(path).is_absolute());
    fs::path value = fs::path(value_);
    std::string pattern = value.is_absolute() ? value.string() : (base_ / value).string();

    // Replace arktsconfig special symbols with regular expressions
    if (IsPattern()) {
        // '**' matches any directory nested to any level
        pattern = std::regex_replace(pattern, std::regex("\\*\\*/"), ".*");
        // '*' matches zero or more characters (excluding directory separators)
        pattern = std::regex_replace(pattern, std::regex("([^\\.])\\*"), "$1[^/]*");
        // '?' matches any one character (excluding directory separators)
        pattern = std::regex_replace(pattern, std::regex("\\?"), "[^/]");
    }
    if (!value.has_extension()) {
        // default extensions to match
        pattern += R"(.*(\.ts|\.d\.ts|\.ets)$)";
    }
    std::smatch m;
    auto res = std::regex_match(path, m, std::regex(pattern));
    return res;
}

#endif  // ARKTSCONFIG_USE_FILESYSTEM

#ifdef ARKTSCONFIG_USE_FILESYSTEM
static std::string ResolveConfigLocation(const std::string &rel_path, const std::string &base)
{
    auto resolved_path = MakeAbsolute(rel_path, base);
    auto new_base = base;
    while (!fs::exists(resolved_path)) {
        resolved_path = MakeAbsolute(rel_path, JoinPaths(new_base, "node_modules"));
        if (new_base == ParentPath(new_base)) {
            return "";
        }
        new_base = ParentPath(new_base);
    }
    return resolved_path;
}
#endif  // ARKTSCONFIG_USE_FILESYSTEM

static std::string ValidDynamicLanguages()
{
    JsonArrayBuilder builder;
    for (auto &l : Language::All()) {
        if (l.IsDynamic()) {
            builder.Add(l.ToString());
        }
    }
    return std::move(builder).Build();
}

bool ArkTsConfig::Parse()
{
    static const std::string BASE_URL = "baseUrl";
    static const std::string COMPILER_OPTIONS = "compilerOptions";
    static const std::string EXCLUDE = "exclude";
    static const std::string EXTENDS = "extends";
    static const std::string FILES = "files";
    static const std::string INCLUDE = "include";
    static const std::string OUT_DIR = "outDir";
    static const std::string PATHS = "paths";
    static const std::string DYNAMIC_PATHS = "dynamicPaths";
    static const std::string ROOT_DIR = "rootDir";
    static const std::string LANGUAGE = "language";
    static const std::string HAS_DECL = "hasDecl";

    ASSERT(!is_parsed_);
    is_parsed_ = true;
    auto arkts_config_dir = ParentPath(panda::os::GetAbsolutePath(config_path_));

    // Read input
    std::ifstream input_stream(config_path_);
    CHECK(!input_stream.fail(), false, "Failed to open file: " << config_path_);
    std::stringstream ss;
    ss << input_stream.rdbuf();
    std::string ts_config_source = ss.str();
    input_stream.close();

    // Parse json
    auto arkts_config = std::make_unique<JsonObject>(ts_config_source);
    CHECK(arkts_config->IsValid(), false, "ArkTsConfig is not valid json");

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "extends"
    auto extends = arkts_config->GetValue<JsonObject::StringT>(EXTENDS);
    if (extends != nullptr) {
        auto base_path = ResolveConfigLocation(*extends, arkts_config_dir);
        CHECK(!base_path.empty(), false, "Can't resolve config path: " << *extends);
        auto base = ArkTsConfig(base_path);
        CHECK(base.Parse(), false, "Failed to parse base config: " << *extends);
        Inherit(base);
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    // Parse "baseUrl", "outDir", "rootDir"
    auto compiler_options = arkts_config->GetValue<JsonObject::JsonObjPointer>(COMPILER_OPTIONS);
    auto parse_rel_dir = [&](std::string &dst, const std::string &key) {
        if (compiler_options != nullptr) {
            auto path = compiler_options->get()->GetValue<JsonObject::StringT>(key);
            dst = ((path != nullptr) ? *path : "");
        }
        dst = MakeAbsolute(dst, arkts_config_dir);
    };
    parse_rel_dir(base_url_, BASE_URL);
    parse_rel_dir(out_dir_, OUT_DIR);
    parse_rel_dir(root_dir_, ROOT_DIR);

    // Parse "paths"
    if (compiler_options != nullptr) {
        auto paths = compiler_options->get()->GetValue<JsonObject::JsonObjPointer>(PATHS);
        if (paths != nullptr) {
            for (size_t key_idx = 0; key_idx < paths->get()->GetSize(); ++key_idx) {
                auto &key = paths->get()->GetKeyByIndex(key_idx);
                if (paths_.count(key) == 0U) {
                    paths_.insert({key, {}});
                }

                auto values = paths->get()->GetValue<JsonObject::ArrayT>(key);
                CHECK(values, false, "Invalid value for 'path' with key '" << key << "'");
                CHECK(!values->empty(), false, "Substitutions for pattern '" << key << "' shouldn't be an empty array");
                for (auto &v : *values) {
                    auto p = *v.Get<JsonObject::StringT>();
                    paths_[key].emplace_back(MakeAbsolute(p, base_url_));
                }
            }
        }

        auto dynamic_paths = compiler_options->get()->GetValue<JsonObject::JsonObjPointer>(DYNAMIC_PATHS);
        if (dynamic_paths != nullptr) {
            for (size_t key_idx = 0; key_idx < dynamic_paths->get()->GetSize(); ++key_idx) {
                auto &key = dynamic_paths->get()->GetKeyByIndex(key_idx);
                auto data = dynamic_paths->get()->GetValue<JsonObject::JsonObjPointer>(key);
                CHECK(data, false, "Invalid value for for dynamic path with key '" << key << "'");

                auto lang_value = data->get()->GetValue<JsonObject::StringT>(LANGUAGE);
                CHECK(lang_value, false, "Invalid 'language' value for dynamic path with key '" << key << "'");

                auto lang = Language::FromString(*lang_value);
                CHECK((lang && lang->IsDynamic()), false,
                      "Invalid 'language' value for dynamic path with key '" << key << "'. Should be one of "
                                                                             << ValidDynamicLanguages());

                CHECK(compiler::Signatures::Dynamic::IsSupported(*lang), false,
                      "Interoperability with language '" << lang->ToString() << "' is not supported");

                auto has_decl_value = data->get()->GetValue<JsonObject::BoolT>(HAS_DECL);
                CHECK(has_decl_value, false, "Invalid 'hasDecl' value for dynamic path with key '" << key << "'");

                auto res = dynamic_paths_.insert({key, DynamicImportData(*lang, *has_decl_value)});
                CHECK(res.second, false, "Duplicated dynamic path '" << key << "' for key '" << key << "'");
            }
        }
    }

    // Parse "files"
    auto files = arkts_config->GetValue<JsonObject::ArrayT>(FILES);
    if (files != nullptr) {
        files_ = {};
        CHECK(!files->empty(), false, "The 'files' list in config file is empty");
        for (auto &f : *files) {
            files_.emplace_back(MakeAbsolute(*f.Get<JsonObject::StringT>(), arkts_config_dir));
        }
    }

#ifdef ARKTSCONFIG_USE_FILESYSTEM
    // Parse "include"
    auto include = arkts_config->GetValue<JsonObject::ArrayT>(INCLUDE);
    if (include != nullptr) {
        include_ = {};
        CHECK(!include->empty(), false, "The 'include' list in config file is empty");
        for (auto &i : *include) {
            include_.emplace_back(*i.Get<JsonObject::StringT>(), arkts_config_dir);
        }
    }
    // Parse "exclude"
    auto exclude = arkts_config->GetValue<JsonObject::ArrayT>(EXCLUDE);
    if (exclude != nullptr) {
        exclude_ = {};
        CHECK(!exclude->empty(), false, "The 'exclude' list in config file is empty");
        for (auto &e : *exclude) {
            exclude_.emplace_back(*e.Get<JsonObject::StringT>(), arkts_config_dir);
        }
    }
#endif  // ARKTSCONFIG_USE_FILESYSTEM

    return true;
}

void ArkTsConfig::Inherit(const ArkTsConfig &base)
{
    base_url_ = base.base_url_;
    out_dir_ = base.out_dir_;
    root_dir_ = base.root_dir_;
    paths_ = base.paths_;
    files_ = base.files_;
#ifdef ARKTSCONFIG_USE_FILESYSTEM
    include_ = base.include_;
    exclude_ = base.exclude_;
#endif  // ARKTSCONFIG_USE_FILESYSTEM
}

#ifdef ARKTSCONFIG_USE_FILESYSTEM
static bool MatchExcludes(const fs::path &path, const std::vector<ArkTsConfig::Pattern> &excludes)
{
    for (auto &e : excludes) {
        if (e.Match(path.string())) {
            return true;
        }
    }
    return false;
}

static std::vector<fs::path> GetSourceList(const std::shared_ptr<ArkTsConfig> &arkts_config)
{
    auto includes = arkts_config->Include();
    auto excludes = arkts_config->Exclude();
    auto files = arkts_config->Files();

    // If "files" and "includes" are empty - include everything from tsconfig root
    auto config_dir = fs::absolute(fs::path(arkts_config->ConfigPath())).parent_path();
    if (files.empty() && includes.empty()) {
        includes = {ArkTsConfig::Pattern("**/*", config_dir.string())};
    }
    // If outDir in not default add it into exclude
    if (!fs::equivalent(arkts_config->OutDir(), config_dir)) {
        excludes.emplace_back("**/*", arkts_config->OutDir());
    }

    // Collect "files"
    std::vector<fs::path> source_list;
    for (auto &f : files) {
        CHECK(fs::exists(f) && fs::path(f).has_filename(), {}, "No such file: " << f);
        source_list.emplace_back(f);
    }

    // Collect "include"
    // TSC traverses folders for sources starting from 'include' rather than from 'rootDir', so we do the same
    for (auto &include : includes) {
        auto traverse_root = fs::path(include.GetSearchRoot());
        if (!fs::exists(traverse_root)) {
            continue;
        }
        if (!fs::is_directory(traverse_root)) {
            if (include.Match(traverse_root.string()) && !MatchExcludes(traverse_root, excludes)) {
                source_list.emplace_back(traverse_root);
            }
            continue;
        }
        for (const auto &dir_entry : fs::recursive_directory_iterator(traverse_root)) {
            if (include.Match(dir_entry.path().string()) && !MatchExcludes(dir_entry, excludes)) {
                source_list.emplace_back(dir_entry);
            }
        }
    }
    return source_list;
}

// Analogue of 'std::filesystem::relative()'
// Example: Relative("/a/b/c", "/a/b") returns "c"
static fs::path Relative(const fs::path &src, const fs::path &base)
{
    fs::path tmp_path = src;
    fs::path rel_path;
    while (!fs::equivalent(tmp_path, base)) {
        rel_path = rel_path.empty() ? tmp_path.filename() : tmp_path.filename() / rel_path;
        if (tmp_path == tmp_path.parent_path()) {
            return fs::path();
        }
        tmp_path = tmp_path.parent_path();
    }
    return rel_path;
}

// Compute path to destination file and create subfolders
static fs::path ComputeDestination(const fs::path &src, const fs::path &root_dir, const fs::path &out_dir)
{
    auto rel = Relative(src, root_dir);
    CHECK(!rel.empty(), {}, root_dir << " is not root directory for " << src);
    auto dst = out_dir / rel;
    fs::create_directories(dst.parent_path());
    return dst.replace_extension("abc");
}

std::vector<std::pair<std::string, std::string>> FindProjectSources(const std::shared_ptr<ArkTsConfig> &arkts_config)
{
    auto source_files = GetSourceList(arkts_config);
    std::vector<std::pair<std::string, std::string>> compilation_list;
    for (auto &src : source_files) {
        auto dst = ComputeDestination(src, arkts_config->RootDir(), arkts_config->OutDir());
        CHECK(!dst.empty(), {}, "Invalid destination file");
        compilation_list.emplace_back(src.string(), dst.string());
    }

    return compilation_list;
}
#else
std::vector<std::pair<std::string, std::string>> FindProjectSources(
    [[maybe_unused]] const std::shared_ptr<ArkTsConfig> &arkts_config)
{
    ASSERT(false);
    return {};
}
#endif  // ARKTSCONFIG_USE_FILESYSTEM

}  // namespace panda::es2panda
