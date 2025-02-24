/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "lsp/include/user_preferences.h"
#include "lsp_api_test.h"

class LspUserPrefTests : public LSPAPITests {};

TEST_F(LspUserPrefTests, UserPreferencesDefaultConstructor)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences defaultPref;

    ASSERT_EQ(defaultPref.GetQuotePreference(), UserPreferences::QuotePreference::AUTO);
    ASSERT_EQ(defaultPref.GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::AUTO);
    ASSERT_EQ(defaultPref.GetIncludeInlayParameterNameHints(), UserPreferences::IncludeInlayParameterNameHints::NONE);
    ASSERT_EQ(defaultPref.GetImportModuleSpecifierPreference(),
              UserPreferences::ImportModuleSpecifierPreference::SHORTEST);
    ASSERT_EQ(defaultPref.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::AUTO);
    ASSERT_EQ(defaultPref.GetAutoImportFileExcludePatterns(), "");
    ASSERT_EQ(defaultPref.GetDisableSuggestions(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsForModuleExports(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsForImportStatements(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsWithSnippetText(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsChainCompletions(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsWithInsertText(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsClassMemberSnippets(), false);
    ASSERT_EQ(defaultPref.GetIncludeCompletionsWithObjectLiteralMethodSnippets(), false);
    ASSERT_EQ(defaultPref.GetUseLabelDetailsIncompletionsEntries(), false);
    ASSERT_EQ(defaultPref.GetAllowIncompleteCompletions(), false);
    ASSERT_EQ(defaultPref.GetAllowTextChangesInNewFiles(), false);
    ASSERT_EQ(defaultPref.GetProvidePrefixAndSuffixTextForRename(), false);
    ASSERT_EQ(defaultPref.GetProvideRefactorNotApplicableReason(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayParameterNameHintsWhenArgumentMatchesName(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayFunctionParameterTypeHints(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayVariableTypeHints(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayVariableTypeHintsWhenTypeMatchesName(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayPropertyDeclarationTypeHints(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayFunctionLikeReturnTypeHints(), false);
    ASSERT_EQ(defaultPref.GetIncludeInlayEnumMemberValueHints(), false);
    ASSERT_EQ(defaultPref.GetAllowRenameOfImportPath(), false);
}

TEST_F(LspUserPrefTests, UserPreferencesQuotePreferenceSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    userpreferences.SetQuotePreference(UserPreferences::QuotePreference::DOUBLE);
    ASSERT_EQ(userpreferences.GetQuotePreference(), UserPreferences::QuotePreference::DOUBLE);

    userpreferences.SetQuotePreference(UserPreferences::QuotePreference::SINGLE);
    ASSERT_EQ(userpreferences.GetQuotePreference(), UserPreferences::QuotePreference::SINGLE);

    userpreferences.SetQuotePreference(UserPreferences::QuotePreference::AUTO);
    ASSERT_EQ(userpreferences.GetQuotePreference(), UserPreferences::QuotePreference::AUTO);
}

TEST_F(LspUserPrefTests, UserPreferencesIncludePackageJsonAutoImportsSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    userpreferences.SetIncludePackageJsonAutoImports(UserPreferences::IncludePackageJsonAutoImports::ON);
    ASSERT_EQ(userpreferences.GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::ON);

    userpreferences.SetIncludePackageJsonAutoImports(UserPreferences::IncludePackageJsonAutoImports::OFF);
    ASSERT_EQ(userpreferences.GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::OFF);

    userpreferences.SetIncludePackageJsonAutoImports(UserPreferences::IncludePackageJsonAutoImports::AUTO);
    ASSERT_EQ(userpreferences.GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::AUTO);
}

TEST_F(LspUserPrefTests, UserPreferencesIncludeInlayParameterNameHintsSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpref;

    userpref.SetIncludeInlayParameterNameHints(UserPreferences::IncludeInlayParameterNameHints::ALL);
    ASSERT_EQ(userpref.GetIncludeInlayParameterNameHints(), UserPreferences::IncludeInlayParameterNameHints::ALL);

    userpref.SetIncludeInlayParameterNameHints(UserPreferences::IncludeInlayParameterNameHints::LITERALS);
    ASSERT_EQ(userpref.GetIncludeInlayParameterNameHints(), UserPreferences::IncludeInlayParameterNameHints::LITERALS);
}

TEST_F(LspUserPrefTests, UserPreferencesImportModuleSpecifierPreferenceSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences usp;

    usp.SetImportModuleSpecifierPreference(UserPreferences::ImportModuleSpecifierPreference::SHORTEST);
    ASSERT_EQ(usp.GetImportModuleSpecifierPreference(), UserPreferences::ImportModuleSpecifierPreference::SHORTEST);

    usp.SetImportModuleSpecifierPreference(UserPreferences::ImportModuleSpecifierPreference::PROJECT_RELATIVE);
    ASSERT_EQ(usp.GetImportModuleSpecifierPreference(),
              UserPreferences::ImportModuleSpecifierPreference::PROJECT_RELATIVE);

    usp.SetImportModuleSpecifierPreference(UserPreferences::ImportModuleSpecifierPreference::RELATIVE);
    ASSERT_EQ(usp.GetImportModuleSpecifierPreference(), UserPreferences::ImportModuleSpecifierPreference::RELATIVE);

    usp.SetImportModuleSpecifierPreference(UserPreferences::ImportModuleSpecifierPreference::NON_RELATIVE);
    EXPECT_EQ(usp.GetImportModuleSpecifierPreference(), UserPreferences::ImportModuleSpecifierPreference::NON_RELATIVE);
}

TEST_F(LspUserPrefTests, UserPreferencesImportModuleSpecifierEndingSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    userpreferences.SetImportModuleSpecifierEnding(UserPreferences::ImportModuleSpecifierEnding::AUTO);
    ASSERT_EQ(userpreferences.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::AUTO);

    userpreferences.SetImportModuleSpecifierEnding(UserPreferences::ImportModuleSpecifierEnding::MINIMAL);
    ASSERT_EQ(userpreferences.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::MINIMAL);

    userpreferences.SetImportModuleSpecifierEnding(UserPreferences::ImportModuleSpecifierEnding::JS);
    ASSERT_EQ(userpreferences.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::JS);

    userpreferences.SetImportModuleSpecifierEnding(UserPreferences::ImportModuleSpecifierEnding::INDEX);
    ASSERT_EQ(userpreferences.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::INDEX);
}

TEST_F(LspUserPrefTests, UserPreferencesAutoImportFileExcludePatternsSetter)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    const std::string testPattern = "*.test.js,*.spec.js";
    userpreferences.SetAutoImportFileExcludePatterns(testPattern);
    ASSERT_EQ(userpreferences.GetAutoImportFileExcludePatterns(), testPattern);
}

TEST_F(LspUserPrefTests, UserPreferencesBooleanSetters)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    userpreferences.SetDisableSuggestions(true);
    ASSERT_TRUE(userpreferences.GetDisableSuggestions());
    // Reset and test false values
    userpreferences.SetDisableSuggestions(false);
    ASSERT_FALSE(userpreferences.GetDisableSuggestions());

    userpreferences.SetIncludeCompletionsForModuleExports(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsForModuleExports());

    userpreferences.SetIncludeCompletionsForModuleExports(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsForModuleExports());

    userpreferences.SetIncludeCompletionsForImportStatements(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsForImportStatements());

    userpreferences.SetIncludeCompletionsForImportStatements(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsForImportStatements());

    userpreferences.SetIncludeCompletionsWithSnippetText(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsWithSnippetText());

    userpreferences.SetIncludeCompletionsWithSnippetText(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsWithSnippetText());

    userpreferences.SetIncludeCompletionsChainCompletions(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsChainCompletions());

    userpreferences.SetIncludeCompletionsChainCompletions(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsChainCompletions());

    userpreferences.SetIncludeCompletionsWithInsertText(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsWithInsertText());

    userpreferences.SetIncludeCompletionsWithInsertText(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsWithInsertText());

    userpreferences.SetIncludeCompletionsClassMemberSnippets(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsClassMemberSnippets());

    userpreferences.SetIncludeCompletionsClassMemberSnippets(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsClassMemberSnippets());

    userpreferences.SetIncludeCompletionsWithObjectLiteralMethodSnippets(true);
    ASSERT_TRUE(userpreferences.GetIncludeCompletionsWithObjectLiteralMethodSnippets());

    userpreferences.SetIncludeCompletionsWithObjectLiteralMethodSnippets(false);
    ASSERT_FALSE(userpreferences.GetIncludeCompletionsWithObjectLiteralMethodSnippets());

    userpreferences.SetUseLabelDetailsIncompletionsEntries(true);
    ASSERT_TRUE(userpreferences.GetUseLabelDetailsIncompletionsEntries());

    userpreferences.SetUseLabelDetailsIncompletionsEntries(false);
    ASSERT_FALSE(userpreferences.GetUseLabelDetailsIncompletionsEntries());

    userpreferences.SetAllowIncompleteCompletions(true);
    ASSERT_TRUE(userpreferences.GetAllowIncompleteCompletions());

    userpreferences.SetAllowIncompleteCompletions(false);
    ASSERT_FALSE(userpreferences.GetAllowIncompleteCompletions());

    userpreferences.SetAllowTextChangesInNewFiles(true);
    ASSERT_TRUE(userpreferences.GetAllowTextChangesInNewFiles());

    userpreferences.SetAllowTextChangesInNewFiles(false);
    ASSERT_FALSE(userpreferences.GetAllowTextChangesInNewFiles());
}

TEST_F(LspUserPrefTests, UserPreferencesBooleanSetters2)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    userpreferences.SetProvidePrefixAndSuffixTextForRename(true);
    ASSERT_TRUE(userpreferences.GetProvidePrefixAndSuffixTextForRename());

    userpreferences.SetProvidePrefixAndSuffixTextForRename(false);
    ASSERT_FALSE(userpreferences.GetProvidePrefixAndSuffixTextForRename());

    userpreferences.SetProvideRefactorNotApplicableReason(true);
    ASSERT_TRUE(userpreferences.GetProvideRefactorNotApplicableReason());

    userpreferences.SetProvideRefactorNotApplicableReason(false);
    ASSERT_FALSE(userpreferences.GetProvideRefactorNotApplicableReason());

    userpreferences.SetIncludeInlayParameterNameHintsWhenArgumentMatchesName(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayParameterNameHintsWhenArgumentMatchesName());

    userpreferences.SetIncludeInlayParameterNameHintsWhenArgumentMatchesName(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayParameterNameHintsWhenArgumentMatchesName());

    userpreferences.SetIncludeInlayFunctionParameterTypeHints(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayFunctionParameterTypeHints());

    userpreferences.SetIncludeInlayFunctionParameterTypeHints(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayFunctionParameterTypeHints());

    userpreferences.SetIncludeInlayVariableTypeHints(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayVariableTypeHints());

    userpreferences.SetIncludeInlayVariableTypeHints(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayVariableTypeHints());

    userpreferences.SetIncludeInlayVariableTypeHintsWhenTypeMatchesName(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayVariableTypeHintsWhenTypeMatchesName());

    userpreferences.SetIncludeInlayVariableTypeHintsWhenTypeMatchesName(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayVariableTypeHintsWhenTypeMatchesName());

    userpreferences.SetIncludeInlayPropertyDeclarationTypeHints(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayPropertyDeclarationTypeHints());

    userpreferences.SetIncludeInlayPropertyDeclarationTypeHints(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayPropertyDeclarationTypeHints());

    userpreferences.SetIncludeInlayFunctionLikeReturnTypeHints(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayFunctionLikeReturnTypeHints());

    userpreferences.SetIncludeInlayFunctionLikeReturnTypeHints(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayFunctionLikeReturnTypeHints());

    userpreferences.SetIncludeInlayEnumMemberValueHints(true);
    ASSERT_TRUE(userpreferences.GetIncludeInlayEnumMemberValueHints());

    userpreferences.SetIncludeInlayEnumMemberValueHints(false);
    ASSERT_FALSE(userpreferences.GetIncludeInlayEnumMemberValueHints());

    userpreferences.SetAllowRenameOfImportPath(true);
    ASSERT_TRUE(userpreferences.GetAllowRenameOfImportPath());

    userpreferences.SetAllowRenameOfImportPath(false);
    ASSERT_FALSE(userpreferences.GetAllowRenameOfImportPath());
}

TEST_F(LspUserPrefTests, UserPreferencesGetDefaultUserPreferences)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences defaultPrefs = UserPreferences::GetDefaultUserPreferences();

    ASSERT_EQ(defaultPrefs.GetQuotePreference(), UserPreferences::QuotePreference::AUTO);
    ASSERT_EQ(defaultPrefs.GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::AUTO);
    ASSERT_EQ(defaultPrefs.GetIncludeInlayParameterNameHints(), UserPreferences::IncludeInlayParameterNameHints::NONE);
    ASSERT_EQ(defaultPrefs.GetImportModuleSpecifierPreference(),
              UserPreferences::ImportModuleSpecifierPreference::SHORTEST);
    ASSERT_EQ(defaultPrefs.GetImportModuleSpecifierEnding(), UserPreferences::ImportModuleSpecifierEnding::AUTO);
    ASSERT_EQ(defaultPrefs.GetAutoImportFileExcludePatterns(), "");
    ASSERT_FALSE(defaultPrefs.GetDisableSuggestions());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsForModuleExports());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsForImportStatements());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsWithSnippetText());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsChainCompletions());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsWithInsertText());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsClassMemberSnippets());
    ASSERT_FALSE(defaultPrefs.GetIncludeCompletionsWithObjectLiteralMethodSnippets());
    ASSERT_FALSE(defaultPrefs.GetUseLabelDetailsIncompletionsEntries());
    ASSERT_FALSE(defaultPrefs.GetAllowIncompleteCompletions());
    ASSERT_FALSE(defaultPrefs.GetAllowTextChangesInNewFiles());
    ASSERT_FALSE(defaultPrefs.GetProvidePrefixAndSuffixTextForRename());
    ASSERT_FALSE(defaultPrefs.GetProvideRefactorNotApplicableReason());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayParameterNameHintsWhenArgumentMatchesName());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayFunctionParameterTypeHints());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayVariableTypeHints());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayVariableTypeHintsWhenTypeMatchesName());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayPropertyDeclarationTypeHints());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayFunctionLikeReturnTypeHints());
    ASSERT_FALSE(defaultPrefs.GetIncludeInlayEnumMemberValueHints());
    ASSERT_FALSE(defaultPrefs.GetAllowRenameOfImportPath());
}

TEST_F(LspUserPrefTests, UserPreferencesGetUserPreferences)
{
    using ark::es2panda::lsp::UserPreferences;
    UserPreferences userpreferences;

    UserPreferences *currentPrefs = userpreferences.GetUserPreferences();
    ASSERT_EQ(currentPrefs, &userpreferences);

    userpreferences.SetQuotePreference(UserPreferences::QuotePreference::DOUBLE);
    userpreferences.SetIncludePackageJsonAutoImports(UserPreferences::IncludePackageJsonAutoImports::ON);
    userpreferences.SetDisableSuggestions(true);

    UserPreferences *modifiedPrefs = userpreferences.GetUserPreferences();
    ASSERT_EQ(modifiedPrefs->GetQuotePreference(), UserPreferences::QuotePreference::DOUBLE);
    ASSERT_EQ(modifiedPrefs->GetIncludePackageJsonAutoImports(), UserPreferences::IncludePackageJsonAutoImports::ON);
    ASSERT_TRUE(modifiedPrefs->GetDisableSuggestions());
}
