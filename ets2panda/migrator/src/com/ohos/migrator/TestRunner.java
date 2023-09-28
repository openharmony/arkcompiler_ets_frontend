/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

package com.ohos.migrator;

import com.ohos.migrator.util.FileUtils;

import java.io.*;
import java.util.*;

public class TestRunner {
    private static final Map<String, String> testExtensions = new HashMap<>();
    private static final Set<String> langsWithCommentsMigration = new HashSet<>();
    private static final Set<String> comparisonFailures = new HashSet<>();

    static {
        testExtensions.put("java", Main.JAVA_EXT);
        testExtensions.put("java-mapper", Main.JAVA_EXT);
        testExtensions.put("kotlin", Main.KOTLIN_EXT);
        testExtensions.put("staticTS", Main.STS_EXT);
        testExtensions.put("ts", Main.TS_EXT);

        // NOTE: Add languages here when comments
        // migration is implemented for them!
        langsWithCommentsMigration.add("java");
        langsWithCommentsMigration.add("java-mapper");
    }

    private static boolean usesOffset(String lang) {
        return !langsWithCommentsMigration.contains(lang);
    }
    public static void main(String[] args) {
        assert(args.length == 1);

        String lang = args[0];
        String ext = testExtensions.get(lang);
        File testDir = new File("test", lang);
        File testResultDir = new File(testDir, "results");
        if (testDir.exists() && testDir.isDirectory()) {
            String[] testFiles = testDir.list((dir, name) -> name.endsWith(ext));
            if (testFiles == null) {
                System.out.println("No tests to run!");
                System.exit(0);
            }

            int total = 0;
            int passed = 0;
            int failed = 0;
            int skipped = 0;
            for (String testFile : testFiles) {
                ++total;

                File skipFile = new File(testDir, testFile + ".skip");
                if (skipFile.exists()) {
                    ++skipped;
                    System.out.println("Skipping test " + testFile);
                    continue;
                }

                String testFilePath = new File(testDir, testFile).getPath();
                System.out.println("Running test " + testFile);

                List<String> mainArgs = new ArrayList<>();
                mainArgs.add("-verbose");
                mainArgs.add("-o");
                mainArgs.add(testResultDir.getPath());

                File optionsFile = new File(testDir, testFile + ".options");
                if (optionsFile.exists()) {
                    String[] options = FileUtils.readFile(optionsFile);
                    if (options != null) {
                        for (String option : options) {
                            if (option != null && !option.isEmpty() && !option.isBlank()) {
                                if (option.contains("${ant.out.dir.prop}")) {
                                    String propVal = System.getProperty("out.dir");
                                    if (propVal != null)
                                        option = option.replace("${ant.out.dir.prop}", propVal);
                                }

                                mainArgs.add(option);
                            }
                        }
                    }
                }

                mainArgs.add(testFilePath);

                Main.runTests(mainArgs.toArray(new String[0]));

                File resultFile = new File(testResultDir, testFile + Main.STS_EXT);
                File expectedFile = new File(testDir, testFile + Main.STS_EXT);

                // Set a flag if comparison fails but keep comparing to report all failures.
                if (!FileUtils.textuallyEqual(resultFile, expectedFile, usesOffset(lang))) {
                    ++failed;
                    System.err.println("Resulting and expected STS files differ for test " + testFile);
                    comparisonFailures.add(testFilePath);
                }
                else
                    ++passed;
            }

            System.out.println("SUMMARY: " + total + " total, " + passed + " passed, " + failed + " failed, " + skipped + " skipped.");
        }

        if (Main.hasErrors() || !comparisonFailures.isEmpty()) {
            // Make sure the list of failing tests appears
            // at the bottom of test run output.
            if (!comparisonFailures.isEmpty()) {
                System.err.println("\n==============");
                System.err.println("Failing tests:");
                for (String failingTestFile : comparisonFailures)
                    System.err.println(failingTestFile);
            }
            System.exit(1);
        }
     }
}
