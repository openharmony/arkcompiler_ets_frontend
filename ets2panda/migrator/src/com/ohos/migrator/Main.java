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

import com.ohos.migrator.java.JavaTranspiler;
import com.ohos.migrator.kotlin.KotlinTranspiler;
import com.ohos.migrator.staticTS.StaticTSSyntaxChecker;
import com.ohos.migrator.ts.TSTranspiler;
import org.apache.commons.cli.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class Main {
    static final String TOOL_NAME = "migrator";
    static final String VERSION_STRING = "version 1.0";
    static final String OPTION_VALUE_SEPARATOR = ",";
    static final String JAVA_EXT = ".java";
    static final String KOTLIN_EXT = ".kt";
    static final String LIB_EXT = ".jar";
    static final String STS_EXT = ".sts";
    static final String TS_EXT = ".ts";
    static List<TranspileException> errorList = new ArrayList<>();
    static boolean verboseMode = false;
    static boolean strictMode = false;

    static boolean convRateMode = false;
    public static void finish(ResultCode exitCode) {
        if (verboseMode) {
            for (TranspileException e: errorList) {
                String errorName = e.getResult().getErrorName();
                System.err.print("[" + errorName + "] ");

                if (e.getCause() != null) {
                    String message = e.getCause().getMessage();
                    if (message != null && !message.isEmpty())
                        System.err.println(message);

                    e.getCause().printStackTrace();
                }
                else
                    System.err.println(e.getMessage());
            }
        }

        if (!runningTests) 
            System.exit(exitCode.value);
	
        errorList = new ArrayList<>();
    }

    private static boolean runningTests = false;
    public static void runTests(String[] args) {
        runningTests = true;
        main(args);
    }

    public static boolean isVerboseMode() { return verboseMode; }
    public static boolean isStrictMode() { return strictMode; }

    public static boolean isConvRateMode() { return convRateMode; }
    public static boolean hasErrors() { return !errorList.isEmpty(); }

    public static void addError(ResultCode code, String message) {
        errorList.add(new TranspileException(code, message));
    }
    public static void main(String[] args) {
        final Options options = new Options();

        try {
            options.addOption(new Option("?","help",false,"Prints this help message"));

            options.addOption(new Option("o","outdir",true,"Specify where to place generated source files"));
            options.addOption(new Option("nowarn","nowarn",false,"Generate no warnings"));
            options.addOption(new Option("Werror","Werror",false,"Treate warnings as errors"));
            options.addOption(new Option("s","strict",false,"Terminate transpile process after first error occurs"));
            options.addOption(new Option("l","libs",true, "List of libraries separate with commas"));
            options.addOption(new Option("T","check-sts-syntax",false,"Check syntactical correctness of StaticTS sources"));
            options.addOption(new Option("R", "conversion-rate", false, "Report conversion rate"));
            options.addOption(new Option("noxrefs", "noxrefs", false, "Don't resolve cross-references in the input source files"));
            options.addOption(new Option("verbose","verbose",false,"Report extended diagnostic info"));
            options.addOption(new Option("k", "keep-temp-files", false, "Keep temporary files created by migrator"));
            options.addOption(new Option("v","version",false,"Version information"));

            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("?")) {
                new HelpFormatter().printHelp(400, TOOL_NAME + " <options> <source files>", "OPTIONS", options, "Translates Java and Kotlin sources into StaticTS", false);
                finish(ResultCode.OK);
            }

            if (cmd.hasOption("v")) {
                System.out.println(TOOL_NAME + " " + VERSION_STRING);
                finish(ResultCode.OK);
            }

            if (cmd.hasOption("verbose")) verboseMode = true;
            if (cmd.hasOption("strict")) strictMode = true;
            if (cmd.hasOption("conversion-rate")) convRateMode = true;

            String outDir = null;
            if (cmd.hasOption("o")) {
                outDir = cmd.getOptionValue("o");
                try {
                    Path outDirPath = Paths.get(outDir);
                    if (!Files.exists(outDirPath)) Files.createDirectories(outDirPath);
                }
                catch (IOException ioe) {
                    System.err.println("[warning] Failed to create output directory " + outDir + ", ignoring.");
                    outDir = null;
                }
            }

            boolean needStsSyntaxCheck = cmd.hasOption("check-sts-syntax");

            List<String> sourceFileNames = cmd.getArgList();

            if (sourceFileNames.isEmpty()) {
                System.err.println("No source files provided");
                finish(ResultCode.InputError);
            }

            List<File> javaSources = new ArrayList<>();
            List<File> kotlinSources = new ArrayList<>();
            List<File> stsSources = new ArrayList<>();
            List<File> tsSources = new ArrayList<>();

            // fill sources lists
            for (String s : sourceFileNames) {
                File f = new File(s);
                if(!f.exists() || !f.isFile()) {
                    System.err.println("Source file " + f + " doesn't exists or is not a file");
                    continue;
                }

                String fileName = f.getName().toLowerCase();
                if (fileName.endsWith(JAVA_EXT)) {
                    javaSources.add(f);
                }
                else if (fileName.endsWith(KOTLIN_EXT)) {
                    kotlinSources.add(f);
                }
                else if (fileName.endsWith(STS_EXT)) {
                    stsSources.add(f);
                }
                else if (fileName.endsWith(TS_EXT)) {
                    tsSources.add(f);
                }
                else {
                    System.err.println("Source file " + f + " is not supported");
                }
            }

            if (needStsSyntaxCheck && !stsSources.isEmpty()) {
                ResultCode code = checkSTSSyntax(stsSources);
                finish(code);
            }

            List<File> jarLibs = new ArrayList<>();

            if (cmd.hasOption("l")) {
                String[] libArgNames = cmd.getOptionValues("libs");

                for (String libs : libArgNames) {
                    for (String libPath : libs.split(OPTION_VALUE_SEPARATOR)) {
                        // -l option requires arg, so libsStr can't be empty,
                        // but its elements (libName) can well be.
                        if (!libPath.isEmpty()) {
                            File f = new File(libPath);
                            if (!f.exists() || !f.isFile()) {
                                System.err.println("Library " + f + " doesn't exists or is not a file");
                            }
                            else if (f.getName().toLowerCase().endsWith(LIB_EXT)) {
                                jarLibs.add(f);
                            } else {
                                System.err.println("Library " + f + "is not supported");
                            }
                        }
                    }
                }
            }

            ResultCode resultCode = ResultCode.OK;
            List<File> outFiles = new LinkedList<>();

            double convRate = 0.;
            int numLanguages = 0;
            boolean noxrefs = cmd.hasOption("noxrefs");

            if (!javaSources.isEmpty()) {
                System.out.println("Transpiling " + javaSources.size() + " Java files.");

                JavaTranspiler javaTranspiler = new JavaTranspiler(javaSources, jarLibs, outDir, noxrefs);
                resultCode = javaTranspiler.transpile();
                outFiles.addAll(javaTranspiler.getOutFiles());
                errorList.addAll(javaTranspiler.getErrorList());

                if (convRateMode) convRate += javaTranspiler.getConversionRate();
                ++numLanguages;
            }

            // TODO: In future, the logic here will need to be extended to support Kotlin-Java interop.
            if (!kotlinSources.isEmpty()) {
                System.out.println("Transpiling " + kotlinSources.size() + " Kotlin files.");

                KotlinTranspiler kotlinTranspiler = new KotlinTranspiler(kotlinSources, jarLibs, outDir);
                resultCode = ResultCode.majorValue(kotlinTranspiler.transpile(), resultCode);
                outFiles.addAll(kotlinTranspiler.getOutFiles());
                errorList.addAll(kotlinTranspiler.getErrorList());

                if (convRateMode) convRate += kotlinTranspiler.getConversionRate();
                ++numLanguages;
            }

            if (!tsSources.isEmpty()) {
                System.out.println("Transpiling " + tsSources.size() + " TypeScript files.");

                TSTranspiler tsTranspiler = new TSTranspiler(tsSources, outDir, cmd.hasOption("k"));
                resultCode = ResultCode.majorValue(tsTranspiler.transpile(), resultCode);
                outFiles.addAll(tsTranspiler.getOutFiles());
                errorList.addAll(tsTranspiler.getErrorList());

                if (convRateMode) convRate += tsTranspiler.getConversionRate();
                ++numLanguages;
            }

            if (resultCode == ResultCode.OK) System.out.println("Transpilation OK.");

            if (convRateMode) {
                if (numLanguages > 0) convRate /= numLanguages;
                System.out.println("Conversion rate: " + String.format("%.1f", convRate) + "%");
            }

            // Check syntax of all STS files produced.
            // NOTE: This is for development process only, probably to be removed afterwards.
            // NOTE: We now ignore Java syntax and semantic errors by default,
            // so don't check STS syntax by default, either.
            if (isStrictMode() || needStsSyntaxCheck)
                resultCode = ResultCode.majorValue(checkSTSSyntax(outFiles), resultCode);

            finish(resultCode);

        } catch (UnrecognizedOptionException e) {
            System.err.println(e.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(TOOL_NAME + " <options> <source files>", options);
            finish(ResultCode.CmdLineError);
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp(TOOL_NAME + " <options> <source files>", options);
            finish(ResultCode.CmdLineError);
        }
    }

    private static ResultCode checkSTSSyntax(List<File> stsSources) {
        if (stsSources.isEmpty()) return ResultCode.OK;

        System.out.println("Checking syntax of " + stsSources.size() + " StaticTS files.");
        
        StaticTSSyntaxChecker stsChecker = new StaticTSSyntaxChecker(stsSources,null);
        ResultCode code = stsChecker.transpile();
        errorList.addAll(stsChecker.getErrorList());

        if (code == ResultCode.OK) {
            System.out.println("Syntax OK.");
        }
	    else {
            System.out.println("Bad syntax in the following files:");
            for (File failedFile : stsChecker.getOutFiles())
                System.out.println(failedFile.getPath());
        }

        return code;
    }
}
