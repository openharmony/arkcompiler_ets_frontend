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

package com.ohos.migrator.ts;

import com.ohos.migrator.AbstractTranspiler;
import com.ohos.migrator.Main;
import com.ohos.migrator.ResultCode;
import com.ohos.migrator.TranspileException;
import com.ohos.migrator.staticTS.XMLReader;
import com.ohos.migrator.staticTS.parser.StaticTSParser.*;
import com.ohos.migrator.util.FileUtils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

public class TSTranspiler extends AbstractTranspiler {

    private static String XML_EXT = ".xml";
    private static String tsTranspilerJS = "typescript/javascript/src/transpiler/TypeScriptTranspiler.js";

    private boolean keepXML;

    private double conversionRate = 0;

    public TSTranspiler(List<File> src, String outDir, boolean keepXML) {
        super(src, null, outDir);
        this.keepXML = keepXML;
    }

    @Override
    public ResultCode transpile() {
        ResultCode transpileResult = ResultCode.OK;

        try {
            String baseDir = FileUtils.getMigratorJarPath().getParent();
            String tsTranspilerPath = new File(baseDir, tsTranspilerJS).getPath();

            int exitCode;
            try {
                exitCode = runTSTranslatorWithRspFile(baseDir, tsTranspilerPath);
            } catch (Exception e) {
                exitCode = runTSTranslatorFallback(tsTranspilerPath);
            }

            if (exitCode != 0) {
                errorList.add(new TranspileException(ResultCode.TranspileError, "TS transpiler exited abnormally."));
                return ResultCode.TranspileError;
            }

            // Pick up XML files created by TS translator and process them.
            for (File srcFile : this.sourceFiles) {
                File xmlFile = new File(srcFile.getPath() + XML_EXT);
                if (xmlFile.exists()) {
                    // Wipe out XML file created by TS translator
                    // unless specifically instructed by user not to.
                    if (!keepXML) xmlFile.deleteOnExit();

                    try {
                        XMLReader xmlReader = new XMLReader(xmlFile);
                        CompilationUnitContext stsCU = xmlReader.read();
                        write(stsCU, srcFile);
                    } catch (Exception e) {
                        transpileResult = ResultCode.TranspileError;
                        errorList.add(new TranspileException(transpileResult, e));
                        if (Main.isStrictMode()) return transpileResult;
                    }
                } else {
                    transpileResult = ResultCode.TranspileError;
                    errorList.add(new TranspileException(transpileResult, "TS transpiler failed for " +
                            srcFile.getPath() + ": No XML output."));
                    if (Main.isStrictMode()) return transpileResult;
                }
            }
        } catch (URISyntaxException use) {
            transpileResult = ResultCode.CmdLineError;
            errorList.add(new TranspileException(transpileResult, use));
        } catch (IOException ioe) {
            transpileResult = ResultCode.InputError;
            errorList.add(new TranspileException(transpileResult, ioe));
        } catch (Exception e) {
            transpileResult = ResultCode.TranspileError;
            errorList.add(new TranspileException(transpileResult, e));
        }

        return transpileResult;
    }

    List<String> getTsTranslatorArgs() {
        List<String> tsArgs = new ArrayList<String>();
        if (Main.isVerboseMode())
            tsArgs.add("-verbose");
        if (Main.isConvRateMode())
            tsArgs.add("-R");
        for (File srcFile : this.sourceFiles) {
            tsArgs.add(srcFile.getPath());
        }
        return tsArgs;
    }

    int runTSTranslatorWithRspFile(String baseDir, String tsTranspilerPath) throws Exception {
        // Use response file to pass arguments to TS translator as
        // the total length of the argument strings might exceed
        // the OS limitation of the command-line length.
        List<String> tsArgs = getTsTranslatorArgs();

        // Prepare response file for TS translator.
        StringBuilder rspFileContent = new StringBuilder();
        for (String arg : tsArgs) {
            rspFileContent.append(arg).append('\n');
        }

        // Create temporary folder to keep the response file.
        String tmpDirPath = baseDir + "/temp";
        File tmpDir = new File(tmpDirPath);
        tmpDir.mkdir();
        if (!keepXML) tmpDir.deleteOnExit();

        // Create response file and write the command list.
        File rspFile = File.createTempFile("ts-args", ".rsp", tmpDir);
        if (!keepXML) rspFile.deleteOnExit();
        BufferedWriter writer = new BufferedWriter(new FileWriter(rspFile));
        writer.write(rspFileContent.toString());
        writer.close();

        // Pass only the response file as an argument.
        tsArgs = new ArrayList<>();
        tsArgs.add('@' + rspFile.getAbsolutePath());

        return runTSTranslatorProcess(tsArgs, tsTranspilerPath);
    }

    int runTSTranslatorFallback(String tsTranspilerPath) throws Exception {
        // Run TS translator process by placing all necessary arguments
        // on transpiler's command-line directly. That way, we can get
        // the translation done normally at least in some cases, unless
        // the OS limit on command-line length is exceeded.
        return runTSTranslatorProcess(getTsTranslatorArgs(), tsTranspilerPath);
    }

    private int runTSTranslatorProcess(List<String> tsArgs, String tsTranspilerPath) throws Exception {
        // Run TS translator with NodeJS runtime.

        // Complete the argument list by adding the name of the NodeJS
        // executable and path to TS transpiler script.
        tsArgs.add(0, "node");
        tsArgs.add(1, tsTranspilerPath);

        // Redirect the error stream of the new process to the standard
        // error stream of main Java process, so that the error messages
        // are automatically printed to console.
        ProcessBuilder pb = new ProcessBuilder(tsArgs).redirectError(ProcessBuilder.Redirect.INHERIT);
        Process p = pb.start();

        // The conversion rate of translated TypeScript code is evaluated
        // by TS translator and is written to its standard output buffer.
        // To retrieve the rate number, we read the output buffer manually,
        // looking for the line that starts with specific text. After the
        // number is extracted, the line is dropped. Other messages are
        // re-printed to standard output of the main process as is.
        try (BufferedReader output = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = output.readLine()) != null) {
                if (line.startsWith("Conversion rate:")) {
                    try {
                        // Extract the conversion rate number.
                        this.conversionRate = Double.parseDouble(line.substring(16));
                    }
                    catch (Exception e) {
                        System.err.println("Failed to evaluate TypeScript conversion rate: " + e.getMessage());
                    }
                } else {
                    // Write the message to standard output.
                    System.out.println(line);
                }
            }
        }
        
        // Wait for the sub-process to finish.
        return p.waitFor();
    }

    @Override
    public double getConversionRate() {
        return conversionRate;
    }

    @Override
    protected void transpileFile(File srcFile) { }
}
