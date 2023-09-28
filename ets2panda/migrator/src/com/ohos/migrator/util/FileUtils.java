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

package com.ohos.migrator.util;

import com.ohos.migrator.Main;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

public class FileUtils {
    public static char[] readFileToCharArray(File file) throws IOException {
        try (FileReader fileReader = new FileReader(file);
            BufferedReader bufReader = new BufferedReader(fileReader)) {

            int length = (int)file.length(); // It's assumed a source file length fits into 2 GB.

            char[] buf = new char[length];
            int offset = 0;
            int left = length;
            int numRead;
            while ((numRead = bufReader.read(buf, offset, left)) != -1 && left > 0) {
                offset += numRead;
                left -= numRead;
            }

            return buf;
        } catch (Throwable t) {
            throw new IOException("Failed to read source file " + file.getPath());
        }
    }

    private static final int offset = 14;
    public static boolean textuallyEqual(File resultFile, File expectedFile, boolean useOffset) {
       String[] resultText = readFile(resultFile);
       String[] expectedText = readFile(expectedFile);

       int expectedLen = useOffset ? expectedText.length-offset : expectedText.length;
       if (resultText.length != expectedLen)
           return false;

       for (int i = 0; i < resultText.length; ++i) {
           int expectedInd = useOffset ? i+offset : i;
           if (!resultText[i].equals(expectedText[expectedInd]))
               return false;
       }

       return true;
    }

    public static String[] readFile(File file) {
       List<String> result = new ArrayList<>();
       try (BufferedReader br = new BufferedReader(new FileReader(file))) {
           String line;
           while ((line = br.readLine()) != null) {
               // drop leading and trailing space
               // and empty lines
               line = line.trim();
               if (!line.isEmpty())
                   result.add(line);
           }
       }
       catch (IOException ioe) {
           System.err.println("Failed to read file " + file.getPath());
       }

       return result.toArray(new String[0]);
    }

    public static void copyFile(File file, FileWriter fw) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                fw.write(line + "\n");
            }
        }
        catch (IOException ioe) {
            System.err.println("Failed to copy file " + file.getPath());
        }
    }

    public static File getMigratorJarPath() throws URISyntaxException {
        URI mainClassURI = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        return new File(mainClassURI);
    }

    public static File getMigratorLibDir() throws URISyntaxException {
        return getMigratorJarPath().getParentFile();
    }
}
