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

package com.ohos.migrator.test.java;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import java.util.Scanner;

class TryWithResources {

    // Basic try-with-resources (no catch/finally blocks)
    void readFile() throws IOException {
        String line = "";
        String path = "";
        try (FileReader fr = new FileReader(path);
             BufferedReader br = new BufferedReader(fr)) {
            line = br.readLine();
        }
    }

    // with catch block
    void viewTable(Connection con) throws SQLException {
        String query = "select COF_NAME, SUP_ID, PRICE, SALES, TOTAL from COFFEES";

        try (Statement stmt = con.createStatement()) {
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                System.out.println(rs.getString("COF_NAME") + ", " + rs.getInt("SUP_ID") + ", " +
                        rs.getFloat("PRICE") + ", " + rs.getInt("SALES") + ", " + rs.getInt("TOTAL"));
            }
        } catch (SQLException e) {
            System.err.println("SQLState: " + e.getSQLState());
            System.err.println("Error Code: " + e.getErrorCode());
            System.err.println("Message: " + e.getMessage());
        }
    }

    // with finally block
    void readFile2() throws IOException {
        String line = "";
        String path = "";
        try (FileReader fr = new FileReader(path);
             BufferedReader br = new BufferedReader(fr)) {
            line = br.readLine();
        } finally {
            System.out.println("Successful!");
        }
    }

    // with catch and finally block
    void scanFile() {
        try (Scanner scanner = new java.util.Scanner(new File("test.txt"))) {
            while (scanner.hasNext()) {
                System.out.println(scanner.nextLine());
            }
        } catch (FileNotFoundException fnfe) {
            fnfe.printStackTrace();
        } finally {
            System.out.println("Successful!");
        }
    }

    // Resource is variable access
    void writeFile() {
        try {
            final Scanner scanner = new Scanner(new File("testRead.txt"));
            PrintWriter writer = new PrintWriter(new File("testWrite.txt"));

            try (scanner; writer) {
                while (scanner.hasNext()) {
                    String line = scanner.nextLine();
                    writer.println(line);
                }
            }
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
    }

    // Resource is field access
    class Z {
        public final Y yz = new Y();
    }
    public class X extends Z {
        final Y y2 = new Y();

        public void foo() {
            Z z = new Z();

            try (this.y2; super.yz)  {
                try (z.yz) {
                    System.out.println(this.y2.val + super.yz.val + z.yz.val);
                }
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        }
    }
    class Y implements AutoCloseable {
        public int val = 10;

        @Override
        public void close() throws IOException {
            if (val < 0) {
                throw new IOException("Invalid value: " + val);
            }
            
            System.out.println("Closed");
        }

// Currently, "try(this)" case doesn't work properly due to bug
// in Eclipse JDT library:
// https://bugs.eclipse.org/bugs/show_bug.cgi?id=577128
// The bug is present in the version of library that the migrator
// is currently restricted to use.
// Uncomment this case, when the library is updated to newer version.
//
//        private void bar() {
//            try (this) {
//                System.out.println("In Try");
//            } catch (IOException e) {
//                System.err.println(e.getMessage());
//            }
//        }
    }
} 
