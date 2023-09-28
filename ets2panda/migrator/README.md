# Migration Tool
Migration tool is essentially a translator from Java and Kotlin to STS, 
a TypeScript-based language whose specification is currently under development.

## Building

### Requirements
This project is using the **Apache Ant** tool for building. You can download binaries from [here](https://ant.apache.org/bindownload.cgi) (it's recommended to use the latest available version) and use the [official guide](https://ant.apache.org/manual/install.html) to install and setup the tool.

You also need to use **Java 11** (or newer) to build the project.

The TypeScript translator is written on TypeScript and requires NodeJS to build the project and run the translator. For details, see the [typescript](typescript) page. 

### Steps to build

The build supports two main targets: **clean** and **build**:
- Use **ant clean build** to perform build with preliminary cleaning of previous build artifacts. 
- Use **ant build** to do incremental build (does not re-build sources that didn't change).

The result jar file is **out/migrator-[version].jar**.

## Running
To use migration tool after the build, run the following command from the top-level folder of 
the repository:

java -jar out/migrator-[version].jar [options] [input files]

To get the list of available command-line options, run:

java -jar out/migrator-[version].jar -help

## Running tests
All tests are located under the test folder and sorted by the input language 
from which the source files are migrated to STS (inside java, kotlin and ts 
folders under test folder, correspondingly). There are also tests for Java API 
migration inside test/java-mapper folder.
 
To run all tests, run **ant test** on the command line. There are also language-
specific ant targets - **test_java**, **test_kotlin**, and **test_ts**. Use 
these targets if you want to run tests for a single language only. To run tests
for Java API migration alone, use **test_java_api** ant target. In all cases, 
resulting STS files are written to the results folder under language-specific 
folders and compared to the expected STS files located next to the test source 
files.
