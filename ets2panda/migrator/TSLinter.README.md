# TypeScript linter
Typescript linter ( further mentioned as 'linter' ) is a tool to check typescript sources and find language elements 
and constructions which are deprecated to use in a purpose to migrate sources to STS. 
The linter is currently under development.

## Building
To build linter download from gitee (https://gitee.com/openharmony-sig/arkcompiler_ets_frontend/tree/master/migrator),

### Requirements
This project is using the **Apache Ant** tool for building. You can download binaries from [here](https://ant.apache.org/bindownload.cgi) (it's recommended to use the latest available version) and use the [official guide](https://ant.apache.org/manual/install.html) to install and setup the tool.

You also need to use **Java 11** (or newer) to build the project.

The linter is written on TypeScript and requires NodeJS to build the project and run. For details, see the [typescript](typescript) page. 

### Steps to build

The build supports two main targets: **clean** and **build**:
- Use **ant clean build** to perform build with preliminary cleaning of previous build artifacts. 
- Use **ant build** to do incremental build (does not re-build sources that didn't change).

The result file is web packet  **out/typescript/javascript/src/linter/dist/tslinter.ts**.

## Running
To use linter after the build, run the following command from the top-level folder of 
the repository:

node ./out/typescript/javascript/src/linter/dist/tslinter.ts [options] [input files]

or use command files tslinter.sh or tslinter.cmd with same arguments as for direct launch.
 
Possible options are:

**--deveco-plugin-mode** - this options defines special mode to launch from IDE and shouldn't be used in command line work

**--strict** - defines 'strict' mode in which all problem TypeScript language elements are counted;
				if this option is not set, linter works in 'relax' mode in which counts only elements that cannot be transpiled
				by TypeSctipt migrator.

**--project-folder \<path>** - defines path to folder with TypeScript sources and subfolders which linter walks recurscevely.
                                This option may be repeated in command line with different paths.

**-p, --project \<path>** - defines path to TS project configuration file (commonly known as **tsconfig.json**).

All other command line arguments are considered as paths to TypeScript files.

To prevent command line buffer overflow response file may be used. Its name is set by adding '@' prefix to file name 
( for example:  'tslinter.sh @responce.file.txt' ).
Response file should contain TypeScript source paths (one at each line). 
In case of using responce file no other arguments except options take effect.

Work results are printed to stdout and may be redirected to file.



## Running tests
All tests are located under the test folder in linter subfolder.

 
To run all tests, run **ant test_linter** on the command line.
