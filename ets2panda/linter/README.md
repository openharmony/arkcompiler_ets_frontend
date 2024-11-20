# TypeScript linter

Typescript linter ( further mentioned as 'linter' ) is a tool to check typescript sources and find language elements
and constructions which are deprecated to use in a purpose to migrate sources to STS.
The linter is currently under development.

## Prerequisits

### Visual Studio Code

For development, it's recommended to use `VS Code`, as it has a full built-in support for TypeScript language.

### NodeJS and NPM

Install the latest stable version of `Node` and `NPM`. It is recommended to use a `Node version manager` to install Node and NPM ([nvm](https://github.com/nvm-sh/nvm) for Linux; [nvm-windows](https://github.com/coreybutler/nvm-windows) for windows). You can also follow the [official guide](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).

## Building

Run the following command to install all project dependencies and build the project:

```bash
npm install
```

Run the following command to only build project sources:

```bash
npm run build
```

## Running

Run the following command from the same directory:

```bash
node dist/tslinter.js [options] [input files]
```

Note: Before linting a project, it is highly recommended to install all project dependencies (with `npm install` or any other methods -- depends on the concrete project).

You can also use command files `tslinter.sh` or `tslinter.bat` with same arguments as for direct launch.

Possible command options:

`--deveco-plugin-mode` - this options defines special mode to launch from IDE and should NOT be used when running from command line.

`-f, --project-folder <path>` - defines path to folder with TypeScript sources and subfolders which linter walks recurscevely. This option may be repeated in command line with different paths.

`-p, --project <path>` - defines path to TS project configuration file (commonly known as tsconfig.json). If no input file is defined directly as command-line argument, then all source files from tsconfig.json will be processed by linter. Otherwise, linter will only process input files from command-line, that are included into project (i.e. files that belong to intersection of input files from command-line and tsconfig.json file).

`-E, --TSC_Errors` - enables logging messages about compilation errors and unresolved symbols.

All other command line arguments are considered as paths to TypeScript files.

To prevent command line buffer overflow, response file may be used. It is specified by adding `@` prefix to file name (e.g.: `tslinter.sh @response-file.txt` ). Response file should contain TypeScript source paths (one at each line). The response file argument should be the last command argument (any following argument will be ignored).

## Running tests

To run all tests, use the following command:

```bash
npm test
```

To run only certain tests, use the `testrunner` command with corresponding arguments:

```bash
npm run testrunner -- [args]
```

E.g., the following command:

```bash
npm run testrunner -- -d test/main -p {array,object}*
```

will run the tests in `test/main` directory that match the glob pattern `{array,object}*` (i.e. tests that start with `array` or `object`)
