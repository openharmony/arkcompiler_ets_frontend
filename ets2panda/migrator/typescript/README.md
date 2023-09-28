# TypeScript Translator
Translator from TypeScript to ArkTS, written on TypeScript and using TSC API.

## Prerequisits

### Visual Studio Code
For development, it's recommended to use `VS Code`, as it has a full built-in support for TypeScript language.

### NodeJS and NPM
In order to build and run TypeScript translator, you need to install `NodeJS` and `NPM`. It is recommended using a `Node version manager` to install Node and NPM ([nvm](https://github.com/nvm-sh/nvm) for Linux; [nvm-windows](https://github.com/coreybutler/nvm-windows) for windows - v1.1.9 is the most stable). You can also follow the [official guide](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).

### TypeScript Compiler
The translator itself is written on TypeScript, therefore you need to use a TSC in order to build the project. The build script uses the TypeScript compiler downloaded as a local project dependency, but you can also install TypeScript Compiler globally and use it to compile the sources separately (see the [Intermediate build steps](#intermediate-build-steps) below):
```bash
npm install -g typescript
```
See https://www.npmjs.com/package/typescript for more details.

## Building
All commands below are run from `migrator/typescript`.

### Full build
- `npm install` - installs/updates project dependencies and compiles the project sources.
- `npm run build` - builds the project, but skips checking the project dependencies (at the `node_modules` folder).

### Intermediate build steps
If you want to build only certain part of the typescript module, use the following commands: 
- `npm run antlr4ts` - generates StaticTS parser/lexer using ANTLR grammar.
- `npm run tsc` (or just `tsc` if using **global** tsc) - compiles project sources.

Compiled JavaScript code is located at `build/javascript` directory.

## Running
Run the following command from the same directory:
```bash
node build\javascript\src\transpiler\TypeScriptTranspiler.js [input_files]
```