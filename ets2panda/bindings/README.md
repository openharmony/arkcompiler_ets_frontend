# Test lsp api

Currently ts lsp api in WIP, this way is only while it's in wip. Later it will change

## Changes due to WIP

change path from you future build dir in files:
- Change $BINDINGS_PATH variable library path in files 
  1. bindings/src/Es2pandaNativeModule.ts in functions `registerNativeModuleLibraryName`
  2. bindings/src/InteropNativeModule.ts in the same function `registerNativeModuleLibraryName`

- If you need to add new lsp method:
  1. add it into `.ts` src/Es2pandaNativeModule.ts check for example `_getCurrentTokenValue` method
  2. add into `native/src/lsp.cpp` method with macro for example `impl_getCurrentTokenValue`
  3. check `lspNode.ts` file, whether you api's node exists. if not add here new class like other, with extending `LspNode` class
  4. add to `public.ts` file method which uses underhood c-api, and pass pointer (peer) to object constructor, after this file will be changed to separate lsp file

## Build:
target:
```
  ninja ts_bindings
```

transpile tsbindings:

```
  cd es2panda/bindings
  npm i
  npm run run
  npm link
```

link with npm lib your code locally 

```
  npm link @es2panda/bindings
```

## Usage

check `lsp_api.ts` file 
```ts
import { Lsp } from "@es2panda/bindings"
let lsp = new Lsp()

let def = lsp.getDefinitionAtPosition("/path/to/panda/ets_frontend/ets2panda/foo/f2.ets", 70)
console.log(def)

let foo = lsp.getSemanticDiagnostics("/path/to/panda/ets_frontend/ets2panda/foo/f3.ets")
console.log(foo)
```

for tests we need add to devDeps in package.json
```json
  "@types/node": "^22.13.5"
```

in tsconfig.json add 

```json
  "moduleResolution": "node",
  "lib": [
    "es2017"
  ]
```
