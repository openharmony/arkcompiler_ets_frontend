# Test lsp api

Currently ts lsp api in WIP, this way is only while it's in wip. Later it will change

## Pre

build es2panda with this branch
```
git clone git@gitee.com:dreamdoomwalker/arkcompiler_ets_frontend.git -b ts_bindings
  
```

## Changes due to WIP

change path from you future build dir in files:
- Change absolute library path in files 
  1. bindings/src/Es2pandaNativeModule.ts in functions `registerNativeModuleLibraryName`
  2. bindings/src/InteropNativeModule.ts in the same function `registerNativeModuleLibraryName`

- If you need to add new lsp method:
  1. add it into `.ts` src/Es2pandaNativeModule.ts check for example `_getCurrentTokenValue` method
  2. add into `native/src/lsp.cpp` method with macro for example `impl_getCurrentTokenValue`

## Build:
target:
```
  ninja ts_bindings
```

transpile tsbindings:

```
  cd es2panda/bindings
  npm i
  npm run compile
  npm link
```

link with npm lib your code locally 

```
  npm link @es2panda/bindings
```

## Usage

check `lsp_api.ts` file 
```ts
  let foo =global.es2panda._getCurrentTokenValue(<path_to_sts_file, offset)
  unpackString(foo) // should be used as 
```


