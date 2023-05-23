# Arkguard
Arkguard is a javascript and typescript obfuscation tool.

# Usage in DevEco Studio
Arkguard has been integrated into SDK. It is convenient to use Arkguard in DevEco Studio.
In DevEco Studio, Arkguard can be enabled only in Stage Model (FA Model is not supported).
For now only name obfuscations can be used in DevEco Studio (because other obfuscation
abilities of Arkguard may hurt execution performance).
You can obfuscate the following names:
* parameter names and local variable names
* names in global scope
* property names

We enable the obfuscation of parameter names and local variable names by default. However,
global names obfuscation and property names obfuscation are disabled by default, as they may
cause runtime error if they are enabled by default.
You can enable them by [obfuscation options](#obfuscation-options).

When you create a new project, the following config will be generated in `build-profile.json5`.
```
"buildOption": {
  "arkOptions": {
    "obfuscation": {
      "ruleOptions": {
        "enable": true,
        "rules": ["obfusation-rules.txt"],
      }
    }
  }
}
```
When you create a new library, additional property `consumerRules` will be added.
```
"buildOption": {
  "arkOptions": {
    "obfuscation": {
      "ruleOptions": {
        "enable": true,
        "rules": ["obfusation-rules.txt"],
      }
      "consumerRules": ["consumer-rules.txt"]
    }
  }
}
```

To enable obfuscation, the following conditions should be satisfied:
* the property `ruleOptions.enable` is `true` and the property `ruleOptions.enable` of every dependency library is `true`.
* build in release mode

The rules in the property `ruleOptions.rules` will be applied when you build HAP or HAR.

The rules in the property `consumerRules` will be applied when you build the project or library which
depends on this library. They will also be merged into a file `obfuscation.txt` in the resulting HAR.

When you are building HAP or HAR, the final obfucation rules are combination of self's `ruleOptions.rules`
property, dependency libraries' `consumerRules` properties and dependency HAR's `obfuscation.txt`.
If your building HAR, the content of `obfuscation.txt` are the combination of self's `consumerRules` property,
dependency libraries' `consumerRules` properties and dependency HAR's `obfuscation.txt`. If you are building
HAP, `obfuscation.txt` will not be generated.

## Write rules

The files `obfusation-rules.txt` and `consumer-rules.txt` are created by DevEco Studio automatically, but they do not
contain any rule by default. You can write rules in these files or include rules from other files, as the following
example shows.
```
"buildOption": {
  "arkOptions": {
    "obfuscation": {
      "ruleOptions": {
        "enable": true,
        "rules": ["obfusation-rules.txt", "myrules.txt"],
      }
      "consumerRules": ["consumer-rules.txt", "my-consumer-rules.txt"]
    }
  }
}
```

In rule files, you can write [obfuscation options](#obfuscation-options) and [keep options](#keep-options).

### Obfuscation options

`-disable-obfusation`

Specifies to disable all obfuscations. If you use this option, the resulting HAP or HAR will not be obfuscated. By default,
Arkguard only obfuscates the parameter names and local variable names by assigning random short names to them.

`-enable-property-obfuscation`

Specifies to obfuscate the property names. If you use this option, all property names will be obfuscated except the
following:
* the property names of `import/export` classes or objects.
* the property names defined in UI components. For example, the property names `message` and `data` in
    ```
    @Component struct MyExample {
        @State message: string = "hello";
        data: number[] = [];
        ...
    }
    ```
    will not be obfuscated.
* the property names that are specified by [keep options](#keep-options).
* the property names in system API list. System API list is a name set which is extracted from SDK automatically by default.

`-enable-toplevel-obfuscation`

Specifies to obfuscate the names in the global scope. If you use this option, all global names will be obfuscated
except the following:
* the `import/export` global names.
* the global names that are not declared in the current file.
* the global names that are specified by [keep options](#keep-options).
* the global names in system API list.

`-compact`

Specifies to remove unnecessary blank spaces and all line feeds. If you use this option, all code will be compressed into
one line.

`-remove-log`

Specifies to remove all `console.*` statements.

`-print-namecache` filepath

Specifies to print the name cache that contains the mapping from the old names to new names. The cache will printed to
the given file. If you use `-enable-property-obfuscation` or `-enable-toplevel-obfuscation`, and you want incremental
obfuscation in the future (for example, hot fix), then you should use this option and keep the resulting cache file
carefully.

`-apply-namecache` filepath

Specifies to reuse the given cache file. The old names in the cache will receive the corresponding new names specified in
the cache. Other names will receive new random short names. This option should be used in incremental obfuscation.

By default, DevEco Studio will keep and update the namecache file in the temporary cache directory and apply the cache for
incremental compilation.

### Keep options

Keep options are useful only when you use `enable-property-obfuscation` or `enable-toplevel-obfuscation`.

`-keep-property-name` [,modifiers,...]

Specifies property names that you want to keep. For example,
```
-keep-property-name
age
firstName
lastName
```

**What property names should be kept?**

Property obfuscation will not obfuscate the string literals and properties that are accessed dynamically.
So for safety, we would suggest keeping all property names that are accessed dynamically.

Example:
```
var obj = {x0: 0, x1: 0, x2: 0};
for (var i = 0; i < 2; i++) {
  console.log(obj['x' + i]);  // x0, x1, x2 should be kept
}

Object.defineProperty(obj, 'y', {});
console.log(obj.y);           // y should be kept

obj.s = 0;
let key = 's';
console.log(obj[key]);        // s should be kept

obj.u = 0;
console.log(obj.u);           // u can be safely obfuscated

obj.t = 0;
console.log(obj['t']);        // t and 't' can be safely obfuscated, but we suggest keeping t

obj.['v'] = 0;
console.log(obj['v']);        // 'v' can be safely obfuscated, but we suggest keeping v
```

`-keep-global-name` [,modifiers,...]

Specifies names that you want to keep in the global scope. For example,
```
-keep-global-name
Person
printPersonName
```

**What global names should be kept?**

It is known that in javascript the variables in the global scope are properties of `globalThis`. So if in your code
you access a global variable as a property, then the global name should be kept.

Example:
```
var a = 0;
console.log(globalThis.a);  // a should be kept

function foo(){}
globalThis.foo();           // foo should be kept

var c = 0;
console.log(c);             // c can be safely obfuscated

function bar(){}
bar();                      // bar can be safely obfuscated

class MyClass {}
let d = new MyClass();      // MyClass can be safely obfuscated
```

`-keep-dts` filepath

Specifies to keep names in the given `.d.ts` file. Here filepath can be also a directory. If so, then the names in all
`d.ts` files under the given directory will be kept.
If your are building HAR with this option, then the kept names will be merged into the resulting `obfuscation.txt`.

### Comments

You can write comments in rules file by using `#`. For each line, the content beginning with `#` and ending with the
line feed will be treated as comment. For example,
```
# white list for MainAbility.ets
-keep-global-name
MyComponent
GlobalFunction

-keep-property-name # white list for dynamic property names
firstName
lastName
age
```
If your are building HAR, comments will not be merged into the resulting `obfuscation.txt`.