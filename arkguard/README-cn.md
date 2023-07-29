# Arkguard
Arkguard 是Javascript和Typescript的源码混淆工具。

# 在DevEco Studio中的用法
Arkguard已经被集成了到SDK中。可以在DevEco Studio中很方便地使用。Arkguard只能用于Stage模型
(不支持FA模型)。目前Arkguard只提供名称混淆的能力(因为其它混淆能力会劣化性能)。
使用Arkguard可以混淆以下名称:
* 参数名和局部变量名
* 顶层作用域的名称
* 属性名称

Arkguard默认使能对参数名和局部变量名的混淆。顶层作用域名称和属性名称的混淆是默认关闭的，
因为默认打开可能会导致运行时错误。你可以通过[混淆选项](#混淆选项)来开启它们。

创建一个新工程的时候，配置文件`build-profile.json5`中会自动生成以下内容:
```
"arkOptions": {
  "obfuscation": {
    "ruleOptions": {
      "enable": true,
      "files": ["obfuscation-rules.txt"],
    }
  }
}
```
创建一个新的library的时候，还会额外生成`consumerFiles`属性:
```
"arkOptions": {
  "obfuscation": {
    "ruleOptions": {
      "enable": true,
      "files": ["obfuscation-rules.txt"],
    }
    "consumerFiles": ["consumer-rules.txt"]
  }
}
```

要想开启混淆，需要满足下面的条件:
* 属性`ruleOptions.enable`的值为`true`，并且所有依赖的library的`ruleOptions.enable`属性是`true`
* 在release模式构建

属性`ruleOptions.files`中指定的混淆配置文件会在构建HAP或HAR的时候被应用。

属性`consumerFiles`中指定的混淆配置文件会在构建依赖这个library的工程或library时被应用。
这些混淆配置文件的内容还会被合并到HAR包中的`obfuscation.txt`文件。

当构建HAP或者HAR的时候，最终的混淆规则是自身的`ruleOptions.files`属性，依赖的library的`consumerFiles`属性，
以及依赖的HAR包中的`obfuscation.txt`文件的合并。如果构建的是HAR，`obfuscation.txt`是自身的`consumerFiles`属性，
依赖的library的`consumerFiles`属性，以及依赖的HAR包中的`obfuscation.txt`文件的合并。
构建HAP不会生成`obfuscation.txt`。详细合并的策略可以查看[混淆规则合并策略](#混淆规则合并策略)。

## 配置混淆规则
在创建工程或library的时候，DevEco Studio会自动生成`obfuscation-rules.txt`和`consumer-rules.txt`文件，
但是它们默认不会包含任何混淆规则。你可以在这些文件中写混淆规则，或者也可以将规则写在其它文件，
然后将文件路径放到`ruleOptions.files`和`consumerFiles`中，如下面的例子所示。
```
"buildOption": {
  "arkOptions": {
    "obfuscation": {
      "ruleOptions": {
        "enable": true,
        "files": ["obfuscation-rules.txt", "myrules.txt"],
      }
      "consumerFiles": ["consumer-rules.txt", "my-consumer-rules.txt"]
    }
  }
}
```

在混淆规则文件中，你可以写[混淆选项](#混淆选项)和[保留选项](#保留选项)。

### 混淆选项

`-disable-obfuscation`

关闭所有混淆。如果你使用这个选项，那么构建出来的HAR或HAR将不会被混淆。默认情况下，
Arkguard只混淆参数名和局部变量名(通过将它们重新命名为随机的短名字)。

`-enable-property-obfuscation`

开启属性混淆。 如果你使用这个选项，那么所有的属性名都会被混淆，除了下面场景:
* 被`import/export`的类或对象的属性名不会被混淆。注意: 只有直接导出的类或对象的属性名不会被混淆。
比如下面例子中的属性名`data`不会被混淆。
    ```
    export class MyClass {
       data: string;
    }
    ```
对于间接导出的场景，比如`export MyClass`和`let a = MyClass; export a;`，如果你不想混淆它们的属性名，
那么你需要使用[保留选项](#保留选项)来保留这些属性名。另外，对于直接导出的类或对象的属性的属性名，比如下面例子中的`name`和`age`, 如果你不想混淆它们，那么你也需要使用[保留选项](#保留选项)来保留这些属性名。
    ```
    export class MyClass {
       person = {name: "123", age: 100};
    }
    ```
* ArkUI组件中的属性名不会被混淆。比如下面例子中的`message`和`data`不会被混淆。
    ```
    @Component struct MyExample {
        @State message: string = "hello";
        data: number[] = [];
        ...
    }
    ```
* 被[保留选项](#保留选项)指定的属性名不会被混淆。
* 系统API列表中的属性名不会被混淆。系统API列表是构建时从SDK中自动提取出来的一个名称列表。
* 字符串字面量属性名不会被混淆。比如下面例子中的`"name"`和`"age"`不会被混淆。
    ```
    let person = {"name": "abc"};
    person["age"] = 22;
    ```
    如果你想混淆字符串字面量属性名，你需要在该选项的基础上再使用`-enable-string-property-obfuscation`选项。比如
    ```
    -enable-property-obfuscation
    -enable-string-property-obfuscation
    ```
    注意：如果你的代码里面有字符串属性名包含特殊字符(除了`a-z, A-Z, 0-9, _`之外的字符)，比如`let obj = {"\n": 123, "": 4, " ": 5}`，我们建议不要开启`-enable-string-property-obfuscation`选项，因为当你不想混淆这些名字时，可能无法通过[保留选项](#保留选项)来指定保留这些名字。

`-enable-toplevel-obfuscation`

开启顶层作用域名称混淆。如果你使用这个选项，那么所有的顶层作用域的名称都会被混淆，除了下面场景:
* 被`import/export`的名称不会被混淆。
* 当前文件找不到声明的名称不会被混淆。
* 被[保留选项](#保留选项)指定的顶层作用域名称不会被混淆。
* 系统API列表中的顶层作用域名称不会被混淆。

`-compact`

去除不必要的空格符和所有的换行符。如果你使用这个选项，那么所有代码会被压缩到一行。

`-remove-log`

删除所有`console.*`语句。

`-print-namecache` filepath

将名称缓存保存到指定的文件路径。名称缓存包含名称混淆前后的映射。如果你使用了`-enable-property-obfuscation`或
`-enable-toplevel-obfuscation`选项，并且你希望未来进行增量编译(比如热修复)，那么你应该使用这个选项，
并且将缓存文件保管好。

`-apply-namecache` filepath

复用指定的名称缓存文件。名字将会被混淆成缓存映射对应的名字，如果没有对应，将会被混淆成新的随机段名字。
该选项应该在增量编译场景中被使用。

默认情况下，DevEco Studio会在临时的缓存目录中保存缓存文件，并且在增量编译场景中自动应用该缓存文件。

### 保留选项

保留选项只有在使用`enable-property-obfuscation`或`enable-toplevel-obfuscation`选项时发挥作用。

`-keep-property-name` [,modifiers,...]

指定你想保留的属性名。比如下面的例子:
```
-keep-property-name
age
firstName
lastName
```

**哪些属性名应该被保留?**

为了保障混淆的正确性，我们建议你保留所有不通过点语法访问的属性。

例子:
```
var obj = {x0: 0, x1: 0, x2: 0};
for (var i = 0; i <= 2; i++) {
    console.log(obj['x' + i]);  // x0, x1, x2 应该被保留
}

Object.defineProperty(obj, 'y', {});  // y 应该被保留
console.log(obj.y);

obj.s = 0;
let key = 's';
console.log(obj[key]);        // s 应该被保留

obj.u = 0;
console.log(obj.u);           // u 可以被正确地混淆

obj.t = 0;
console.log(obj['t']);        // 在开启字符串字面量属性名混淆时t和't'会被正确地混淆，但是我们建议保留

obj['v'] = 0;
console.log(obj['v']);        // 在开启字符串字面量属性名混淆时'v'会被正确地混淆，但是我们建议保留
```

`-keep-global-name` [,modifiers,...]

指定要保留的顶层作用域的名称。比如，
```
-keep-global-name
Person
printPersonName
```

**哪些顶层作用域的名称应该被保留?**

在Javascript中全局变量是`globalThis`的属性。如果在代码中使用`globalThis`去访问全局变量，那么该变量名应该被保留。

例子:
```
var a = 0;
console.log(globalThis.a);  // a 应该被保留

function foo(){}
globalThis.foo();           // foo 应该被保留

var c = 0;
console.log(c);             // c 可以被正确地混淆

function bar(){}
bar();                      // bar 可以被正确地混淆

class MyClass {}
let d = new MyClass();      // MyClass 可以被正确地混淆
```

`-keep-dts` filepath

保留指定路径的`.d.ts`文件中的名称。这里的文件路径可以是一个目录，这种情况下目录中所有`.d.ts`文件中的名称都会被保留。
如果在构建HAR时使用了这个选项，那么文件中的名称会被合并到最后的`obfuscation.txt`文件中。

### 注释

可以使用`#`在混淆规则文件中进行注释。每行以`#`开头的文本会被当做是注释，比如下面的例子:
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
构建HAR时，注释不会被合并到最后的`obfuscation.txt`文件中。

### 混淆规则合并策略
一个工程中经常会有许多混淆规则文件，这些文件来自于:
* 主工程的`ruleOptions.files` (这里主工程我们指的是正在构建的工程)
* 本地依赖的library中的`consumerFiles`选项中指定的文件
* 远程依赖的HAR包中的`obfuscate.txt`文件

当构建主工程的时候，这些文件中的混淆规则会按照下面的合并策略(伪代码)进行合并:
```
let `listRules` 表示上面提到的所有混淆规则文件的列表
let finalRule = {
    disableObfuscation: false,
    enablePropertyObfuscation: false,
    enableToplevelObfuscation: false,
    compact: false,
    removeLog: false,
    keepPropertyName: [],
    keepGlobalName: [],
    keepDts: [],
    printNamecache: string,
    applyNamecache: string
}
for each file in `listRules`:
    for each option in file:
        switch(option) {
            case -disable-obfuscation:
                finalRule.disableObfuscation = true;
                continue;
            case -enable-property-obfuscation:
                finalRule.enablePropertyObfuscation = true;
                continue;
            case -enable-toplevel-obfuscation:
                finalRule.enableToplevelObfuscation = true;
                continue;
            case -compact:
                finalRule.compact = true;
                continue;
            case -remove-log:
                finalRule.removeLog = true;
                continue;
            case -print-namecache:
                finalRule.printNamecache = #{指定的路径名};
                continue;
            case -apply-namecache:
                finalRule.applyNamecache = #{指定的路径名};
                continue;
            case -keep-property-name:
                finalRule.keepPropertyName.push(#{指定的名称});
                continue;
            case -keep-global-name:
                finalRule.keepGlobalName.push(#{指定的名称});
                continue;
            case -keep-dts:
                finalRule.keepDts.push(#{指定的路径});
                continue;
        }
    end-for
end-for
```
最后使用的混淆规则来自于对象`finalRule`。

如果构建的是HAR，那么最终的`obfuscate.txt`文件内容来自于主工程和本地依赖的library的`consumerFiles`选项，
以及依赖的HAR的`obfuscate.txt`文件的合并。合并策略和上面一样，除了以下的不同:
* `-keep-dts`选项会被转换成`-keep-global-name`和`-keep-property-name`。
* `-print-namecache`和`apply-namecache`选项会被忽略，不会出现在最后的`obfuscate.txt`文件中。
