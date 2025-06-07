# homecheck

## 项目简介

该项目（homecheck）专为提升代码质量而设计，能高效识别代码缺陷并提出方案；其核心功能是对应用工程项目执行静态代码分析，评估代码在安全性、性能等方面上的表现，精准定位问题及其在代码中的位置。

## 目录

```
homecheck
├─config/                 # 项目配置
├─document/               # 项目文档
├─resources/              # 依赖库
├─src/
│　├─checker/             # 项目检测规则功能代码
│　├─codeFix/             # 修复
│　├─matcher/             # 匹配类型
│　├─model/               # 模块
│　├─utils/               # 公共接口
│　└─run.ts               # 项目入口
└─test/                   # 测试目录
```

## 项目主体流程

1.读取配置文件projectConfig.json和ruleConfig.json

2.使用**ArkAnalyzer**项目构建**sence**

3.根据配置文件参数，获取需要检测的文件

4.前处理

5.进行检测

6.后处理

## QuickStart

### 1.下载本项目

### 2.进入项目根目录，打开终端

```
cmd
```

### 3.安装依赖库

```
npm install
```

### 4.修改配置

**config\projectConfig.json**中修改项目配置
示例：

```
{
  "projectName": "TestProject",
  "projectPath": "/path/to/project",
  "logPath": "./HomeCheck.log",
  "ohosSdkPath": "/path/to/ohosSdk",
  "hmsSdkPath": "/path/to/hmsSdk",
  "checkPath": "",
  "sdkVersion": 14,
  "fix": "true",
  "npmPath": "",
  "sdksThirdParty": [
    {
      "name": "thirdParty",
      "path": "./resources/thirdPartyModules",
      "moduleName": ""
    }
  ]
}
```
字段说明：
```
projectName：需要检测工程的名字
projectPath：需要检测工程的路径
logPath：日志输出路径
ohosSdkPath：ohossdk路径，比如DevEco Studio安装目录下的sdk\default\openharmony\ets
hmsSdkPath：hmssdk路径，比如DevEco Studio安装目录下的sdk\default\hms\ets
checkPath：解析指定的文件
sdkVersion：sdk版本
fix：是否修复
npmPath：自定义规则npm路径
sdksThirdParty：sdk三方库，name：库名称，path:库路径，moduleName：模块名称
```

**config\ruleConfig.json**中修改规则配置
示例：

```
{
  "files": [
    "**/*.ets",
    "**/*.ts"
  ],
  "ignore": [
    "**/ohosTest/**/*",
    "**/node_modules/**/*",
    "**/build/**/*",
    "**/hvigorfile/**/*",
    "**/oh_modules/**/*",
    "**/.preview/**/*"
  ],
  "rules": {
    "@performance/foreach-args-check":3
  },
  "ruleSet": [
    "plugin:@performance/all",
    "plugin:@correctness/all"
  ],
  "overrides": [],
  "extRuleSet": []
}
```

字段说明：

```
files：待检测文件类型
ignore：过滤文件
rules：可以基于ruleSet配置的规则集，新增额外规则项
ruleSet：规则集
overrides：定制化检查的规则
extRuleSet：自定义规则
```
extRuleSet：自定义规则,参考[自定义规则](#自定义规则)

### 5.启动项目

注意修改projectConfig.json和ruleConfig.json文件路径

#### 5.1 命令行启动，示例：

根目录下执行
```
node -r ts-node/register ./src/run.ts  --projectConfigPath=./config/projectConfig.json --configPath=./config/ruleConfig.json
```

#### 5.2 vscode启动：

根目录新建.vscode目录，并新建launch.json文件，内容参考.vscode_sample\launch.json

点击左侧运行和调试按钮，点击启动程序，开始运行，运行结束查看HomeCheck.log
#### 5.3 webstorm启动：

## 新增规则

### 自定义规则
参考：[自定义规则开发指南](document/ExtRule自定义规则开发指南.md)

### 检测规则
参考：[新增检测规则开发指南](document/规则开发指南.md)

## api
参考：[api说明](doc/globals.md)

## 打包

根目录下执行命令：

```
npm pack
```
产物，根目录下：

homecheck-1.0.0.tgz

## 安装与使用

参考：[homecheck安装与使用指南](document/homecheck安装与使用指南.md)

## HomeCheck附带工具使用指南

参考：[HomeCheck附带工具使用指南](document/HomeCheck附带工具使用指南.md)

### 日志

运行结果请查看根目录下的HomeCheck.log

## 代码上库
遵守openharmony-sig代码上库规范, 操作方法请参考：[创建pr指南](document/PR指南.md)

## Issues
提交Issues请参考：[Issues指南](document/Issues指南.md)。

## 添加自验证测试用例
自验证用例请参考：[单元测试用例开发指南](document/单元测试用例开发指南.md)

## 相关仓

[ArkAnalyzer](https://gitcode.com/openharmony-sig/arkanalyzer)

## 欢迎加入homecheck社区开发讨论

![homecheck社区开发讨论](document/img/homecheck社区开发讨论.JPG)