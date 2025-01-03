### 关联的Issue


### 提交类型
- [ ] 需求
- [ ] bugfix

### 需求背景/Description <!-- 仅涉及需求时填写 -->


### 问题现象&&分析/Reason <!-- 仅涉及bugfix时填写 -->


### 修改方案/Scheme


### 测试结果（测试截图直接贴在对应测试项，主干已知问题需明确引入pr/责任人）

#### 当前GGW中未添加的测试套(请在本地进行验证)
1.Fuzz编译测试
```
./build.sh --product-name rk3568 --build-target arkcompiler/runtime_core/tests/fuzztest:fuzztest
```

2."runtime_core/libpandabase/tests:host_unittest"
release模式：
```
./build.sh --product-name rk3568 --build-target runtime_core_host_unittest
```
debug模式：
```
./build.sh --product-name rk3568 --build-target runtime_core_host_unittest --gn-args is_debug=true
```

#### 功能测试（除仅涉及文本外必测项）[wiki](https://gitee.com/openharmony/arkcompiler_ets_frontend/wikis/%E4%BB%A3%E7%A0%81%E6%8F%90%E4%BA%A4%E8%A6%81%E6%B1%82%E5%8F%8A%E6%B5%8B%E8%AF%95%E9%AA%8C%E8%AF%81%E6%B5%81%E7%A8%8B)
1. test262测试
    - [ ] 已通过
    - [ ] 不涉及，无需验证

2. ut测试
    - [ ] 已通过
    - [ ] 不涉及，无需验证

3. verifier测试
    - [ ] 已通过
    - [ ] 不涉及，无需验证

#### 独立编译测试（涉及BUILD.gn改动时必测项）[wiki](https://gitee.com/ark_standalone_build/docs#arkcompiler%E5%BC%80%E5%8F%91%E6%8C%87%E5%AF%BC)
1. test262 release
    - [ ] 已通过
    - [ ] 不涉及，无需验证

2. ut release
    - [ ] 已通过
    - [ ] 不涉及，无需验证

3. ut debug
    - [ ] 已通过
    - [ ] 不涉及，无需验证

#### 混淆测试（涉及arkguard改动时必测项）[wiki](https://gitee.com/openharmony/arkcompiler_ets_frontend/wikis/%E6%B7%B7%E6%B7%86%E6%B5%8B%E8%AF%95%E9%AA%8C%E8%AF%81%E6%B5%81%E7%A8%8B?sort_id=11451209)
1. 单元测试
    - [ ] 已通过
    - [ ] 不涉及，无需验证

2. Compiler测试套
    - [ ] 已通过
    - [ ] 不涉及，无需验证

3. TSC extra测试套
    - [ ] 已通过
    - [ ] 不涉及，无需验证

4. Test262测试套
    - [ ] 已通过
    - [ ] 不涉及，无需验证

5. Benchmark测试
    - [ ] 已通过
    - [ ] 不涉及，无需验证

6. 应用自动化测试套
    - [ ] 已通过
    - [ ] 不涉及，无需验证

#### 兼容性测试（指令生成、文件格式修改时）
1. 小版本兼容性测试 <!-- 修改导致新abc无法运行在老镜像上时，需新增版本号 -->
    - [ ] 已增加版本号
    - [ ] 已通过
    - [ ] 不涉及，无需验证

2. 大版本兼容性测试 <!-- 配置target-api-version时，生成的abc需要能在对应版本运行-->
    - [ ] 已通过
    - [ ] 不涉及，无需验证

#### 性能测试 (新增语法检查等场景)
- [ ] 已通过
- [ ] 不涉及，无需验证

#### 指令/abc格式修改自检，需联系下方邮箱，同步至相关领域
- [ ] 涉及，已同步
- [ ] 不涉及

**Email:** chenqiuyao@huawei.com
