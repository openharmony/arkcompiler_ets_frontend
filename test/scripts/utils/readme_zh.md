# utils包使用说明
## 脚本目的
* 下载测试所需要的镜像文件
* 获取烧录工具并烧录下载好的dayu镜像
* 获取前一天0点到脚本运行时这个时间段内仓库的提交信息
* 邮件自动发送测试结果

## 依赖安装
```
python3 -m pip install pywinauto lxml requests
```

## 注意事项
* sdk的存放路径需要按照新版idea中sdk路径的结构去严格填写
* 镜像地址这个参数如果后面不输入内容就会自动去官网获取镜像地址
* 不输入参数将按照配置去执行
