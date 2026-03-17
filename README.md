<h1>使用教程:</h1>

<h2>支持 Windows, Linux, MacOS :</h2>
<ol>
  <li>安装 Python和pip(不会网络搜索教程)</li>
  <li>安装pycryptodome</li>
  <pre><code>pip install pycryptodome</code></pre>
  <li>完成后输入</li>
  <pre><code>python xiaomi_get_unlock-code.py</code></pre>
</ol>

## 说明:

1 - 参考项目 [Termux-miunlock](https://github.com/RohitVerma882/termux-miunlock)

2 - 获取登录token app(来自RohitVerma882):
[mi_account](https://www.123865.com/s/Q0TTjv-DEE13)

3 - 提交/使用过程:
使用fastboot工具!!!!

获取代号：fastboot getvar product

获取token：fastboot getvar token(高通)/fastboot oem get_token(联发科)
如果是联发科返回多少行token就合并多少，然后粘贴到命令行里
按两次回车继续提交就可看见返回的数据！

解锁文件使用：
1 - fastboot stage <文件>
2 - fastboot oem unlock(先拿到当前fastboot token提交后的的解锁文件在执行！不然提示token验证失败，重启设备)

## 作者:
[BEICHEN](https://space.bilibili.com/9784369)

[bgm145632](https://space.bilibili.com/618620472)
