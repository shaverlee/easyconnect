
一个python小程序，可以自动控制深信服EasyConnect的连接/断开，而避免手工使用界面登录/注销。
EasyConnect的客户端程序，包括系统服务程序和使用界面部分。本程序通过模拟使用界面部分，和系统服务程序通讯，达到控制连接/断开的目的。为了使用本程序，你仍旧需要安装EasyConnect。

### 使用方法
1. 确保EasyConnect的系统服务处于运行中。
2. 修改easyconnect.py文件，填入你的连接地址/用户名/密码。
3. 在命令行
   <blockquote>
       <p>python3 easyconnect.py</p>
   </blockquote>
   或在你的.py文件中
   <blockquote>
       <p>import easyconnect</p>
       <p>easyconnect.start()</p>
       <p>...</p>
       <p>easyconnect.stop()</p>
   </blockquote>
   
### 免责声明
1. EasyConnect的一切权利属深信服所有，本程序开发者不做任何保证，使用者使用本程序产生的一切法律纠纷由使用者自行承担。
2. 如果深信服认为本程序侵犯了深信服的任何权利，请联系开发者（372567610@qq.com）删除。
