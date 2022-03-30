## spring-core-rce

## 暂时不放 POC

提一嘴: CVE-2010-1622 的绕过也可以写入文件

ROOT.war 来自白帽汇的 vulfocus 镜像,直接放在 jdk9+ 的 tomcat 环境部署即可启动测试.

也可以自行使用 docker pull

```
docker run -d -p 8082:8080 --name springrce -it vulfocus/spring-core-rce-2022-03-29
```

然后访问 本地的 8082 端口，显示 OK,即运行成功


本地测试写入的文件截图:

<img width="1318" alt="image" src="https://user-images.githubusercontent.com/18260135/160864865-b1a1e71f-d462-45cf-9fbb-f1f20250c206.png">
