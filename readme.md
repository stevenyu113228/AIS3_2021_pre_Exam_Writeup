# AIS3 2021 Pre-Exam Writeup

這算是我第二次參加 AIS3 Pre-Exam ， 雖然是第二次參加，但我那個週末有很多其他的事情要忙 QQ ，真正解題的時間應該不超過三小時，不過名次竟然比上次(88名)上升了到了76名(???，滿奇妙的。

![](https://i.imgur.com/Dqi9flI.png)

這次我故意囤 Flag 在奇怪的時間一口氣交，看看用這種方式會不會被官方認定我是抄襲(?之類的，抽我寫 Writeup ，結果真ㄉ被抽到ㄌXDDDD
![](https://i.imgur.com/YOTP4C9.png)


總之，我覺得今年的題目相較於去年，難度提升了不少，增加了滿多的挑戰性，不過我覺得如果是以 MyFirstCTF 為基礎來看的話，這次的題目偏難，難太多了，對於初學非常的不友善。初學者看到這種等級的題目應該會嚇到QAQ，甚至有可能 MyFirstCTF 變成 MyLastCTF，希望未來主辦單位可以斟酌調整題目難度。


##  **[Welcome]** Cat Slayer ᶠᵃᵏᵉ | Nekogoroshi 
這一題印象中原本是 Misc 題目，不知道什麼時候被改成 Welcome 題目了。

題目主要就是給了下面這行，可以直接貼到 Terminal
`TERM=xterm-256color ssh -p 5566 h173@quiz.ais3.org`

會出現一個類似密碼鎖的東西，如果輸入錯誤就會跳 Error，輸入正確就可以再輸入下一個數字，很明顯就是一個暴力破解的題目。

Hint 上面有提供這一段： `process('TERM=xterm-256color ssh -p 5566 h173@quiz.ais3.org', shell=True, stdin=PTY)` 也就是提供給 pwntools 使用的腳本，滿貼心的。

但是根據本人精密的計算，透過 pwntools 寫腳本來暴力破解，跟徒手直接進行暴力破解，需要的時間應該差不多，都是 5\~10 分鐘，想當然，身為一個資深的工程師，在時間差不多ㄉ狀況下，誰會想寫程式呢？

所以我就開始徒手戳密碼了！
![](https://i.imgur.com/Eps1FKC.png)

約莫戳了七八分鐘，就試完了所有密碼，密碼是 `2025830455298` ，輸入完畢後，即可取得 FLAG。
![](https://i.imgur.com/7OMjyWs.png)

FLAG ： `AIS3{H1n4m1z4w4_Sh0k0gun}`

## **[Misc]** [震撼彈] AIS3 官網疑遭駭！ 
這一題提供了一個 pcap 檔案，又提到被駭相關的資訊，所以我原本覺得應該是一個數位鑑識的題目，解到後面才發現，還需要一點 Web 的技術。

首先，可以看到 pcap 檔案中主要有兩個 IP ，分別是 `10.153.11.112` 以及`10.153.11.126`。其中，`10.153.11.112`是 Client (Hacker) ， `10.153.11.126` 是 Server，而Server開的 Port 是 `8100` Port ， 其 Host Name 為 `magic.ais3.org`。
![](https://i.imgur.com/qRrvQIV.png)

接下來就使用 curl 直接訪問 `10.153.11.126` ，發現會是 Nginx Default page。
![](https://i.imgur.com/ZlYXAGa.png)

可以很明顯的猜測就是透過 VHost 之類的方法管制 Host Name，雖然 curl 應該加一個 option 就可以了，但想到等一下可能要用瀏覽器開，滿麻煩的，所以我選擇直接修改自己電腦ㄉ `/etc/hosts`，多加上以下這行
```
10.153.11.126 magic.ais3.org
```

接下來訪問 http://magic.ais3.org:8100/ 就能看到一個 CSS 跟 img 都爛掉的 ais3 官網，透過 pcap 裡面的路徑 `/index.php?page=bHMgLg%3d` 訪問，看不出什麼東西。但是依照直覺可以看出 `bHMgLg%3d` 應該是一段 base64 encode + URL Encode 後的字串，解碼後內容為 `ls .`，可以合理猜測這應該是一個 webshell。

這個時候有兩種解法，剛開始時我是用笨方法，後來才想到有更聰明的解法。先來分享笨解法。

因為最近在做的計畫跟分析 pcap 有關，所以我很直覺的想到說應該可以看 pcap 中的 string 成分進行統計，也就是輸入指令
`strings release.pcap | grep GET` ，就能看到所有 GET 的字串，在比眼力之下，就發現了有一個特別奇怪的 `Index.php`，他的 I 是大寫。

![](https://i.imgur.com/87UtA7U.png)


聰明的解法是， Wireshark 上方工具列有一個 Statistics，裡面就有 HTTP 的分析器，
![](https://i.imgur.com/h5gmuCM.png)

按下去後就可以看到 HTTP 的分析結果。
![](https://i.imgur.com/IlGDeER.png)

觀察後面的 payload 是先前的字串反轉，所以修改一下，把輸入轉 base64 再翻轉字串即可控制 shell！

最後，把上述的內容寫成腳本就完成ㄌ！
```python=
import requests
import base64

while True:
    a = input("> ").encode("ASCII")
    a = base64.b64encode(a)
    a = requests.utils.quote(a)
    a = a[::-1]
    res = requests.get("http://magic.ais3.org:8100/Index.php?page=" + a)
    print(res.text)
```
![](https://i.imgur.com/AS6XYRY.png)
FLAG : `AIS3{0h!Why_do_U_kn0w_this_sh3ll1!1l!}`

## **[Web]** Ӌҽէ Ⱥղօէհҽɾ Ꝉօցïղ φąցҽ!
這題其實算是滿老梗的 injection 題目，只是頁面超級ㄎㄧㄤ......
![](https://i.imgur.com/Icr8lVI.png)

這種題目解題的重點是，有提供原始碼就盡量在自己的電腦上架起來測。這邊雖然沒有提供 templates 的原始檔案，可以自己把 html 載下來簡單改一下就好，順便把ㄐㄅ的 CSS 給拔掉。

接下來在原始碼中插入一些 print 檢查輸入的東西長的樣子。

```python
@app.route("/")
def index():
    def valid_user(user):
        print(None == user['password'])
        return users_db.get(user['username']) == user['password']

    if 'user_data' not in session:
        return render_template("login.html", message="Login Please :D")

    user = json.loads(session['user_data'])
    # print(user)
    if valid_user(user):
        # print(user)
        if user['showflag'] == True and user['username'] != 'guest':
            return FLAG
        else:
            return render_template("welcome.html", username=user['username'])

    return render_template("login.html", message="Verify Failed :(")


@app.route("/login", methods=['POST'])
def login():
    data = '{"showflag": false, "username": "%s", "password": "%s"}' % (
        request.form["username"], request.form['password']
    )
    print(data)
    session['user_data'] = data
    return redirect("/")
```

其中，第一步驟是可以透過 data 的 json 建構任意的 payload ， 其中重點是 json.loads 遇到相同ㄉ key 會選擇讀取後面的那個
```python
json.loads("""{"A":"B","A":"C"}""")
# 回傳 {"A":"C"}
```
透過這招就可以建構`showflag`為 `true`， json 中的 `true` 會被解析為 Python 的 `True`，所以這邊也不能直接輸入 `"True"` 的字串，會被當成字串解析

接下來，DB的.get如果查無資料會回傳 Python 的 None，所以我們要在密碼中建構 `None` ， 在 json 中即為 `null`

最後透過 Postman 傳送給 Server 即可！
![](https://i.imgur.com/C1iemJv.png)
FLAG : `AIS3{/r/badUIbattles?!?!}`


## **[Web]** HaaS
一直覺得這一題滿通靈的，介面就是這樣可以戳任何地方？
然後如果戳 `127.0.0.1` 會出現`Don't Attack Server!`
![](https://i.imgur.com/ed9vLgr.png)

猜測應該是 SSRF ，接下來我就開始掃內網 IP 了，但都沒什麼結果 QQ。

後來臨時想到可以嘗試看看用其他方法戳`127.0.0.1`，我使用的方法是直接用數字來代表ip的方式，也就是 `(127 << 24) + 1 = 2130706433` 。

接下來 URL填 `http://2130706433/haas` 這樣會出現 404 的 error
![](https://i.imgur.com/hGYVjDr.png)

觀察 post 出去ㄉ資料會發現，他 Post 了兩個參數， URL 以及 status
![](https://i.imgur.com/b0CjWSO.png)
藏在原始碼的一個 hidden input
![](https://i.imgur.com/mgM5ng9.png)

透過 F12 功能的修改並重新發送，把 200 改成 404，預期這邊發出ㄉ東西應該會是他期望取得的 status code。
![](https://i.imgur.com/DCOf540.png)

可惜他只會回答 "Alive"

接下來我就亂試，把他亂改成 500 錯誤看看
![](https://i.imgur.com/Kkt1Ko3.png)

然後就莫名其妙拿到 Flag ㄌ
![](https://i.imgur.com/sQTTMLW.png)

FLAG : `AIS3{V3rY_v3rY_V3ry_345Y_55rF}`

## **[Crypto]** Microchip
這題真ㄉ有夠ㄎㄧㄤ，看起來是一個很 Python 的 Cpp

![](https://i.imgur.com/jyb7WDI.png)

原本想說就不管了，直接 Compile 看看，反正他的ㄎㄧㄤㄎㄧㄤ.h檔案也有提供，但卻 Compile 失敗 QAQ
![](https://i.imgur.com/9UeHTAe.png)


最主要的問題是他的冒號`꞉`不是真正的冒號
![](https://i.imgur.com/5F7tAQ3.png)

讓我想到ㄌ這個 Meme
![](https://i.imgur.com/1IdV3sU.png)

但後來我也懶得用這個思路ㄌ，想說他既然長得很像 Python ，那就直接拿去 Python 上面跑跑看。
```python=
def track(name, id):
    if len(name) % 4 == 0:                    
        padded = name + "4444"
    elif len(name) % 4 == 1 :                  
        padded = name + "333"
    elif len(name) % 4 == 2 :
        padded = name + "22"                    
    elif len(name) % 4 == 3 :                  
        padded = name + "1"                     

    keys = list()                               
    temp = id                                   
    for i in range(4) :                        
        keys.append(temp % 96)                  
        temp = int(temp / 96)                   

    result = ""                                 
    for i in range(0, len(padded), 4) :        
        nums = list()                           
        for j in range(4) :                    
            num = ord(padded[i + j]) - 32       
            num = (num + keys[j]) % 96          
            nums.append(num + 32)               

        result += chr(nums[3])                  
        result += chr(nums[2])                  
        result += chr(nums[1])                  
        result += chr(nums[0])                  

    return result                               


def main():                            

    name = open("flag.txt", "r").read().strip() 
    id = int(input("key = "))                   

    print("result is:", track(name, id))        
    return 0                                    

if __name__ == '__main__':
    main()
```

基本上他會把字串每 4 個一組，與 key 做一些處理，再用翻轉的方式存，我們只知道加密結果卻不知道 key。但知道會與 key 做一些動作，而且有一個 `%96`，所以就姑且用 0~95 來暴力破解密碼ㄅ！！

ㄛ忘了說到，這邊的key指的是程式碼裡面的 keys ， 因為之後都是使用 keys 做運算，所以最原先輸入的 key 就沒有很重要了。

到此為止，我們可以知道，`;=Js&` 分別對應到了 FLAG 的開頭 `}3SIA`
透過這4個的暴力破解，就可以得知 keys = [69, 42, 87, 10]

其實幾下來可以把程式碼的所有功能做反運算，但我覺得好麻煩ㄛ......，所以我的解法是，直接去暴力窮舉所有 printable 的 ASCII 再與加密後字串比對，雖然這對於電腦而言不是最有效率的方法，但 FLAG 只有數十個字，對於電腦而言應該不用 1 秒的時間就能爆破完。這樣就能拿到 FLAG 了！

總而言之，先透過固定的開頭 `AIS3{` 來爆破 keys，再透過 printable ascii 搭配 keys 的運算來爆破 FLAG。

完整程式碼如下
```python=
import string
"""
;=Js&
}3SIA
A = 65
& = 38
"""

cipher = "=Js&;*A`odZHi'>D=Js&#i-DYf>Uy'yuyfyu<)Gu"
re_cipher = [cipher[i:i+4] for i in range(0,len(cipher),4)] # 每4個一組
re_cipher = [i[::-1] for i in re_cipher] # 翻轉
block0 = re_cipher[0]
re_cipher = ''.join(re_cipher)

def gen_key(plain,cipher):
    for key in range(96):
        num = ord(plain) - 32
        num = (num + key) % 96
        num += 32
        if num == ord(cipher):
            return key

plain_text_head = list("AIS3")
block0 = list(block0) # &sJ=

keys = list()
for i in range(len(plain_text_head)):
    keys.append(gen_key(plain_text_head[i],block0[i]))

print(keys)

sol = ''
for i in range(0,len(re_cipher),4):
    for j in range(4):
        for s in string.printable:
            num = ord(s) - 32       
            num = (num + keys[j]) % 96
            num += 32        
            if num == ord(re_cipher[i + j]):
                # print(s,end='')
                sol += s
                print(sol)
                break
# print(sol)
```

FLAG : `AIS3{w31c0me_t0_AIS3_cryptoO0O0o0Ooo0}`

## **[Misc]** Blind
這一題我覺得滿好玩的，首先 nc 上去之後會要你指定各 reg 的值，接下來就會依照這些暫存器來發 System Call。

![](https://i.imgur.com/Lnsoca0.png)


相關 System call 可以參考以下的網址，簡單來說只要把 reg 裏面放入指定ㄉ值，再執行 system call 就是執行該 function。
https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

看一下重點部分的程式碼
```c=
close(1);
make_a_syscall();
int fd = open("flag", O_RDONLY);
char flag[0x100];
size_t flag_len = read(fd, flag, 0xff);
write(1, flag, flag_len);
```
這邊的需要先了解到 Linux 的 fd [(File descriptor)](https://zh.wikipedia.org/wiki/文件描述符)檔案闡述者(??
其中 0 是 stdin ， 1 是 stdout , 2 是 stderr

程式碼先把 stdout 的 pipe 關閉，接下來讀取 flag ，再透過 write 放到 stdout 上面。但問題是 stdout 已經被關掉ㄌQQ。

這個時候可以使用 dup 指令，他是 duplicate 的縮寫，也就是複製的意思。

查詢上述的網址可以發現 dup 指令是 rax=32 ， 接下來既然被關掉了，我猜(? 他應該會跑去 stderr (rdi=2) ，所以就嘗試寫過去，其他值就都給他的87，理論上給他隨便的數字都可以，正常人應該是會給他0ㄅ。

![](https://i.imgur.com/SxPAkee.png)

最後就成功透過 dup 把資料從 stderr 給複製回來ㄌ。 (其實這邊我沒有找到可靠的來源證明說法正確，但...，無論如何，這樣就可以解出
 Flag ㄌ！)

Flag : `AIS3{dupppppqqqqqub}`

## **[Crypto]** ReSident evil villAge
先 nc 上去看看狀況，可以看到有 n 跟有 e ，e 又是65537，很直觀的，這題目應該跟 RSA 有關，又看到了 sign 跟 verify ，推測也跟 MAC 有關，好想換 M1ㄛ...(X。這邊的 MAC是指(Message Authentication Code)

![](https://i.imgur.com/TvUSlmP.png)
題目的說法是，我要想辦法幫 `Ethan Winters` 給 Sign。

那很直覺的，我們可以就字面上意思幫 `Ethan Winters` sign 看看，他說需要用 hex 模式，所以可以先進行轉換
```python=
import binascii
binascii.b2a_hex(b"Ethan Winters")
# b'457468616e2057696e74657273'
```
可以得知`Ethan Winters`的hex為`457468616e2057696e74657273`
![](https://i.imgur.com/KvFYx8J.png)
可惜他跟我講了一個 Nice Try QQQ

接下來選擇來看一下 Source Code，註解的地方滿明顯的給了提示。

```python=
sig = pow(bytes_to_long(msg), privkey.d, n)     
# TODO: Apply hashing first to prevent forgery
```

既然有 TODO: 所以我可以視為這個功能目前還沒完成，要防止 forgery(偽造)。透過 Google 可以查詢到 Digital signatures forgery 的維基百科 https://en.wikipedia.org/wiki/Digital_signature_forgery

再來通個靈(對，我解Crypto就是基於通靈，因為我的Crypto基礎不好，數學也不好QQ)，直接看到維基百科其中一個(Existential forgery (existential unforgeability, EUF))有給範例，那就來測測看。

$$\sigma(m_1) \cdot \sigma(m_2) = \sigma(m_1 \cdot m_2)$$

所以我可以嘗試先把`Ethan Winters` 的 Bytes 分成兩半來做 sign，再手動乘起來。

前面得知 `Ethan Winters`的hex為`457468616e2057696e74657273`，十進位為`5502769663009776377079720669811`
透過 factordb.com 可以知道 `5502769663009776377079720669811 = 163 * 33759323085949548325642458097`

而其中
`hex(163) = 0xa3`
`hex(33759323085949548325642458097) = 0x6d150ebb92427fdc8e1053f1`

如果可以成功適用 EUF 的話，我們只要把這兩個值分別 sign 並相乘，再 mod n，就Verify就過了！
有一個小小被雷到的點是，他最後吃的是int不是hex，然後乘完忘記 mod n

![](https://i.imgur.com/52FtZ9O.png)

![](https://i.imgur.com/EXNqrZs.png)

Flag : `AIS3{R3M383R_70_HAsh_7h3_M3Ssa93_83F0r3_S19N1N9}`

