BÁO CÁO ĐIỀU TRA SỰ CỐ AN NINH MẠNG VÀ PHÁT HIỆN MỐI ĐE DỌA TRÊN SPLUNK SIEM
I. TỔNG QUAN SỰ CỐ (EXECUTIVE SUMMARY)
1. Thông tin sự cố
Thuộc tính	Chi tiết
Mã sự cố	INC-2026-BOTS-001
Loại sự cố	Web Application Reconnaissance and Vulnerability Scanning
Mức độ rủi ro sơ bộ	High
Ngày phân tích	10/10/2026
Nền tảng SIEM	Splunk Enterprise
Tập dữ liệu	Splunk BOTS v1 (Boss of the SOC)
Nguồn nhật ký	IIS Access Logs
Sourcetype	_json
Địa chỉ IP đáng ngờ	40.80.148.42
Ứng dụng mục tiêu	Joomla CMS
Ngôn ngữ truy vấn	Splunk Processing Language (SPL)
2. Tóm tắt sự cố

Trong quá trình phân tích nhật ký truy cập máy chủ web IIS trên Splunk SIEM, địa chỉ IP 40.80.148.42 được xác định là nguồn phát sinh lưu lượng đáng chú ý.

Kết quả truy vấn ban đầu ghi nhận tổng cộng 22.616 sự kiện, trong đó địa chỉ IP trên chiếm 20.967 sự kiện, tương đương khoảng 92,71% tổng số sự kiện được thống kê.

Các yêu cầu tập trung vào những đường dẫn thuộc ứng dụng Joomla, bao gồm giao diện tìm kiếm và khu vực quản trị. Những đặc điểm này có thể phản ánh hoạt động thu thập thông tin hoặc rà quét ứng dụng web tự động.

Tuy nhiên, số lượng yêu cầu lớn và việc truy cập các endpoint nhạy cảm chưa đủ để khẳng định đối tượng đã khai thác thành công lỗ hổng, chiếm quyền quản trị hoặc thực thi mã từ xa (RCE). Các giả thuyết này cần được xác minh bằng những bằng chứng bổ sung.

II. MÔI TRƯỜNG PHÂN TÍCH VÀ CÔNG CỤ
Thành phần	Mô tả
Nền tảng SIEM	Splunk Enterprise 10.6.0.5
Hệ điều hành	Ubuntu Linux
Tập dữ liệu đầu vào	botsv1.iis.json
Nguồn nhật ký	Microsoft IIS
Sourcetype	_json
Ngôn ngữ truy vấn	Splunk Processing Language (SPL)
Công cụ hỗ trợ	Git, GitHub, Visual Studio Code
Mục tiêu điều tra
Phát hiện nguồn tạo ra lưu lượng HTTP bất thường.
Phân tích phương thức HTTP, endpoint và mã trạng thái phản hồi.
Xây dựng dòng thời gian của hoạt động đáng ngờ.
Xác định các chỉ dấu phục vụ quá trình điều tra.
Đánh giá rủi ro và đề xuất biện pháp ứng phó.
III. QUY TRÌNH ĐIỀU TRA VÀ PHÂN TÍCH BẰNG CHỨNG
1. Phát hiện lưu lượng bất thường và xác định địa chỉ IP đáng ngờ
1.1. Mục tiêu

Thống kê số lượng sự kiện theo địa chỉ IP nguồn nhằm xác định các nguồn tạo ra lưu lượng lớn bất thường trong tập dữ liệu.

1.2. Truy vấn SPL
index=* sourcetype="_json"
| stats count BY result.c_ip
| sort - count
1.3. Giải thích truy vấn
index=*: Tìm kiếm trên các index mà tài khoản có quyền truy cập.
sourcetype="_json": Lọc các sự kiện có sourcetype _json.
stats count BY result.c_ip: Đếm số sự kiện theo từng địa chỉ IP nguồn.
sort - count: Sắp xếp kết quả theo số lượng sự kiện giảm dần.
1.4. Kết quả và phân tích

Kết quả truy vấn ban đầu ghi nhận:

Tổng số sự kiện: 22.616.
Số sự kiện liên quan đến IP 40.80.148.42: 20.967.
Tỷ lệ sự kiện của IP này: khoảng 92,71%.

Tỷ lệ lưu lượng tập trung cao cho thấy địa chỉ IP trên cần được ưu tiên điều tra. Tuy nhiên, số lượng sự kiện lớn không tự nó chứng minh đây là một cuộc tấn công. Cần kết hợp tần suất truy cập, nội dung yêu cầu, endpoint và ngữ cảnh hệ thống để xác định bản chất hoạt động.

Kết luận bước 1: Địa chỉ IP 40.80.148.42 được xác định là nguồn lưu lượng đáng ngờ cần phân tích sâu hơn.

2. Phân tích hành vi truy cập, phương thức HTTP và endpoint mục tiêu
2.1. Mục tiêu

Xác định các đường dẫn được truy cập nhiều nhất, phương thức HTTP được sử dụng và mã trạng thái do máy chủ trả về.

2.2. Truy vấn SPL
index=* sourcetype="_json" result.c_ip="40.80.148.42"
| stats count BY result.cs_method result.cs_uri_stem result.sc_status
| sort - count
2.3. Giải thích truy vấn
result.c_ip="40.80.148.42": Lọc sự kiện theo địa chỉ IP đang điều tra.
stats count BY result.cs_method result.cs_uri_stem result.sc_status: Thống kê sự kiện theo phương thức HTTP, đường dẫn URI và mã trạng thái phản hồi.
sort - count: Sắp xếp theo số lượng sự kiện giảm dần.
2.4. Phân tích kết quả

a. Endpoint tìm kiếm Joomla

Đường dẫn cần chú ý:

/joomla/index.php/component/search/

Endpoint này cần được kiểm tra về tần suất truy cập, tham số tìm kiếm và nội dung truy vấn. Nếu các yêu cầu lặp lại với nhiều chuỗi đầu vào khác nhau hoặc chứa dấu hiệu kiểm thử lỗ hổng, chúng có thể phản ánh hoạt động rà quét tự động.

Chỉ dựa vào đường dẫn trên chưa đủ để kết luận có hành vi SQL Injection, Command Injection hoặc một phương thức khai thác cụ thể.

b. Trang chính và khu vực quản trị

Các đường dẫn cần kiểm tra:

/joomla/index.php

/joomla/administrator/index.php

Lưu lượng tập trung vào các endpoint này có thể liên quan đến việc thu thập thông tin về ứng dụng và xác định giao diện quản trị.

Để kết luận có hành vi dò mật khẩu (Brute Force), cần kiểm tra thêm số lần đăng nhập thất bại, tham số xác thực, mã phản hồi và nhật ký đăng nhập. Việc truy cập trang đăng nhập nhiều lần không tự động đồng nghĩa với Brute Force.

c. Phân tích mã trạng thái HTTP

Mã trạng thái	Ý nghĩa	Giá trị điều tra
200 OK	Yêu cầu được xử lý thành công ở cấp HTTP	Cần kiểm tra nội dung phản hồi để xác định dữ liệu được trả về
302 Found	Chuyển hướng tạm thời	Có thể liên quan đến điều hướng hoặc xác thực
304 Not Modified	Tài nguyên không thay đổi theo cơ chế bộ nhớ đệm	Không phải dấu hiệu tấn công nếu đứng riêng lẻ
404 Not Found	Không tìm thấy tài nguyên	Có thể xuất hiện khi dò tìm đường dẫn
500 Internal Server Error	Máy chủ gặp lỗi khi xử lý yêu cầu	Cần đối chiếu nhật ký ứng dụng để tìm nguyên nhân

Các mã trạng thái trên cung cấp thêm ngữ cảnh cho quá trình điều tra. Đặc biệt, mã 500 cần được đối chiếu với nhật ký ứng dụng và máy chủ để xác định liệu lỗi có liên quan đến đầu vào bất thường hay nguyên nhân vận hành thông thường.

Kết luận bước 2: Các endpoint Joomla và sự phân bố phương thức HTTP là cơ sở để đánh giá giả thuyết rà quét ứng dụng web. Cần kiểm tra nội dung yêu cầu và phản hồi để xác định chính xác hơn hành vi của nguồn đáng ngờ.

3. Phân tích diễn tiến sự cố theo dòng thời gian
3.1. Mục tiêu

Xây dựng dòng thời gian của các sự kiện để xác định giai đoạn lưu lượng tăng cao và những endpoint nổi bật trong quá trình hoạt động đáng ngờ.

3.2. Truy vấn SPL
index=* sourcetype="_json" result.c_ip="40.80.148.42"
| timechart span=1m limit=5 count BY result.cs_uri_stem
3.3. Giải thích truy vấn
timechart: Tổng hợp dữ liệu theo thời gian.
span=1m: Chia dữ liệu thành các khoảng thời gian một phút.
limit=5: Giới hạn số chuỗi được hiển thị trong biểu đồ.
count BY result.cs_uri_stem: Thống kê số sự kiện theo URI trong từng khoảng thời gian.
3.4. Kết quả và phân tích

Theo kết quả quan sát ban đầu:

Phạm vi thời gian được sử dụng: Last 4 hours.
Thời điểm lưu lượng tăng mạnh được mô tả: khoảng 2:30 PM.
Endpoint tìm kiếm Joomla được ghi nhận là một trong những đường dẫn nổi bật trong giai đoạn lưu lượng tăng cao.

Mức lưu lượng khoảng 15.000 yêu cầu/phút được nêu trong kết quả phân tích ban đầu. Số liệu này cần được xác minh trực tiếp trên biểu đồ hoặc kết quả truy vấn Splunk trước khi đưa vào kết luận chính thức.

Nếu được xác nhận, mức lưu lượng trên tương đương trung bình khoảng 250 yêu cầu mỗi giây trong một phút quan sát.

Cần xác nhận ngày, múi giờ và timestamp thực tế của sự kiện vì thời gian hiển thị trên Splunk phụ thuộc vào cấu hình và phạm vi thời gian được chọn.

Kết luận bước 3: Phân tích chuỗi thời gian hỗ trợ xác định giai đoạn hoạt động tập trung của nguồn đáng ngờ. Việc xác nhận đỉnh lưu lượng cần dựa trên kết quả thực tế của truy vấn.

IV. TỔNG HỢP CHỈ DẤU VÀ ĐÁNH GIÁ TÁC ĐỘNG
1. Indicators of Compromise (IoCs)
Loại chỉ dấu	Giá trị	Ý nghĩa
IP nguồn	40.80.148.42	Nguồn tạo ra lưu lượng cần điều tra
Ứng dụng mục tiêu	Joomla CMS	Ứng dụng xuất hiện trong các đường dẫn được truy cập
Endpoint tìm kiếm	/joomla/index.php/component/search/	Endpoint cần kiểm tra tần suất và tham số đầu vào
Endpoint quản trị	/joomla/administrator/index.php	Đường dẫn liên quan đến giao diện quản trị
Phương thức HTTP	GET, POST	Các phương thức được ghi nhận trong hoạt động truy cập
Đặc điểm lưu lượng	Số lượng sự kiện tập trung cao	Dấu hiệu cần phân tích về hành vi tự động

Địa chỉ IP trong tập dữ liệu được sử dụng làm chỉ dấu phục vụ điều tra, không mặc nhiên chứng minh chủ sở hữu IP là tác nhân độc hại.

2. Đánh giá mức độ ảnh hưởng

Tính sẵn có (Availability)

Lưu lượng HTTP tăng cao có thể làm tăng mức sử dụng CPU, bộ nhớ, băng thông hoặc số lượng kết nối của máy chủ web. Tuy nhiên, để xác định ảnh hưởng thực tế đến tính sẵn có, cần bổ sung số liệu tài nguyên hệ thống, thời gian phản hồi và lỗi dịch vụ.

Tính bảo mật (Confidentiality)

Việc truy cập các endpoint công khai không đồng nghĩa với việc dữ liệu nhạy cảm đã bị tiết lộ. Cần kiểm tra nội dung phản hồi, các yêu cầu truy cập tệp nhạy cảm và nhật ký ứng dụng để xác định có xảy ra truy cập trái phép hay không.

Tính toàn vẹn (Integrity)

Dữ liệu hiện có chưa đủ để xác nhận tệp tin hoặc dữ liệu ứng dụng đã bị sửa đổi. Việc đánh giá cần bổ sung nhật ký thay đổi tệp, nhật ký quản trị và dấu hiệu thực thi mã bất thường nếu có.

3. Đánh giá rủi ro tổng thể

Dựa trên số lượng sự kiện lớn, mức độ tập trung vào một địa chỉ IP và các endpoint thuộc Joomla, hoạt động này cần được ưu tiên điều tra.

Mức độ ưu tiên High được đề xuất cho mục đích phân loại và xử lý ban đầu. Đây là đánh giá rủi ro sơ bộ, không phải kết luận rằng hệ thống đã bị xâm nhập hoặc lỗ hổng đã bị khai thác thành công.

V. KHUYẾN NGHỊ VÀ PHƯƠNG ÁN ỨNG PHÓ
1. Hành động ưu tiên

1.1. Xác minh nguồn lưu lượng

Kiểm tra các sự kiện gốc của IP 40.80.148.42.
Xác định thời gian bắt đầu, thời gian kết thúc và tốc độ yêu cầu.
Kiểm tra URI, tham số truy vấn và mã trạng thái HTTP.
Đối chiếu nhật ký IIS, nhật ký ứng dụng và nhật ký xác thực.

1.2. Kiểm soát lưu lượng

Nếu hoạt động tiếp tục diễn ra và được xác định là độc hại, đội ngũ vận hành có thể áp dụng biện pháp giới hạn tốc độ, chặn IP hoặc tạo quy tắc WAF phù hợp.

Trước khi chặn IP, cần đánh giá nguy cơ ảnh hưởng đến người dùng hợp lệ hoặc các dịch vụ dùng chung hạ tầng.

1.3. Bảo toàn bằng chứng

Lưu lại các truy vấn SPL đã sử dụng.
Xuất các sự kiện liên quan.
Ghi nhận thời điểm truy vấn, phạm vi thời gian và múi giờ.
Bảo toàn nhật ký gốc phục vụ điều tra tiếp theo.
2. Biện pháp phòng thủ dài hạn

2.1. Tăng cường giám sát bằng SIEM

Xây dựng các cảnh báo dựa trên:

Số lượng yêu cầu HTTP từ một IP trong khoảng thời gian ngắn.
Tần suất truy cập cao vào các endpoint nhạy cảm.
Tỷ lệ phản hồi 404 hoặc 500 bất thường.
Nhiều yêu cầu có dấu hiệu kiểm thử đầu vào hoặc dò tìm đường dẫn.
Các chuỗi sự kiện đáng ngờ kết hợp nhiều dấu hiệu khác nhau.

Các ngưỡng cảnh báo cần được điều chỉnh theo lưu lượng nền thực tế để hạn chế cảnh báo sai.

2.2. Tăng cường bảo vệ ứng dụng web

Triển khai WAF và cấu hình quy tắc phát hiện phù hợp.
Áp dụng Rate Limiting cho các endpoint có nguy cơ bị lạm dụng.
Cập nhật Joomla, plugin và extension lên phiên bản được nhà cung cấp hỗ trợ.
Rà soát quyền truy cập, cấu hình xác thực và nhật ký quản trị.
Tắt Directory Browsing nếu không có nhu cầu nghiệp vụ.
Kiểm tra lỗi ứng dụng và cấu hình máy chủ phát sinh trong thời gian có lưu lượng bất thường.

2.3. Quy trình phản ứng sự cố SOC

Detect: Phát hiện lưu lượng bất thường qua truy vấn và cảnh báo SIEM.
Triage: Xác minh nguồn, thời gian, endpoint và mức độ đáng ngờ.
Investigate: Đối chiếu nhật ký IIS, ứng dụng và các nguồn dữ liệu liên quan.
Contain: Giới hạn hoặc chặn lưu lượng khi có đủ cơ sở.
Eradicate and Recover: Khắc phục nguyên nhân nếu phát hiện lỗ hổng hoặc hệ thống bị xâm nhập.
Lessons Learned: Cập nhật quy tắc phát hiện và tài liệu ứng phó dựa trên kết quả điều tra.
VI. KẾT LUẬN

Quá trình phân tích dữ liệu IIS trên Splunk SIEM cho thấy địa chỉ IP 40.80.148.42 tạo ra số lượng sự kiện đáng kể và có hoạt động truy cập tập trung vào các endpoint thuộc Joomla CMS.

Ba nhóm phân tích chính gồm thống kê lưu lượng theo IP, phân tích phương thức HTTP và endpoint, cùng với dựng dòng thời gian, cung cấp cơ sở ban đầu để nhận diện hoạt động có dấu hiệu rà quét ứng dụng web tự động.

Kết quả điều tra cho thấy cần ưu tiên xác minh nguồn lưu lượng và kiểm tra sâu hơn các yêu cầu đáng ngờ. Tuy nhiên, dữ liệu hiện có chưa đủ để khẳng định việc khai thác lỗ hổng thành công, rò rỉ dữ liệu hoặc chiếm quyền kiểm soát máy chủ.

Các bước tiếp theo nên tập trung vào xác minh sự kiện gốc, đối chiếu nhật ký ứng dụng, xác nhận số liệu lưu lượng và triển khai biện pháp phòng thủ phù hợp với bằng chứng thu thập được.

Báo cáo này thể hiện quy trình thực hành phân tích nhật ký, sử dụng SPL để điều tra và tổng hợp chỉ dấu phục vụ hoạt động giám sát an ninh mạng theo quy trình SOC.