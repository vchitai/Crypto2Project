# Crypto2Project

[Update 29/06/2018]

*Thêm Video Demo*
*Sửa lỗi liên quan đến danh sách thuật toán mã hóa bất đối xứng*

[Update 28/06/2018]

*Thông tin lưu trong json được mã hóa bằng base64encoder*

![alt text][logo]

[logo]: /img/Demo.PNG "Demo"

## Demo ##

[![Alt Demo](https://img.youtube.com/vi/7ADGZjY-sLQ/0.jpg)](http://www.youtube.com/watch?v=7ADGZjY-sLQ)

## Export / Import thông tin tài khoản

Thông tin tài khoản khi đăng kí được export mặc định vào thư mục **user/email.usr**

Để import thêm tài khoản, đưa tập tin usr đúng format vào thư mục **user/**

## Đăng kí tài khoản

Thông tin cần nhập bao gồm:

- **Email**: email người dùng (dùng để định danh), theo đúng format (email@example.com)
- **Name**: tên người dùng, chỉ gồm ký tự a-z, A-Z và dấu cách, tối thiểu 3 ký tự
- **Password**: mật khẩu, ít nhất 1 ký tự số và 1 ký tự chữ cái a-z, A-Z, tối thiểu 6 ký tự
- **Phone**: số điện thoại, chỉ gồm ký tự số, gồm 7, 10, 11 số
- **Address**: địa chỉ, tùy chọn
- **Birthday**: ngày sinh, theo đúng format (dd/mm/YYYY)
- **Key length**: độ dài khóa RSA, lớn hơn 1024 và là bội số của 256

Thông tin được sinh thêm
- **Public key**: lưu trữ theo chuẩn PEM
- **Private key**: lưu trữ theo chuẩn PEM, được mã hóa bằng thuật toán **AES_MODE_EAX** với key là password được hash bằng thuật toán **SHAKE256**
- **Private tag**: giá trị hash **Private key** để xác nhận khi giải mã
- **Private nonce**: giá trị phụ được sinh thêm trong thuật toán **AES_MODE_EAX**

## Thay đổi thông tin tài khoản

*Cần xác nhận email và mật khẩu để tiếp tục*

**Muốn thay đổi trường nào thì nhập vào trường đó, nếu không thì để nguyên.**

Thông tin có thể sửa đổi bao gồm:
- **Name**: tên người dùng, chỉ gồm ký tự a-z, A-Z và dấu cách, tối thiểu 3 ký tự
- **Password**: mật khẩu, ít nhất 1 ký tự số và 1 ký tự chữ cái a-z, A-Z, tối thiểu 6 ký tự
- **Phone**: số điện thoại, chỉ gồm ký tự số, gồm 7, 10, 11 số
- **Address**: địa chỉ, tùy chọn
- **Birthday**: ngày sinh, theo đúng format (dd/mm/YYYY)

## Mã hóa tập tin

Thông tin cần cung cấp:

- **File**: Đường dẫn tập tin
- **Algorithm**: Thuật toán dùng để mã hóa
- **Receiver**: Email người nhận (phải có sẵn trong cơ sở dữ liệu aka thư mục **user/**)

Kết quả: Tập tin đã được mã hóa **\*.e**

Cấu trúc tập tin mã hóa (JSON):
```json
{
    "alg": "Thuật toán mã hóa",
    "secret_key": "Secret Key của thuật toán mã hóa đối xứng mã hóa bằng Public Key của người nhận",
    "cipher_text": "Dữ liệu mã hóa",
    "tag": "Băm dữ liệu gốc để xác nhận",
    "...": "Thông tin thêm cho từng thuật toán cụ thể"
}
```

Các thuật toán hỗ trợ:

- *Block Cipher*
    - **AES_MODE_EAX**
    - **AES_MODE_OCB**
    - **AES_MODE_CFB**
    - **AES_MODE_CTR**
    - **Single DES (Default MODE OFB)**
    - **RC2 (Default MODE CFB)**
- *Stream Cipher*
    - **ARC4**
    - **ChaCha20**
    - **Salsa20**
- *(Updating...)*

## Giải mã tập tin
*Cần xác nhận email và mật khẩu để tiếp tục*

Chọn tập tin được mã hóa đúng chuẩn được mã hóa bằng quá trình trên và dùng tài khoản của mình để giải mã.

Kết quả: Nếu đúng chuẩn và đúng chủ sở hữu, nhận được tập tin đã giải mã **\*.d** là nội dung file gốc trước khi mã hóa.

## Tạo chữ ký tập tin

*Cần xác nhận email và mật khẩu để tiếp tục*

Chọn tập tin và xác nhận đăng nhập để dùng khóa bí mật ký trên nội dung đã được băm của tập tin.

Kết quả: Tập tin đã được ký **\*.sig**

## Xác nhận chữ ký

Chọn tập tin cần xác nhận và tập tin chữ ký (**\*.sig**). Chương trình sẽ duyệt tìm cơ sở dữ liệu để tìm ra người đã ký tập tin.

Kết quả: Nhận được thông báo về người đã ký tập tin (Phải có trong cơ sở dữ liệu aka thư mục **user/**)

## Thư viện sử dụng

- **PyCryptodome**
- **Tkinter**