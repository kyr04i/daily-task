# 1.0
![alt text](image.png)
- Level cho ta các function để lựa chọn
- Thấy có function `read_flag`
![alt text](image-1.png) 
- `read_flag` sẽ gọi `malloc` và flag sẽ được lưu tại đó
- Xem hàm còn lại
![alt text](image-3.png)
- Để đọc flag thì cần `flag_buffer` bằng địa chỉ của `allocations[0]`
- Cần `malloc` với kích thước bằng với kích thước `flag_buffer` đã `malloc`, sau đó `free` và gọi lại hàm `read_flag`, khi đó chunk với kích thước đó sẽ được sử dụng lại và sẽ đọc được flag
![alt text](image-4.png)

# 1.1
- Level này không cho ta biết được hàm `read_flag` sẽ malloc với kích thước bao nhiêu
![alt text](image-5.png)
- Debug để xem đã malloc với kích thước là bao nhiêu 
![alt text](image-6.png)
- ta thấy trước khi malloc thì tham số `rdi` được lấy từ `rbp-0xa0` , đặt breakpoint tại hàm `malloc` và xem tại địa chỉ `rbp-0xa0`
![alt text](image-7.png)
> 0x11f = 287
- Tương tự level 1.0
![alt text](image-8.png)