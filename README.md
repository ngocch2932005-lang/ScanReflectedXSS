B1: Cài đặt môi trường sử dụng Anaconda
    - tạo môi trường conda create -n [Tên_môi_trường] python=3.12
    - kích hoạt môi trường conda activate [Tên_môi_trường]

B2: Tải về project Cài đặt các gói cần thiết
    git clone https://github.com/ngocch2932005-lang/ScanReflectedXSS.git
    pip install -r requirements.txt
    Sau đó dùng lệnh: python -m playwright install. Để tải về trình duyệt sử dụng cho playwright

B3: Truy cap thu muc project: python main.py [URL_Target]