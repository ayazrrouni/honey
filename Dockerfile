FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# تثبيت Python والمتطلبات
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    net-tools \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# نخلي python = python3
RUN ln -s /usr/bin/python3 /usr/bin/python

# مجلد التطبيق
WORKDIR /app

# ننسخو requirements
COPY requirements.txt .

# تثبيت مكتبات بايثون
RUN pip3 install --no-cache-dir -r requirements.txt

# ننسخو المشروع كامل
COPY . .

# فتح المنافذ
EXPOSE 2222 21 80

# الأمر الافتراضي
CMD ["python", "main.py"]
