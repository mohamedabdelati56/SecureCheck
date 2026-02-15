import socket
import re
import os
from datetime import datetime

class SecureCheck:
    def __init__(self):
        self.sensitive_patterns = {
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Credit Card": r'\b(?:\d[ -]*?){13,16}\b',  # نمط مبسط للبطاقات
            "IP Address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }

    def scan_ports(self, target_ip):
        """فحص المنافذ الشائعة لاكتشاف الثغرات المحتملة"""
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389]
        print(f"\n[+] Starting Port Scan on: {target_ip}")
        print(f"[+] Time: {datetime.now()}")
        
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"  [!] Port {port}: OPEN")
            s.close()

    def audit_file(self, file_path):
        """البحث عن بيانات حساسة داخل الملفات (Data Leakage Prevention)"""
        if not os.path.exists(file_path):
            print(f"[-] File {file_path} not found.")
            return

        print(f"\n[+] Auditing file for sensitive data: {file_path}")
        with open(file_path, 'r', errors='ignore') as file:
            content = file.read()
            for label, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    print(f"  [!] Found {len(matches)} potential {label}(s)!")

# --- تشغيل الأداة ---
if __name__ == "__main__":
    auditor = SecureCheck()
    
    # 1. فحص الجهاز المحلي كمثال (أو أي IP تصرح لك بفحصه)
    auditor.scan_ports("127.0.0.1")
    
    # 2. فحص ملف نصي (تأكد من وجود ملف تجريبي بجانب الكود)
    # auditor.audit_file("test_data.txt")