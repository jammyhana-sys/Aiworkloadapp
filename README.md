# DEMCO Timesheet (PWA)

โฟลเดอร์นี้คือแอปที่ติดตั้งบนมือถือได้ (Progressive Web App) — ไฟล์หลักคือ index.html

## วิธีใช้บนมือถือ
1. นำทั้งโฟลเดอร์ `pwa` ไปโฮสต์บนเว็บเซิร์ฟเวอร์ที่เป็น **https** (เช่น Azure Static Web Apps, SharePoint/IIS ของบริษัท)
   - อย่าโฮสต์โฟลเดอร์ `Workload Project` ทั้งโฟลเดอร์ เพราะมีไฟล์ Excel อื่นปะปนอยู่
2. เปิด URL บนมือถือ
   - iPhone (Safari): ปุ่มแชร์ > "เพิ่มลงในหน้าจอโฮม"
   - Android (Chrome): เมนู ⋮ > "ติดตั้งแอป" / "เพิ่มลงในหน้าจอหลัก"
3. ถ้าจะเปิดใช้ SSO ให้ตั้งค่า CONFIG ใน index.html และใช้ URL นี้เป็น Redirect URI (ชนิด SPA) ใน Entra ID

## ทดสอบบนเครื่อง
    python -m http.server 8765 --bind 127.0.0.1   (รันในโฟลเดอร์นี้) แล้วเปิด http://127.0.0.1:8765/

## หมายเหตุ
- Service worker จะทำงานเฉพาะบน https หรือ localhost ถ้าเปลี่ยนไฟล์แอปให้แก้เลข VER ใน sw.js เพื่อบังคับอัปเดตแคช
- ข้อมูลบันทึกงานเก็บในเครื่องมือถือของแต่ละคน (localStorage) ใช้ส่งออก Excel จากแท็บตั้งค่า (admin)

## ลืมรหัสผ่าน (ส่งอีเมลรีเซ็ต)
หน้าเว็บส่งอีเมลเองไม่ได้ ต้องตั้งค่า `CONFIG.mail` ใน index.html อย่างใดอย่างหนึ่ง:
- `provider:'emailjs'` — สมัคร emailjs.com ใส่ serviceId / templateId / publicKey (เทมเพลตใช้ {{to_email}} {{subject}} {{message}} {{reset_link}})
- `provider:'webhook'` — URL ของ Power Automate (HTTP request trigger) รับ JSON {to, subject, body, link} แล้วส่งผ่าน Outlook (ควรให้ Flow ตรวจว่า to ลงท้าย @demco.co.th)
- เว้นว่าง = ปิดฟีเจอร์ หน้า login จะบอกให้ติดต่อ Admin

ลิงก์รีเซ็ตใช้ได้ 30 นาที ครั้งเดียว และต้องเปิดบนอุปกรณ์เครื่องเดียวกับที่สร้างบัญชี (ข้อมูลเก็บในเบราว์เซอร์)
