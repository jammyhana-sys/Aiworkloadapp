// Service worker: ทำให้แอปเปิดได้แม้ไม่มีเน็ต (ข้อมูลบันทึกงานอยู่ใน localStorage อยู่แล้ว)
const VER = 'timesheet-v116';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icon-192.png', './icon-512.png', './apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VER).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== VER).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET') return;
  // การล็อกอิน Microsoft ต้องไปที่เครือข่ายเสมอ ห้ามแคช
  if (/login\.microsoftonline\.com|login\.live\.com|graph\.microsoft\.com|supabase\.co|supabase\.in/.test(url.hostname)) return;
  // เปิดหน้าแอป: ลองเครือข่ายก่อนเพื่อรับเวอร์ชันใหม่ ถ้าไม่ได้ใช้แคช
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req, { cache: 'no-store' }).then(r => { caches.open(VER).then(c => c.put('./index.html', r.clone())); return r; })
      .catch(() => caches.match('./index.html')));
    return;
  }
  // ไฟล์อื่น (รวมไลบรารี CDN/ฟอนต์): ใช้แคชก่อนแล้วอัปเดตเบื้องหลัง
  e.respondWith(caches.match(req).then(hit => {
    const net = fetch(req).then(r => { if (r.ok || r.type === 'opaque') caches.open(VER).then(c => c.put(req, r.clone())); return r; }).catch(() => hit);
    return hit || net;
  }));
});
