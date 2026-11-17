-- เก็บชื่อ/สีของประเภทที่ Admin แก้ไข (รันใน Supabase > SQL Editor หนึ่งครั้ง — ถ้าไม่รัน แอปยังใช้ได้ แต่ชื่อ/สีจะไม่ถูกบันทึกบนเซิร์ฟเวอร์)
create table if not exists public.app_settings (
  key   text primary key,
  value jsonb not null default '{}'::jsonb
);
alter table public.app_settings enable row level security;
revoke all on public.app_settings from anon;

drop policy if exists set_select on public.app_settings;
create policy set_select on public.app_settings for select to authenticated using (true);
drop policy if exists set_admin on public.app_settings;
create policy set_admin on public.app_settings for all to authenticated
  using (public.is_admin()) with check (public.is_admin());