-- รันไฟล์นี้ใน Supabase > SQL Editor (ฐานข้อมูลที่สร้างไว้แล้ว) เพื่อเปิดระบบ "Admin อนุมัติก่อนใช้งาน"
alter table public.employees add column if not exists approved boolean not null default false;

-- บัญชีที่มีอยู่แล้ว (Admin และคนที่สมัครไว้แล้ว) ให้ถือว่าอนุมัติแล้ว
update public.employees set approved = true where role = 'admin' or user_id is not null;

-- สิทธิ์เข้าถึงข้อมูลต้องผ่านการอนุมัติเท่านั้น
create or replace function public.my_emp_id() returns text
language sql stable security definer set search_path = public as $$
  select id from public.employees where user_id = auth.uid() and active and approved limit 1
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' from public.employees where user_id = auth.uid() and active and approved limit 1), false)
$$;
