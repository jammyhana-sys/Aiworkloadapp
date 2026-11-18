-- รวมทุกไฟล์อัปเดตฐานข้อมูล (v31–v49) รันซ้ำได้ ไม่เสียหาย — วางทั้งไฟล์ใน Supabase > SQL Editor แล้วกด Run

-- ===== supabase_update_roles.sql =====
-- อัปเดตสิทธิ์ 4 ระดับ + ลบสมาชิก — รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอปเวอร์ชันใหม่)
-- user = พนักงาน | project_admin | controller_admin | super_admin (เห็นทุกเมนู + จัดการสมาชิก)
-- admin เดิมทุกคนจะถูกเลื่อนเป็น super_admin อัตโนมัติ

-- 1) อนุญาตค่า role ใหม่ (ลบ check เดิมของคอลัมน์ role แล้วสร้างใหม่)
do $$
declare c record;
begin
  for c in select conname from pg_constraint
           where conrelid = 'public.employees'::regclass and contype = 'c'
             and pg_get_constraintdef(oid) ilike '%role%' loop
    execute format('alter table public.employees drop constraint %I', c.conname);
  end loop;
end $$;

update public.employees set role = 'super_admin' where role = 'admin';

alter table public.employees
  add constraint employees_role_check
  check (role in ('user','project_admin','controller_admin','super_admin'));

-- 2) ฟังก์ชันตรวจสิทธิ์
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.employees
    where user_id = auth.uid() and active and approved
      and role in ('project_admin','controller_admin','super_admin'));
$$;

create or replace function public.is_super_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.employees
    where user_id = auth.uid() and active and approved and role = 'super_admin');
$$;

-- 3) ตาราง employees: ทุก admin อ่านได้ทั้งหมด แต่เพิ่ม/แก้/ลบได้เฉพาะ super_admin
drop policy if exists emp_admin on public.employees;
drop policy if exists emp_super on public.employees;
create policy emp_super on public.employees for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

drop policy if exists emp_admin_read on public.employees;
create policy emp_admin_read on public.employees for select to authenticated
  using (public.is_admin());

-- 4) ปฏิเสธ/แก้รหัสผู้สมัคร: เฉพาะ super_admin
create or replace function public.admin_reject(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  select user_id into uid from public.employees where id = p_id and approved = false;
  if not found then raise exception 'NOT_PENDING'; end if;
  delete from public.employees where id = p_id;
  if uid is not null then delete from auth.users where id = uid; end if;
end $$;

create or replace function public.admin_rename_emp(p_old text, p_new text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  if exists (select 1 from public.employees where id = p_new) then raise exception 'ID_EXISTS'; end if;
  if not exists (select 1 from public.employees where id = p_old and approved = false) then raise exception 'NOT_PENDING'; end if;
  update public.employees set id = p_new where id = p_old;
end $$;

-- 5) ลบสมาชิกถาวร (เฉพาะ super_admin) — ลบแถวพนักงาน (timesheets/assignments ถูกลบตาม) และบัญชีล็อกอิน
create or replace function public.admin_delete_employee(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare e public.employees;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  select * into e from public.employees where id = p_id;
  if not found then raise exception 'NOT_FOUND'; end if;
  if e.user_id is not null and e.user_id = auth.uid() then raise exception 'SELF'; end if;
  if e.role = 'super_admin' and e.active and e.approved
     and (select count(*) from public.employees where role = 'super_admin' and active and approved and id <> p_id) = 0
  then raise exception 'LAST_SUPER'; end if;
  delete from public.employees where id = p_id;
  if e.user_id is not null then delete from auth.users where id = e.user_id; end if;
end $$;

revoke all on function public.admin_delete_employee(text) from public, anon;
grant execute on function public.admin_delete_employee(text) to authenticated;
revoke all on function public.is_super_admin() from public, anon;
grant execute on function public.is_super_admin() to authenticated;


-- ===== supabase_update_import_log.sql =====
-- เพิ่มช่อง "ผู้นำเข้า/แก้ไข" และ "อัปเดตล่าสุด" ให้ตารางโครงการและ Sales Contract
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอป v35) — รันซ้ำได้ ไม่เสียหาย
alter table public.projects  add column if not exists updated_by text not null default '';
alter table public.projects  add column if not exists updated_at timestamptz default now();
alter table public.contracts add column if not exists updated_by text not null default '';
alter table public.contracts add column if not exists updated_at timestamptz default now();


-- ===== supabase_update_approval_flow.sql =====
-- ขั้นตอนอนุมัติใบบันทึกงาน: พนักงานส่ง (Pending) → Project Admin / Super Admin อนุมัติ → Submitted
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_roles.sql และก่อนอัปโหลดแอป v37) — รันซ้ำได้

-- 1) อนุญาตสถานะ Pending + ช่องบันทึกผู้อนุมัติ/เหตุผลส่งกลับ
do $$
declare c record;
begin
  for c in select conname from pg_constraint
           where conrelid = 'public.timesheets'::regclass and contype = 'c'
             and pg_get_constraintdef(oid) ilike '%status%' loop
    execute format('alter table public.timesheets drop constraint %I', c.conname);
  end loop;
end $$;
alter table public.timesheets
  add constraint timesheets_status_check check (status in ('Draft','Pending','Submitted'));
alter table public.timesheets add column if not exists approved_by  text not null default '';
alter table public.timesheets add column if not exists approved_at  timestamptz;
alter table public.timesheets add column if not exists reject_note  text not null default '';

-- 2) ผู้อนุมัติ = project_admin หรือ super_admin (ที่ active และ approved)
create or replace function public.is_approver() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.employees
    where user_id = auth.uid() and active and approved
      and role in ('project_admin','super_admin'));
$$;
revoke all on function public.is_approver() from public, anon;
grant execute on function public.is_approver() to authenticated;

-- 3) สิทธิ์ตารางบันทึกงาน
--    พนักงาน: เพิ่ม/แก้ได้เฉพาะใบของตัวเองที่เป็น Draft/Pending และตั้งสถานะเป็น Submitted เองไม่ได้
--    Project Admin / Super Admin: อนุมัติ/ส่งกลับใบของคนอื่นได้ (ใบของตัวเอง ต้องเป็น Super Admin จึงอนุมัติเองได้)
--    Controller Admin: ดูได้อย่างเดียว
drop policy if exists ts_write on public.timesheets;
drop policy if exists ts_emp_write on public.timesheets;
drop policy if exists ts_approver_write on public.timesheets;

create policy ts_emp_write on public.timesheets for all to authenticated
  using (emp_id = public.my_emp_id() and status in ('Draft','Pending'))
  with check (emp_id = public.my_emp_id() and status in ('Draft','Pending'));

create policy ts_approver_write on public.timesheets for all to authenticated
  using (public.is_approver() and (emp_id <> public.my_emp_id() or public.is_super_admin()))
  with check (public.is_approver() and (emp_id <> public.my_emp_id() or public.is_super_admin()));

-- ใบที่เคยเป็น Submitted อยู่แล้วคงเดิม (ถือว่าอนุมัติแล้ว)


-- ===== supabase_update_salary.sql =====
-- ตารางเงินเดือน (กำหนดตาม Level / ฝ่าย / รายบุคคล) — เห็นและแก้ได้เฉพาะ Super Admin
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_roles.sql และก่อนอัปโหลดแอป v40) — รันซ้ำได้
create table if not exists public.salary_rates (
  id         text primary key,                      -- scope|key เช่น level|L4, dept|43001, emp|12345, config|hours
  scope      text not null check (scope in ('level','dept','emp','config')),
  key        text not null,
  amount     numeric(14,2) not null check (amount >= 0),
  updated_by text not null default '',
  updated_at timestamptz not null default now(),
  unique (scope, key)
);

alter table public.salary_rates enable row level security;
revoke all on public.salary_rates from anon;

drop policy if exists sal_super on public.salary_rates;
create policy sal_super on public.salary_rates for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());
-- ไม่มี policy อื่น = พนักงาน / Project Admin / Controller Admin อ่านและแก้ไม่ได้


-- ===== supabase_update_company.sql =====
-- Sales Contract แยกบริษัท DP / Demco (ใช้กำหนดว่าประเภท SG&A ไหนเลือกสัญญาของบริษัทใดได้)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอป v44) — รันซ้ำได้ ไม่เสียหาย
alter table public.contracts add column if not exists company text not null default 'Demco';
do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.contracts'::regclass and conname = 'contracts_company_check') then
    alter table public.contracts add constraint contracts_company_check check (company in ('DP','Demco'));
  end if;
end $$;
-- สัญญาเดิมทั้งหมดถูกตั้งเป็น Demco โดยอัตโนมัติ ถ้าสัญญาไหนเป็นของ DP ให้แก้ในแอป (ตั้งค่าข้อมูล > Sales Contract) หรือนำเข้า Excel ที่มีคอลัมน์ Company


-- ===== supabase_update_roleperm.sql =====
-- Role and permission สำหรับการอนุมัติรายการบันทึกงาน (PM / Mgr / ผู้บริหารฝ่าย / COO / CEO) + ผู้อนุมัติและขอบเขต
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_roles.sql และ supabase_update_approval_flow.sql) — รันซ้ำได้

-- 1) ตารางสิทธิ์ Role × (cost | sga):  yes = อนุมัติได้ · no = ไม่ได้ · na = N/A
create table if not exists public.approval_perms (
  role text not null check (role in ('pm','mgr','dir','coo','ceo')),
  cat  text not null check (cat in ('cost','sga')),
  perm text not null default 'no' check (perm in ('yes','no','na')),
  primary key (role, cat)
);
insert into public.approval_perms (role, cat, perm) values
  ('pm','cost','yes'),('mgr','cost','yes'),('dir','cost','yes'),('coo','cost','yes'),('ceo','cost','yes'),
  ('pm','sga','no'),('mgr','sga','yes'),('dir','sga','yes'),('coo','sga','na'),('ceo','sga','na')
on conflict (role, cat) do nothing;

-- 2) ผู้อนุมัติและขอบเขต: pm = รหัสโครงการ · mgr/dir = รหัสฝ่าย · coo/ceo = ทั้งบริษัท (scope_key '*')
create table if not exists public.approver_scopes (
  id         text primary key,
  emp_id     text not null references public.employees(id) on delete cascade,
  role       text not null check (role in ('pm','mgr','dir','coo','ceo')),
  scope_type text not null default 'dept' check (scope_type in ('project','dept','all')),
  scope_key  text not null default '*'
);

alter table public.approval_perms  enable row level security;
alter table public.approver_scopes enable row level security;
revoke all on public.approval_perms, public.approver_scopes from anon;

-- 3) สิทธิ์ผู้อนุมัติ: super_admin หรือพนักงานที่มีแถวใน approver_scopes
create or replace function public.is_approver() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.employees
                 where user_id = auth.uid() and active and approved and role = 'super_admin')
      or exists (select 1 from public.approver_scopes s join public.employees e on e.id = s.emp_id
                 where e.user_id = auth.uid() and e.active and e.approved);
$$;
revoke all on function public.is_approver() from public, anon;
grant execute on function public.is_approver() to authenticated;

-- 4) นโยบาย: ทุกคนอ่านตารางสิทธิ์ได้ · อ่านขอบเขตของตัวเองได้ · แก้ไขได้เฉพาะ super_admin
drop policy if exists perms_read on public.approval_perms;
create policy perms_read on public.approval_perms for select to authenticated using (true);
drop policy if exists perms_super on public.approval_perms;
create policy perms_super on public.approval_perms for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

drop policy if exists scopes_read on public.approver_scopes;
create policy scopes_read on public.approver_scopes for select to authenticated
  using (public.is_super_admin() or emp_id = public.my_emp_id());
drop policy if exists scopes_super on public.approver_scopes;
create policy scopes_super on public.approver_scopes for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

-- 5) ให้ผู้อนุมัติ (ที่ไม่ใช่ admin) อ่านข้อมูลที่ต้องใช้แสดงรายการอนุมัติ: พนักงาน, โครงการ, สัญญา, ฝ่าย, ใบบันทึกงาน
drop policy if exists emp_approver_read on public.employees;
create policy emp_approver_read on public.employees for select to authenticated using (public.is_approver());
drop policy if exists proj_approver_read on public.projects;
create policy proj_approver_read on public.projects for select to authenticated using (public.is_approver());
drop policy if exists con_approver_read on public.contracts;
create policy con_approver_read on public.contracts for select to authenticated using (public.is_approver());
drop policy if exists ts_approver_read on public.timesheets;
create policy ts_approver_read on public.timesheets for select to authenticated using (public.is_approver());

-- ผู้อนุมัติเขียนใบของคนอื่นได้ (นโยบาย ts_approver_write จาก supabase_update_approval_flow.sql ใช้ is_approver() อยู่แล้ว)
-- หมายเหตุ: การตรวจ "สิทธิ์ตามขอบเขต" (PM/ฝ่าย) ทำที่ฝั่งแอป ฐานข้อมูลอนุญาตระดับผู้อนุมัติทั่วไป
