-- =====================================================================
-- DEMCO Timesheet — สคีมา Supabase (รันใน Supabase > SQL Editor > New query)
-- ลำดับ: 1) รันไฟล์นี้ทั้งไฟล์  2) เพิ่ม Admin คนแรก (ดูท้ายไฟล์)  3) สมัครสมาชิกในแอปด้วยอีเมลเดียวกัน
-- ความปลอดภัย: เปิด Row Level Security ทุกตาราง — พนักงานเห็น/แก้ได้เฉพาะของตัวเอง, Admin จัดการทั้งหมด
-- =====================================================================

-- ---------- ตาราง ----------
create table if not exists public.employees (
  id        text primary key,                       -- Emp.No
  name      text not null,
  nick      text default '',
  dept      text default '',
  level     text default '',
  position  text default '',
  email     text not null,
  role      text not null default 'user' check (role in ('user','admin')),
  work_sat  boolean not null default false,
  active    boolean not null default true,
  approved  boolean not null default false,                         -- Admin ต้องอนุมัติก่อนจึงใช้งานได้
  user_id   uuid unique references auth.users(id) on delete set null   -- ผูกอัตโนมัติเมื่อสมัครด้วยอีเมลตรงกัน
);
create unique index if not exists employees_email_lower on public.employees (lower(email));

create table if not exists public.departments (
  id text primary key, name text not null default '', active boolean not null default true
);
create table if not exists public.projects (
  id text primary key, name text not null default '',
  kind text not null default 'cost' check (kind in ('cost','mt','backlog')),
  active boolean not null default true
);
create table if not exists public.contracts (
  id text primary key, name text not null default '', active boolean not null default true
);
create table if not exists public.assignments (
  emp_id text not null references public.employees(id) on delete cascade,
  code   text not null,
  primary key (emp_id, code)
);
create table if not exists public.holidays (
  day date primary key, name text not null default ''
);
create table if not exists public.timesheets (
  id           text primary key,                    -- EmpNo-YYYY-MM-DD
  emp_id       text not null references public.employees(id) on delete cascade,
  day          date not null,
  status       text not null default 'Draft' check (status in ('Draft','Submitted')),
  submitted_at timestamptz,
  entries      jsonb not null default '[]'::jsonb,  -- รายการงานในวันนั้น
  unique (emp_id, day)
);
create index if not exists timesheets_day_idx on public.timesheets (day);

-- ---------- ฟังก์ชันช่วย (security definer เพื่อไม่ให้ policy วนซ้ำ) ----------
create or replace function public.my_emp_id() returns text
language sql stable security definer set search_path = public as $$
  select id from public.employees where user_id = auth.uid() and active and approved limit 1
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' from public.employees where user_id = auth.uid() and active and approved limit 1), false)
$$;

-- ---------- สมัครสมาชิก: อนุญาตเฉพาะอีเมลที่ Admin เพิ่มไว้ในตาราง employees ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_emp  text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
  v_name text := coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), split_part(new.email, '@', 1));
  v_id   text;
begin
  -- ถ้า Admin เพิ่มรายชื่อพร้อมอีเมลนี้ไว้แล้ว → ผูกกับแถวเดิม (สถานะอนุมัติตามที่ Admin ตั้งไว้)
  update public.employees set user_id = new.id
   where lower(email) = lower(new.email) and user_id is null and active;
  if found then return new; end if;
  -- ไม่เช่นนั้น สร้างคำขอใหม่ สถานะ "รออนุมัติ"
  v_id := coalesce(v_emp, 'N' || substr(new.id::text, 1, 6));
  if exists (select 1 from public.employees where id = v_id) then
    v_id := v_id || '-' || substr(new.id::text, 1, 4);      -- รหัสซ้ำ: Admin แก้รหัสให้ถูกต้องตอนอนุมัติ
  end if;
  insert into public.employees (id, name, email, role, approved, active, user_id)
  values (v_id, v_name, lower(new.email), 'user', false, true, new.id);
  return new;
end $$;


drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Admin ปฏิเสธคำขอสมัคร (ลบบัญชีผู้สมัครที่ยังไม่อนุมัติ)
create or replace function public.admin_reject(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid;
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  select user_id into v_uid from public.employees where id = p_id and approved = false;
  if not found then raise exception 'NOT_PENDING'; end if;
  delete from public.employees where id = p_id and approved = false;
  if v_uid is not null then delete from auth.users where id = v_uid; end if;
end $$;

-- Admin แก้รหัสพนักงานของผู้สมัครที่ยังไม่อนุมัติ
create or replace function public.admin_rename_emp(p_old text, p_new text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  p_new := trim(p_new);
  if p_new = '' then raise exception 'EMPTY_ID'; end if;
  if exists (select 1 from public.employees where id = p_new) then raise exception 'ID_EXISTS'; end if;
  update public.employees set id = p_new where id = p_old and approved = false;
  if not found then raise exception 'NOT_PENDING'; end if;
end $$;

revoke all on function public.admin_reject(text) from public, anon;
revoke all on function public.admin_rename_emp(text, text) from public, anon;
grant execute on function public.admin_reject(text) to authenticated;
grant execute on function public.admin_rename_emp(text, text) to authenticated;
-- ---------- Row Level Security ----------
alter table public.employees   enable row level security;
alter table public.departments enable row level security;
alter table public.projects    enable row level security;
alter table public.contracts   enable row level security;
alter table public.assignments enable row level security;
alter table public.holidays    enable row level security;
alter table public.timesheets  enable row level security;

revoke all on all tables in schema public from anon;     -- คนที่ไม่ได้ login เข้าถึงอะไรไม่ได้เลย

-- employees: เห็นแถวตัวเอง (Admin เห็นทั้งหมด) / แก้ไขได้เฉพาะ Admin
drop policy if exists emp_select on public.employees;
create policy emp_select on public.employees for select to authenticated
  using (public.is_admin() or user_id = auth.uid());
drop policy if exists emp_admin on public.employees;
create policy emp_admin on public.employees for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- departments / holidays: อ่านได้ทุกคนที่ login, แก้ไขได้เฉพาะ Admin
drop policy if exists dept_select on public.departments;
create policy dept_select on public.departments for select to authenticated using (true);
drop policy if exists dept_admin on public.departments;
create policy dept_admin on public.departments for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists hol_select on public.holidays;
create policy hol_select on public.holidays for select to authenticated using (true);
drop policy if exists hol_admin on public.holidays;
create policy hol_admin on public.holidays for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- projects / contracts: พนักงานเห็นเฉพาะรหัสที่ถูก assign ให้ (Admin เห็นทั้งหมด)
drop policy if exists prj_select on public.projects;
create policy prj_select on public.projects for select to authenticated
  using (public.is_admin() or exists (select 1 from public.assignments a where a.emp_id = public.my_emp_id() and a.code = projects.id));
drop policy if exists prj_admin on public.projects;
create policy prj_admin on public.projects for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists ctr_select on public.contracts;
create policy ctr_select on public.contracts for select to authenticated
  using (public.is_admin() or exists (select 1 from public.assignments a where a.emp_id = public.my_emp_id() and a.code = contracts.id));
drop policy if exists ctr_admin on public.contracts;
create policy ctr_admin on public.contracts for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- assignments: เห็นของตัวเอง / แก้ไขเฉพาะ Admin
drop policy if exists asg_select on public.assignments;
create policy asg_select on public.assignments for select to authenticated
  using (public.is_admin() or emp_id = public.my_emp_id());
drop policy if exists asg_admin on public.assignments;
create policy asg_admin on public.assignments for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- timesheets: เห็น/เพิ่ม/แก้/ลบ ได้เฉพาะของตัวเอง (Admin ทั้งหมด)
drop policy if exists ts_select on public.timesheets;
create policy ts_select on public.timesheets for select to authenticated
  using (public.is_admin() or emp_id = public.my_emp_id());
drop policy if exists ts_write on public.timesheets;
create policy ts_write on public.timesheets for all to authenticated
  using (public.is_admin() or emp_id = public.my_emp_id())
  with check (public.is_admin() or emp_id = public.my_emp_id());

-- ---------- ข้อมูลเริ่มต้น: ฝ่าย ----------
insert into public.departments (id, name) values
 ('31001','ฝ่ายออกแบบและวิศวกรรมไฟฟ้า'),
 ('31002','ฝ่ายออกแบบและวิศวกรรมโยธา'),
 ('31003','ฝ่ายออกแบบและวิศวกรรมโครงเหล็ก'),
 ('32002','ฝ่ายบริหารงานก่อสร้างระบบสายส่ง 115 kV. และระบบจำหน่าย'),
 ('32003','ฝ่ายบริหารงานก่อสร้างระบบสายส่ง 230-500 kV และก่อสร้างโยธา'),
 ('43001','ฝ่ายบริหารงานก่อสร้างสถานีไฟฟ้า 1'),
 ('43002','ฝ่ายบริหารงานก่อสร้างสถานีไฟฟ้า 2'),
 ('43003','ฝ่ายงานก่อสร้างสถานีไฟฟ้า'),
 ('73001','ฝ่ายบำรุงรักษา ทดสอบระบบไฟฟ้าและพลังงานทดแทน'),
 ('41004','ฝ่ายบริหารงานก่อสร้างวิศวกรรมนวัตกรรม'),
 ('60001','ฝ่ายความปลอดภัยและสิ่งแวดล้อม'),
 ('65002','พัฒนาทรัพยากรบุคคล')
on conflict (id) do nothing;

-- =====================================================================
-- ขั้นตอนถัดไป: เพิ่ม Admin คนแรก (แก้ค่าแล้วรันแยกอีกครั้ง — ต้องทำก่อนสมัครสมาชิกในแอป)
-- =====================================================================
-- insert into public.employees (id, name, email, role, dept, position, approved)
-- values ('รหัสพนักงานของคุณ', 'ชื่อ นามสกุล', 'อีเมลบริษัทของคุณ@demco.co.th', 'admin', '65002', 'ตำแหน่ง', true);
--
-- จากนั้นเปิดแอป > "สมัครสมาชิก" ด้วยอีเมลเดียวกัน > กดลิงก์ยืนยันในอีเมล > เข้าสู่ระบบ
-- พนักงานคนอื่น: Admin เพิ่มรายชื่อ (พร้อมอีเมล) ในแท็บ "สมาชิก" ก่อน แล้วให้พนักงานสมัครเอง
