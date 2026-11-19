-- รวมทุกไฟล์อัปเดตฐานข้อมูล (v31–v58) รันซ้ำได้ ไม่เสียหาย — วางทั้งไฟล์ใน Supabase > SQL Editor แล้วกด Run

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

-- 1) ตารางลำดับขั้นอนุมัติ Role × (cost | sga): perm = '1'..'5' (ลำดับขั้น) · 'no' = ไม่เกี่ยวข้อง · 'na' = N/A (ค่าเก่า 'yes' ถือเป็นขั้นตามค่าเริ่มต้น)
create table if not exists public.approval_perms (
  role text not null check (role in ('pm','mgr','dir','coo','ceo')),
  cat  text not null check (cat in ('cost','sga')),
  perm text not null default 'no',
  primary key (role, cat)
);
alter table public.approval_perms drop constraint if exists approval_perms_perm_check;
alter table public.approval_perms add constraint approval_perms_perm_check check (perm in ('yes','no','na','1','2','3','4','5'));
insert into public.approval_perms (role, cat, perm) values
  ('pm','cost','1'),('mgr','cost','2'),('dir','cost','3'),('coo','cost','4'),('ceo','cost','5'),
  ('pm','sga','no'),('mgr','sga','1'),('dir','sga','2'),('coo','sga','na'),('ceo','sga','na')
on conflict (role, cat) do nothing;
-- แปลงค่าเก่า yes เป็นลำดับขั้นตามค่าเริ่มต้น
update public.approval_perms set perm = case role||'|'||cat
  when 'pm|cost' then '1' when 'mgr|cost' then '2' when 'dir|cost' then '3' when 'coo|cost' then '4' when 'ceo|cost' then '5'
  when 'mgr|sga' then '1' when 'dir|sga' then '2' else 'no' end where perm = 'yes';

-- 2) ผู้อนุมัติและขอบเขต: pm = รหัสโครงการ · mgr/dir = รหัสฝ่าย · coo/ceo = ทั้งบริษัท (scope_key '*')
create table if not exists public.approver_scopes (
  id         text primary key,
  emp_id     text not null references public.employees(id) on delete cascade,
  role       text not null check (role in ('pm','mgr','dir','coo','ceo')),
  scope_type text not null default 'dept' check (scope_type in ('project','dept','all')),
  scope_key  text not null default '*'
);

-- ขอบเขตรายบุคคล: อนุญาต scope_type = 'emp' เพิ่ม (project=รหัสโครงการ/สัญญา · dept=ฝ่าย · emp=พนักงาน · all=ทั้งบริษัท)
alter table public.approver_scopes drop constraint if exists approver_scopes_scope_type_check;
alter table public.approver_scopes add constraint approver_scopes_scope_type_check check (scope_type in ('project','dept','emp','all'));

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

-- 4) นโยบาย: ทุกคนอ่านตารางสิทธิ์และผู้อนุมัติได้ (เพื่อคำนวณเส้นทางอนุมัติ) · แก้ไขได้เฉพาะ super_admin
drop policy if exists perms_read on public.approval_perms;
create policy perms_read on public.approval_perms for select to authenticated using (true);
drop policy if exists perms_super on public.approval_perms;
create policy perms_super on public.approval_perms for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

drop policy if exists scopes_read on public.approver_scopes;
create policy scopes_read on public.approver_scopes for select to authenticated using (true);   -- ทุกคนอ่านได้ (ใช้คำนวณเส้นทางอนุมัติ ไม่มีข้อมูลส่วนตัว)
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


-- ===== supabase_update_single_session.sql =====
-- จำกัด 1 บัญชี = 1 อุปกรณ์ที่ใช้งานพร้อมกัน (login ซ้ำจากอีกอุปกรณ์ถูกปฏิเสธ)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอป v58) — รันซ้ำได้
-- หลักการ: เครื่องที่กำลังใช้งานส่งสัญญาณ (heartbeat) ทุก 30 วินาที ถ้าเงียบเกิน 150 วินาที (ปิดเบราว์เซอร์/ไม่ได้ใช้งาน) ถือว่าว่าง อุปกรณ์อื่นเข้าใช้ได้
create table if not exists public.active_sessions (
  emp_id     text primary key references public.employees(id) on delete cascade,
  device_id  text not null,
  user_agent text not null default '',
  started_at timestamptz not null default now(),
  last_seen  timestamptz not null default now()
);
alter table public.active_sessions enable row level security;
revoke all on public.active_sessions from anon, authenticated;          -- เข้าถึงผ่านฟังก์ชันด้านล่างเท่านั้น

-- เริ่มใช้งาน: ถ้ามีอีกอุปกรณ์ใช้อยู่ (last_seen ภายใน 150 วินาที) → SESSION_ACTIVE
create or replace function public.claim_session(p_device text, p_ua text default '') returns void
language plpgsql security definer set search_path = public as $$
declare e text := public.my_emp_id(); r public.active_sessions;
begin
  if e is null then return; end if;
  select * into r from public.active_sessions where emp_id = e for update;
  if found and r.device_id <> p_device and r.last_seen > now() - interval '150 seconds' then
    raise exception 'SESSION_ACTIVE';
  end if;
  insert into public.active_sessions (emp_id, device_id, user_agent, started_at, last_seen)
    values (e, p_device, left(coalesce(p_ua,''), 300), now(), now())
  on conflict (emp_id) do update set
    started_at = case when public.active_sessions.device_id = excluded.device_id then public.active_sessions.started_at else now() end,
    device_id = excluded.device_id, user_agent = excluded.user_agent, last_seen = now();
end $$;

-- สัญญาณต่อเนื่อง: คืน false ถ้ามีอุปกรณ์อื่นยึดบัญชีไปแล้ว (อุปกรณ์นี้ต้องออกจากระบบ)
create or replace function public.heartbeat(p_device text) returns boolean
language plpgsql security definer set search_path = public as $$
declare e text := public.my_emp_id(); r public.active_sessions;
begin
  if e is null then return true; end if;
  select * into r from public.active_sessions where emp_id = e for update;
  if not found then
    insert into public.active_sessions (emp_id, device_id) values (e, p_device);
    return true;
  end if;
  if r.device_id <> p_device then return false; end if;
  update public.active_sessions set last_seen = now() where emp_id = e;
  return true;
end $$;

-- ออกจากระบบ: คืนสิทธิ์ให้อุปกรณ์อื่นเข้าได้ทันที
create or replace function public.release_session(p_device text) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.active_sessions where emp_id = public.my_emp_id() and device_id = p_device;
end $$;

-- Super Admin ปลดล็อกบัญชีของพนักงาน (กรณีอุปกรณ์เดิมค้างหรือเสีย)
create or replace function public.admin_release_session(p_emp text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  delete from public.active_sessions where emp_id = p_emp;
end $$;

revoke all on function public.claim_session(text,text), public.heartbeat(text), public.release_session(text), public.admin_release_session(text) from public, anon;
grant execute on function public.claim_session(text,text), public.heartbeat(text), public.release_session(text), public.admin_release_session(text) to authenticated;

-- v60: สมัครสมาชิกต้องรอ Admin อนุมัติเสมอ (ไม่มีการอนุมัติล่วงหน้า)
-- 1) ตัวสร้างบัญชีผู้สมัคร: ผูกกับแถวเดิมที่ Admin เพิ่มไว้ได้ แต่บังคับสถานะ "รออนุมัติ" เสมอ
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_emp  text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
  v_name text := coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), split_part(new.email, '@', 1));
  v_id   text;
begin
  update public.employees set user_id = new.id, approved = false
   where lower(email) = lower(new.email) and user_id is null and active;
  if found then return new; end if;
  v_id := coalesce(v_emp, 'N' || substr(new.id::text, 1, 6));
  if exists (select 1 from public.employees where id = v_id) then
    v_id := v_id || '-' || substr(new.id::text, 1, 4);
  end if;
  insert into public.employees (id, name, email, role, approved, active, user_id)
  values (v_id, v_name, lower(new.email), 'user', false, true, new.id);
  return new;
end $$;

-- 2) รายชื่อที่เคยถูกอนุมัติล่วงหน้าไว้แต่ยังไม่มีใครสมัคร → ยกเลิกการอนุมัติล่วงหน้า
update public.employees set approved = false where user_id is null;

-- ===== supabase_update_budget_delegate.sql =====
-- v61: (1) สิทธิ์บันทึกงานแทนผู้อื่น  (2) Budget รายโครงการ / Sales Contract
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลังไฟล์ roleperm / no_preapprove) — รันซ้ำได้

-- ===== 1) Budget =====
-- ยอดตั้งต้นเก็บที่ตารางโครงการ/สัญญา · ยอดใช้ไป = ผลรวมชั่วโมงของรายการงานที่ "อนุมัติขั้นสุดท้ายแล้ว" (คำนวณในแอป ไม่ต้องเก็บซ้ำ)
alter table public.projects  add column if not exists budget_hours numeric(14,2) not null default 0;
alter table public.projects  add column if not exists budget_baht  numeric(16,2) not null default 0;
alter table public.contracts add column if not exists budget_hours numeric(14,2) not null default 0;
alter table public.contracts add column if not exists budget_baht  numeric(16,2) not null default 0;

-- ===== 2) บันทึกงานแทนผู้อื่น =====
create table if not exists public.entry_delegates (
  id          text primary key,                                   -- ผู้บันทึกแทน|ขอบเขต|รหัส
  delegate_id text not null references public.employees(id) on delete cascade,
  scope_type  text not null check (scope_type in ('emp','dept','all')),
  scope_key   text not null default '*'
);
alter table public.entry_delegates enable row level security;
revoke all on public.entry_delegates from anon;

drop policy if exists deleg_read on public.entry_delegates;
create policy deleg_read on public.entry_delegates for select to authenticated using (true);
drop policy if exists deleg_super on public.entry_delegates;
create policy deleg_super on public.entry_delegates for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

-- ผู้ใช้ปัจจุบันบันทึกงานแทนพนักงานคนนี้ได้หรือไม่
create or replace function public.can_enter_for(p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1
      from public.entry_delegates d
      join public.employees me on me.id = d.delegate_id
      join public.employees t  on t.id  = p_emp
     where me.user_id = auth.uid() and me.active and me.approved and t.active
       and (d.scope_type = 'all'
         or (d.scope_type = 'emp'  and d.scope_key = t.id)
         or (d.scope_type = 'dept' and d.scope_key = t.dept)));
$$;
revoke all on function public.can_enter_for(text) from public, anon;
grant execute on function public.can_enter_for(text) to authenticated;

-- ผู้บันทึกแทน: อ่านข้อมูลที่ต้องใช้บันทึกงานแทน (พนักงาน · การมอบหมาย · โครงการ/สัญญาที่พนักงานนั้นได้รับมอบหมาย)
drop policy if exists emp_delegate_read on public.employees;
create policy emp_delegate_read on public.employees for select to authenticated
  using (public.can_enter_for(id));

drop policy if exists asg_delegate_read on public.assignments;
create policy asg_delegate_read on public.assignments for select to authenticated
  using (public.can_enter_for(emp_id));

drop policy if exists prj_delegate_read on public.projects;
create policy prj_delegate_read on public.projects for select to authenticated
  using (exists (select 1 from public.assignments a where a.code = projects.id and public.can_enter_for(a.emp_id)));

drop policy if exists ctr_delegate_read on public.contracts;
create policy ctr_delegate_read on public.contracts for select to authenticated
  using (exists (select 1 from public.assignments a where a.code = contracts.id and public.can_enter_for(a.emp_id)));

-- ใบบันทึกงาน: ผู้บันทึกแทนอ่านได้ทุกสถานะ · เพิ่ม/แก้/ลบ ได้เฉพาะใบที่ยังเป็น Draft / Pending (ตั้งเป็น Submitted เองไม่ได้)
drop policy if exists ts_delegate_read on public.timesheets;
create policy ts_delegate_read on public.timesheets for select to authenticated
  using (public.can_enter_for(emp_id));

drop policy if exists ts_delegate_write on public.timesheets;
create policy ts_delegate_write on public.timesheets for all to authenticated
  using (public.can_enter_for(emp_id) and status in ('Draft','Pending'))
  with check (public.can_enter_for(emp_id) and status in ('Draft','Pending'));

-- ===== supabase_update_cost_access.sql =====
-- v62: บริหารค่าใช้จ่ายโครงการ (Budget vs Actual) + สิทธิ์การเข้าถึงข้อมูลตามระดับ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_budget_delegate.sql) — รันซ้ำได้

-- 1) ตารางระดับสิทธิ์: none = ไม่เห็น · hours = เห็นชั่วโมง · cost = เห็นชั่วโมง + บาท
--    subject = Role ของระบบ (controller_admin / project_admin / user) หรือ Role อนุมัติ (pm / mgr / dir / coo / ceo)
create table if not exists public.cost_access (
  subject text primary key check (subject in ('controller_admin','project_admin','user','pm','mgr','dir','coo','ceo')),
  level   text not null default 'none' check (level in ('none','hours','cost'))
);
insert into public.cost_access (subject, level) values
  ('controller_admin','cost'), ('project_admin','hours'), ('user','none'),
  ('pm','hours'), ('mgr','none'), ('dir','none'), ('coo','cost'), ('ceo','cost')
on conflict (subject) do nothing;

alter table public.cost_access enable row level security;
revoke all on public.cost_access from anon;
drop policy if exists ca_read on public.cost_access;
create policy ca_read on public.cost_access for select to authenticated using (true);
drop policy if exists ca_super on public.cost_access;
create policy ca_super on public.cost_access for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

-- 2) รายงาน Budget vs Actual รายโครงการ — คำนวณที่ฐานข้อมูล (ครบทุกช่วงเวลา) และคืนเฉพาะที่ผู้เรียกมีสิทธิ์
--    ยอดใช้ไป = รายการงานที่อนุมัติขั้นสุดท้ายแล้ว · บาท = ชั่วโมง × (เงินเดือน ÷ ชั่วโมงมาตรฐาน/เดือน)
--    ผู้ที่ไม่ใช่ Super Admin ได้เพียงยอดรวมระดับโครงการ ไม่เห็นเงินเดือนรายคน
create or replace function public.project_cost_report()
returns table (code text, name text, ptype text, lvl text,
               budget_hours numeric, budget_baht numeric,
               used_hours numeric, used_baht numeric, pending_hours numeric, months jsonb)
language plpgsql stable security definer set search_path = public as $$
#variable_conflict use_column
declare
  v_me     public.employees%rowtype;
  v_global int;
  v_hpm    numeric;
begin
  select * into v_me from public.employees where user_id = auth.uid() and active and approved limit 1;
  if v_me.id is null then return; end if;

  v_hpm := coalesce((select amount from public.salary_rates where scope = 'config' and key = 'hours'), 160);
  if v_hpm <= 0 then v_hpm := 160; end if;

  v_global := case when v_me.role in ('super_admin','admin') then 2
                   else coalesce((select case level when 'cost' then 2 when 'hours' then 1 else 0 end
                                    from public.cost_access where subject = v_me.role), 0) end;

  return query
  with codes as (
    select p.id as c_code, p.name as c_name, p.kind as c_type, p.budget_hours as bh, p.budget_baht as bb from public.projects p
    union all
    select c.id, c.name, 'sc_' || lower(c.company), c.budget_hours, c.budget_baht from public.contracts c
  ),
  acc as (
    select k.*, greatest(v_global, coalesce((
      select max(case a.level when 'cost' then 2 when 'hours' then 1 else 0 end)
        from public.approver_scopes s join public.cost_access a on a.subject = s.role
       where s.emp_id = v_me.id
         and (s.scope_type = 'all' or (s.scope_type = 'project' and s.scope_key = k.c_code))), 0)) as lv
    from codes k
  ),
  ent as (
    select e->>'code' as e_code, (e->>'hours')::numeric as h, to_char(t.day, 'YYYY-MM') as ym, t.emp_id as e_emp,
           case when (e->'ap'->>'s') = 'A' or (e->'ap' is null and t.status = 'Submitted') then 'A'
                when (e->'ap'->>'s') = 'P' or (e->'ap' is null and t.status = 'Pending')   then 'P' end as st
      from public.timesheets t, jsonb_array_elements(t.entries) e
     where coalesce(e->>'code', '') <> ''
  ),
  rate as (
    select em.id as r_emp, coalesce(
      (select amount from public.salary_rates where scope = 'emp'   and key = em.id),
      (select amount from public.salary_rates where scope = 'level' and key = em.level and coalesce(em.level,'') <> ''),
      (select amount from public.salary_rates where scope = 'dept'  and key = em.dept  and coalesce(em.dept,'')  <> '')) / v_hpm as r
    from public.employees em
  ),
  agg as (
    select ent.e_code, ent.ym, ent.st, sum(ent.h) as h, sum(ent.h * coalesce(rate.r, 0)) as b
      from ent left join rate on rate.r_emp = ent.e_emp
     where ent.st is not null
     group by 1, 2, 3
  )
  select a.c_code, a.c_name, a.c_type,
         case when a.lv >= 2 then 'cost' else 'hours' end,
         a.bh,
         case when a.lv >= 2 then a.bb end,
         coalesce((select sum(g.h) from agg g where g.e_code = a.c_code and g.st = 'A'), 0),
         case when a.lv >= 2 then coalesce((select round(sum(g.b), 2) from agg g where g.e_code = a.c_code and g.st = 'A'), 0) end,
         coalesce((select sum(g.h) from agg g where g.e_code = a.c_code and g.st = 'P'), 0),
         coalesce((select jsonb_agg(jsonb_build_object('ym', g.ym, 'h', g.h, 'b', case when a.lv >= 2 then round(g.b, 2) end) order by g.ym)
                     from agg g where g.e_code = a.c_code and g.st = 'A'), '[]'::jsonb)
    from acc a
   where a.lv >= 1;
end $$;
revoke all on function public.project_cost_report() from public, anon;
grant execute on function public.project_cost_report() to authenticated;
