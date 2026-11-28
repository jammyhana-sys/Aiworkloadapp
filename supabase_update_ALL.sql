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
  role text not null check (role in ('adm','pm','mgr','dir','coo','ceo')),
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
  role       text not null check (role in ('adm','pm','mgr','dir','coo','ceo')),
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
  subject text primary key check (subject in ('controller_admin','project_admin','user','adm','pm','mgr','dir','coo','ceo')),
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

-- ===== supabase_update_cost_access2.sql =====
-- v63: สิทธิ์ข้อมูลค่าใช้จ่ายแบบ Dynamic — เพิ่ม/ลบกฎได้เอง กำหนดให้ Role ระบบ / Role อนุมัติ / รายบุคคล
--      และเลือกขอบเขตได้ต่อกฎ: all = ทุกโครงการ · scoped = เฉพาะโครงการ/ทั้งบริษัทที่ผู้นั้นเป็นผู้อนุมัติ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_cost_access.sql) — รันซ้ำได้

-- 1) subject ไม่จำกัดเฉพาะ Role ตายตัวอีกต่อไป: 'controller_admin' | 'project_admin' | 'user' | 'pm' | 'mgr' | 'dir' | 'coo' | 'ceo' | 'emp:<รหัสพนักงาน>'
alter table public.cost_access drop constraint if exists cost_access_subject_check;

-- 2) คอลัมน์ขอบเขต (เพิ่มครั้งแรก: Role อนุมัติ = scoped, ที่เหลือ = all ตรงกับพฤติกรรมเดิม)
do $$
begin
  if not exists (select 1 from information_schema.columns
                  where table_schema = 'public' and table_name = 'cost_access' and column_name = 'scope') then
    alter table public.cost_access add column scope text not null default 'all';
    update public.cost_access set scope = 'scoped' where subject in ('adm','pm','mgr','dir','coo','ceo');
  end if;
end $$;
insert into public.cost_access (subject, level, scope) values ('super_admin','cost','all') on conflict (subject) do nothing;   -- Super Admin เป็นกฎที่แก้ได้ (ถ้าลบกฎ = เห็นทั้งหมด กันล็อกตัวเอง)
alter table public.cost_access drop constraint if exists cost_access_scope_check;
alter table public.cost_access add constraint cost_access_scope_check check (scope in ('all','scoped'));

-- 3) รายงาน Budget vs Actual — คำนวณสิทธิ์ตามกฎแบบใหม่
create or replace function public.project_cost_report()
returns table (code text, name text, ptype text, lvl text,
               budget_hours numeric, budget_baht numeric,
               used_hours numeric, used_baht numeric, pending_hours numeric, months jsonb)
language plpgsql stable security definer set search_path = public as $$
#variable_conflict use_column
declare
  v_me  public.employees%rowtype;
  v_hpm numeric;
begin
  select * into v_me from public.employees where user_id = auth.uid() and active and approved limit 1;
  if v_me.id is null then return; end if;

  v_hpm := coalesce((select amount from public.salary_rates where scope = 'config' and key = 'hours'), 160);
  if v_hpm <= 0 then v_hpm := 160; end if;

  return query
  with codes as (
    select p.id as c_code, p.name as c_name, p.kind as c_type, p.budget_hours as bh, p.budget_baht as bb from public.projects p
    union all
    select c.id, c.name, 'sc_' || lower(c.company), c.budget_hours, c.budget_baht from public.contracts c
  ),
  acc as (
    select k.*,
      case when v_me.role in ('super_admin','admin') and not exists (select 1 from public.cost_access x where x.subject = 'super_admin') then 2 else coalesce((
        select max(case r.level when 'cost' then 2 when 'hours' then 1 else 0 end)
          from public.cost_access r
         where (   r.subject = case when v_me.role = 'admin' then 'super_admin' else v_me.role end
                or r.subject = 'emp:' || v_me.id
                or (r.subject in ('adm','pm','mgr','dir','coo','ceo')
                    and exists (select 1 from public.approver_scopes s where s.emp_id = v_me.id and s.role = r.subject)))
           and (   r.scope = 'all'
                or exists (select 1 from public.approver_scopes s
                            where s.emp_id = v_me.id
                              and (s.role = r.subject or r.subject not in ('adm','pm','mgr','dir','coo','ceo'))
                              and (s.scope_type = 'all' or (s.scope_type = 'project' and s.scope_key = k.c_code))))), 0) end as lv
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

-- ===== supabase_update_line_approval.sql =====
-- v64: แจ้งรายการรออนุมัติไปที่ LINE และกดอนุมัติผ่าน LINE ได้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ต้องรัน supabase_line.sql และไฟล์อัปเดตก่อนหน้ามาแล้ว) — รันซ้ำได้
-- แล้ว deploy โค้ดใหม่ของ Edge Function: line-notify.ts → function "hyper-api" และ line-webhook.ts → function "clever-task"
--
-- หลักการ: ทุกครั้งที่ใบงานเปลี่ยนเป็น "รออนุมัติ" หรือขยับไปขั้นถัดไป (ไม่ว่าอนุมัติจากเว็บหรือจาก LINE)
--          trigger จะเรียก Edge Function ให้แจ้งผู้อนุมัติของขั้นนั้นที่ผูก LINE ไว้ (ส่งซ้ำรายการเดิมไม่ได้)
--          ผู้อนุมัติกดปุ่ม "อนุมัติ" ใน LINE → ยืนยันอีกครั้ง → ฐานข้อมูลตรวจสิทธิ์ตามขอบเขตและบันทึกอนุมัติ
--          การตรวจสิทธิ์/ลำดับขั้นทำที่ฐานข้อมูล (ฟังก์ชัน ap_*) ให้ผลตรงกับหน้าเว็บ

-- 1) บันทึกว่าแจ้งรายการไหนให้ใครแล้ว (กันแจ้งซ้ำ)
create table if not exists public.ap_notified (
  key text primary key,
  at  timestamptz not null default now()
);
alter table public.ap_notified enable row level security;
revoke all on public.ap_notified from anon, authenticated;

-- 2) ลำดับขั้นของ Role ต่อประเภทรายการ (เหมือน permOf/stepOf ในแอป) — ค่าเริ่มต้นเมื่อยังไม่ได้ตั้ง
create or replace function public.ap_step(p_role text, p_cat text) returns int
language plpgsql stable security definer set search_path = public as $$
declare v text; d text;
begin
  d := case p_role || '|' || p_cat
         when 'pm|cost' then '1' when 'mgr|cost' then '2' when 'dir|cost' then '3' when 'coo|cost' then '4' when 'ceo|cost' then '5'
         when 'pm|sga'  then 'no' when 'mgr|sga' then '1' when 'dir|sga' then '2' else 'na' end;
  select perm into v from public.approval_perms where role = p_role and cat = p_cat;
  v := coalesce(v, d);
  if v = 'yes' then
    v := case when d ~ '^[1-5]$' then d else array_position(array['adm','pm','mgr','dir','coo','ceo'], p_role)::text end;
  end if;
  if v ~ '^[1-5]$' then return v::int; end if;
  return null;
end $$;

-- 3) ขอบเขตผู้อนุมัติตรงกับรายการหรือไม่ (all / project / emp / dept)
create or replace function public.ap_scope_ok(s public.approver_scopes, p_owner text, p_code text) returns boolean
language sql stable security definer set search_path = public as $$
  select case s.scope_type
           when 'all'     then true
           when 'project' then p_code is not null and p_code = s.scope_key
           when 'emp'     then p_owner = s.scope_key
           else exists (select 1 from public.employees e where e.id = p_owner and e.dept = s.scope_key)
         end
$$;

-- 4) สายอนุมัติของรายการ (เฉพาะขั้นที่มีผู้อนุมัติในขอบเขต ไม่นับเจ้าของรายการ) และขั้นถัดไป
create or replace function public.ap_chain(p_owner text, p_e jsonb) returns text[]
language sql stable security definer set search_path = public as $$
  select coalesce(array_agg(q.role_ order by q.st, q.ord), '{}')
    from (select u.role_,
                 public.ap_step(u.role_, case when p_e->>'cat' = 'Cost' then 'cost' else 'sga' end) as st,
                 array_position(array['adm','pm','mgr','dir','coo','ceo'], u.role_) as ord
            from unnest(array['adm','pm','mgr','dir','coo','ceo']) as u(role_)) q
   where q.st is not null
     and exists (select 1 from public.approver_scopes s
                  where s.role = q.role_ and s.emp_id <> p_owner
                    and public.ap_scope_ok(s, p_owner, p_e->>'code'))
$$;

create or replace function public.ap_next(p_owner text, p_e jsonb) returns text
language sql stable security definer set search_path = public as $$
  select u.c from unnest(public.ap_chain(p_owner, p_e)) with ordinality as u(c, i)
   where not (coalesce(p_e->'ap'->'done', '[]'::jsonb) ? u.c)
   order by u.i limit 1
$$;

-- 5) รายการที่ต้องแจ้งผู้อนุมัติ (ยังไม่เคยแจ้ง) — รวมต่อผู้อนุมัติ/ขั้น/รอบการส่ง · ใช้โดย Edge Function (service_role)
drop function if exists public.ap_queue(text);
create or replace function public.ap_code_name(p_code text) returns text
language sql stable security definer set search_path = public as $$
  select left(coalesce((select p.name from public.projects p where p.id = p_code),
                       (select c.name from public.contracts c where c.id = p_code), ''), 40)
$$;
revoke all on function public.ap_code_name(text) from public, anon, authenticated;

create or replace function public.ap_queue(p_sheet text)
returns table (line_user_id text, role text, sub text, n int, hours numeric, labels text, owner_id text, owner_name text, day date, owner_dept text)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare t public.timesheets%rowtype;
begin
  perform pg_advisory_xact_lock(hashtext('ap_queue|' || p_sheet));
  select * into t from public.timesheets where id = p_sheet and status = 'Pending';
  if t.id is null then return; end if;

  return query
  with ent as (
    select a.x as e, a.i as idx, a.x->>'id' as eid, public.ap_next(t.emp_id, a.x) as nr, coalesce(a.x->'ap'->>'sub', '') as sb
      from jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where coalesce(a.x->'ap'->>'s', 'P') = 'P'
  ),
  cand as (
    select distinct ent.e, ent.idx, ent.eid, ent.nr, ent.sb, s.emp_id as approver
      from ent join public.approver_scopes s
        on s.role = ent.nr and s.emp_id <> t.emp_id and public.ap_scope_ok(s, t.emp_id, ent.e->>'code')
     where ent.nr is not null
  ),
  fresh as (
    select c.*, em.line_user_id as lu
      from cand c join public.employees em
        on em.id = c.approver and em.active and em.approved and em.line_user_id is not null
     where (c.e->>'rb') is distinct from c.approver
       and not exists (select 1 from public.ap_notified nt
                        where nt.key = p_sheet || '|' || c.eid || '|' || c.nr || '|' || c.sb || '|' || c.approver)
  ),
  ins as (
    insert into public.ap_notified (key)
    select distinct p_sheet || '|' || f.eid || '|' || f.nr || '|' || f.sb || '|' || f.approver from fresh f
    on conflict do nothing
    returning key
  )
  select f.lu, f.nr, f.sb, count(*)::int,
         coalesce(sum((f.e->>'hours')::numeric), 0),
         string_agg(t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(f.idx::text, 2, '0') || ' · '
                    || coalesce(f.e->>'code', f.e->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(f.e->>'code'), ''), '')
                    || ' · ' || coalesce(f.e->>'hours', '0') || ' ชม.', E'\n' order by f.idx),
         t.emp_id, (select em.name from public.employees em where em.id = t.emp_id), t.day,
         (select trim(coalesce(em.dept, '') || ' ' || coalesce(d.name, '')) from public.employees em
            left join public.departments d on d.id = em.dept where em.id = t.emp_id)
    from fresh f
   group by f.lu, f.nr, f.sb;
end $$;

-- 6) อนุมัติผ่าน LINE: ตรวจสิทธิ์จาก LINE userId → ขอบเขต/ขั้น/ผู้อนุมัติ แล้วอนุมัติ 1 ขั้นให้ทุกรายการในใบที่ถึงคิวของผู้นั้น
--    p_dry = true → ตรวจและสรุปจำนวน ไม่บันทึก (ใช้ในขั้นยืนยัน)
create or replace function public.line_approve(p_line_user text, p_sheet text, p_role text, p_sub text, p_dry boolean default false)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  me public.employees%rowtype; t public.timesheets%rowtype;
  x jsonb; ne jsonb; ap jsonb; arr jsonb := '[]'::jsonb;
  n int := 0; k int := 0; hrs numeric := 0; labels text := ''; all_a boolean; owner_name text; owner_dept text;
  now_ text := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;

  select * into t from public.timesheets where id = p_sheet for update;
  if t.id is null or t.status <> 'Pending' then
    return jsonb_build_object('ok', false, 'msg', 'ใบงานนี้ไม่ได้อยู่ในสถานะรออนุมัติแล้ว (อาจมีการอนุมัติ/ส่งกลับ/แก้ไขไปแล้ว)');
  end if;
  if t.emp_id = me.id then return jsonb_build_object('ok', false, 'msg', 'อนุมัติรายการของตัวเองไม่ได้'); end if;
  select em.name, trim(coalesce(em.dept, '') || ' ' || coalesce(d.name, '')) into owner_name, owner_dept
    from public.employees em left join public.departments d on d.id = em.dept where em.id = t.emp_id;

  for x in select value from jsonb_array_elements(t.entries) loop
    ne := x; k := k + 1;
    if coalesce(x->'ap'->>'s', 'P') = 'P'
       and (coalesce(p_sub, '') = '' or coalesce(x->'ap'->>'sub', '') = p_sub)
       and public.ap_next(t.emp_id, x) = p_role
       and (x->>'rb') is distinct from me.id
       and exists (select 1 from public.approver_scopes s
                    where s.emp_id = me.id and s.role = p_role and public.ap_scope_ok(s, t.emp_id, x->>'code')) then
      n := n + 1; hrs := hrs + coalesce((x->>'hours')::numeric, 0);
      labels := labels || case when labels = '' then '' else E'\n' end
                || t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(k::text, 2, '0') || ' · '
                || coalesce(x->>'code', x->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(x->>'code'), ''), '')
                || ' · ' || coalesce(x->>'hours', '0') || ' ชม.';
      if not p_dry then
        ap := coalesce(x->'ap', '{}'::jsonb);
        ne := jsonb_set(x, '{ap}',
              jsonb_build_object('s', 'P',
                                 'done', coalesce(ap->'done', '[]'::jsonb) || to_jsonb(p_role),
                                 'hist', coalesce(ap->'hist', '[]'::jsonb) || jsonb_build_array(jsonb_build_object('role', p_role, 'by', me.name, 'at', now_)),
                                 'by', me.name, 'at', now_)
              || case when ap->'sub' is not null then jsonb_build_object('sub', ap->'sub') else '{}'::jsonb end, true);
        if public.ap_next(t.emp_id, ne) is null then ne := jsonb_set(ne, '{ap,s}', '"A"'::jsonb); end if;
      end if;
    end if;
    arr := arr || jsonb_build_array(ne);
  end loop;

  if n = 0 then
    return jsonb_build_object('ok', false, 'msg', 'ไม่มีรายการที่คุณอนุมัติได้ในใบนี้ (ไม่ใช่คิวของคุณ หรือมีคนอนุมัติ/พนักงานแก้ไขไปแล้ว)');
  end if;
  if p_dry then
    return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', owner_name, 'dept', owner_dept, 'day', t.day, 'finished', false);
  end if;

  select bool_and(coalesce(y->'ap'->>'s', 'P') = 'A') into all_a from jsonb_array_elements(arr) y;
  update public.timesheets
     set entries = arr,
         status = case when all_a then 'Submitted' else 'Pending' end,
         approved_by = me.name, approved_at = now(),
         reject_note = case when all_a then '' else reject_note end
   where id = t.id;
  return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', owner_name, 'dept', owner_dept, 'day', t.day, 'finished', all_a);
end $$;

revoke all on function public.ap_step(text, text)                                   from public, anon, authenticated;
revoke all on function public.ap_scope_ok(public.approver_scopes, text, text)       from public, anon, authenticated;
revoke all on function public.ap_chain(text, jsonb)                                 from public, anon, authenticated;
revoke all on function public.ap_next(text, jsonb)                                  from public, anon, authenticated;
revoke all on function public.ap_queue(text)                                        from public, anon, authenticated;
revoke all on function public.line_approve(text, text, text, text, boolean)         from public, anon, authenticated;
grant execute on function public.ap_queue(text)                                     to service_role;
grant execute on function public.line_approve(text, text, text, text, boolean)      to service_role;

-- ===== v65: รวมรายการอนุมัติหลายรายการไว้ในการ์ดเดียว + อนุมัติทั้งหมดครั้งเดียว =====
-- ap_digest: รวม "ทุกรายการที่ถึงคิวของผู้อนุมัติแต่ละคน" (ทุกใบงาน) เป็นชุดเดียวต่อคน — ส่งเมื่อมีรายการใหม่ที่ยังไม่เคยแจ้งอย่างน้อย 1 รายการ
--            (Edge Function จะหน่วงไว้ไม่กี่วินาทีก่อนเรียก เพื่อรวมใบที่ส่งมาพร้อมกันเป็นการ์ดใบเดียว)
create or replace function public.ap_digest()
returns table (line_user_id text, approver_id text, approver_name text, n_new int, n_all int, hours numeric, sheets int, groups jsonb)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
begin
  perform pg_advisory_xact_lock(hashtext('ap_digest'));
  return query
  with ent as (
    select t.id as sid, t.emp_id as oid, t.day as dd, a.x as e, a.i as idx, a.x->>'id' as eid,
           public.ap_next(t.emp_id, a.x) as nr, coalesce(a.x->'ap'->>'sub', '') as sb
      from public.timesheets t, jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where t.status = 'Pending' and coalesce(a.x->'ap'->>'s', 'P') = 'P'
  ),
  cand as (
    select distinct ent.sid, ent.oid, ent.dd, ent.e, ent.idx, ent.eid, ent.nr, ent.sb, s.emp_id as approver
      from ent join public.approver_scopes s
        on s.role = ent.nr and s.emp_id <> ent.oid and public.ap_scope_ok(s, ent.oid, ent.e->>'code')
     where ent.nr is not null and (ent.e->>'rb') is distinct from s.emp_id
  ),
  due as (
    select c.*, em.line_user_id as lu, em.name as aname,
           exists (select 1 from public.ap_notified nt
                    where nt.key = c.sid || '|' || c.eid || '|' || c.nr || '|' || c.sb || '|' || c.approver) as seen
      from cand c join public.employees em
        on em.id = c.approver and em.active and em.approved and em.line_user_id is not null
  ),
  targets as (select d.approver from due d group by d.approver having bool_or(not d.seen)),
  ins as (
    insert into public.ap_notified (key)
    select distinct d.sid || '|' || d.eid || '|' || d.nr || '|' || d.sb || '|' || d.approver
      from due d where d.approver in (select approver from targets) and not d.seen
    on conflict do nothing
    returning key
  ),
  grp as (
    select d.approver, d.lu, d.aname, d.sid, d.oid, d.dd,
           (select em.name from public.employees em where em.id = d.oid) as oname,
           (select trim(coalesce(em.dept, '') || ' ' || coalesce(dp.name, '')) from public.employees em
              left join public.departments dp on dp.id = em.dept where em.id = d.oid) as odept,
           count(*) as n, count(*) filter (where not d.seen) as nn, sum((d.e->>'hours')::numeric) as h,
           jsonb_agg(jsonb_build_object(
             'tx', d.oid || '-' || to_char(d.dd, 'DDMMYY') || '-' || lpad(d.idx::text, 2, '0'),
             'code', coalesce(d.e->>'code', d.e->>'sgaId', '-'),
             'name', public.ap_code_name(d.e->>'code'),
             'h', d.e->>'hours', 'new', not d.seen) order by d.idx) as items
      from due d where d.approver in (select approver from targets)
     group by d.approver, d.lu, d.aname, d.sid, d.oid, d.dd
  )
  select g.lu, g.approver, g.aname, sum(g.nn)::int, sum(g.n)::int, sum(g.h), count(*)::int,
         jsonb_agg(jsonb_build_object('sheet', g.sid, 'owner_id', g.oid, 'owner', g.oname, 'dept', g.odept, 'day', g.dd, 'items', g.items)
                   order by g.dd, g.oid)
    from grp g
   where (select count(*) from ins) >= 0
   group by g.lu, g.approver, g.aname;
end $$;

-- ap_apply_sheet: อนุมัติ 1 ขั้นให้ทุกรายการในใบที่ถึงคิวของผู้ใช้ (ใช้ขั้นของแต่ละรายการเอง) · p_dry = ตรวจอย่างเดียว
create or replace function public.ap_apply_sheet(p_me_id text, p_me_name text, p_sheet text, p_dry boolean)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  t public.timesheets%rowtype; x jsonb; ne jsonb; ap jsonb; arr jsonb := '[]'::jsonb; labels jsonb := '[]'::jsonb;
  n int := 0; k int := 0; hrs numeric := 0; all_a boolean; nr text; oname text;
  now_ text := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_dry then
    select * into t from public.timesheets where id = p_sheet and status = 'Pending';
  else
    select * into t from public.timesheets where id = p_sheet and status = 'Pending' for update;
  end if;
  if t.id is null or t.emp_id = p_me_id then return jsonb_build_object('n', 0); end if;
  select name into oname from public.employees where id = t.emp_id;

  for x in select value from jsonb_array_elements(t.entries) loop
    ne := x; k := k + 1;
    if coalesce(x->'ap'->>'s', 'P') = 'P' then
      nr := public.ap_next(t.emp_id, x);
      if nr is not null and (x->>'rb') is distinct from p_me_id
         and exists (select 1 from public.approver_scopes s
                      where s.emp_id = p_me_id and s.role = nr and public.ap_scope_ok(s, t.emp_id, x->>'code')) then
        n := n + 1; hrs := hrs + coalesce((x->>'hours')::numeric, 0);
        labels := labels || jsonb_build_array(
          t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(k::text, 2, '0') || ' · '
          || coalesce(x->>'code', x->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(x->>'code'), ''), '')
          || ' · ' || coalesce(x->>'hours', '0') || ' ชม.');
        if not p_dry then
          ap := coalesce(x->'ap', '{}'::jsonb);
          ne := jsonb_set(x, '{ap}',
                jsonb_build_object('s', 'P',
                                   'done', coalesce(ap->'done', '[]'::jsonb) || to_jsonb(nr),
                                   'hist', coalesce(ap->'hist', '[]'::jsonb) || jsonb_build_array(jsonb_build_object('role', nr, 'by', p_me_name, 'at', now_)),
                                   'by', p_me_name, 'at', now_)
                || case when ap->'sub' is not null then jsonb_build_object('sub', ap->'sub') else '{}'::jsonb end, true);
          if public.ap_next(t.emp_id, ne) is null then ne := jsonb_set(ne, '{ap,s}', '"A"'::jsonb); end if;
        end if;
      end if;
    end if;
    arr := arr || jsonb_build_array(ne);
  end loop;

  if n = 0 or p_dry then
    return jsonb_build_object('n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', oname, 'finished', false);
  end if;
  select bool_and(coalesce(y->'ap'->>'s', 'P') = 'A') into all_a from jsonb_array_elements(arr) y;
  update public.timesheets
     set entries = arr, status = case when all_a then 'Submitted' else 'Pending' end,
         approved_by = p_me_name, approved_at = now(),
         reject_note = case when all_a then '' else reject_note end
   where id = t.id;
  return jsonb_build_object('n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', oname, 'finished', all_a);
end $$;

-- line_approve_all: อนุมัติ "ทุกรายการที่ถึงคิวของฉัน" ทุกใบงานในครั้งเดียว
--   p_dry = สรุปจำนวนเพื่อขอยืนยัน · p_expect = จำนวนที่ผู้ใช้เห็นตอนยืนยัน (ถ้ามีรายการใหม่เข้ามาระหว่างนั้น จะไม่อนุมัติ ให้ดูใหม่ก่อน)
create or replace function public.line_approve_all(p_line_user text, p_expect int default null, p_dry boolean default false)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  me public.employees%rowtype; sid text; r jsonb;
  n int := 0; hrs numeric := 0; sheets int := 0; fin int := 0; labels jsonb := '[]'::jsonb; owners text[] := '{}';
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;

  for sid in select t.id from public.timesheets t where t.status = 'Pending' and t.emp_id <> me.id order by t.id loop
    r := public.ap_apply_sheet(me.id, me.name, sid, true);
    if (r->>'n')::int > 0 then
      n := n + (r->>'n')::int; hrs := hrs + (r->>'hours')::numeric; sheets := sheets + 1;
      owners := array_append(owners, r->>'owner_id');
      if jsonb_array_length(labels) < 30 then labels := labels || (r->'labels'); end if;
    end if;
  end loop;
  if n = 0 then return jsonb_build_object('ok', false, 'msg', 'ไม่มีรายการที่รออนุมัติของคุณแล้ว (อาจมีคนอนุมัติ/ส่งกลับ/แก้ไขไปแล้ว)'); end if;

  if p_dry then
    return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'sheets', sheets,
                              'people', (select count(distinct o) from unnest(owners) o), 'labels', labels);
  end if;
  if p_expect is not null and p_expect <> n then
    return jsonb_build_object('ok', false, 'n', n,
      'msg', 'จำนวนรายการรออนุมัติเปลี่ยนจาก ' || p_expect || ' เป็น ' || n || ' รายการ (มีรายการใหม่เข้ามา หรือมีผู้อื่นอนุมัติแล้ว) — ยังไม่ได้อนุมัติ กรุณากดปุ่ม "อนุมัติทั้งหมด" ในการ์ดอีกครั้งเพื่อดูจำนวนล่าสุด');
  end if;

  n := 0; hrs := 0; sheets := 0;
  for sid in select t.id from public.timesheets t where t.status = 'Pending' and t.emp_id <> me.id order by t.id loop
    r := public.ap_apply_sheet(me.id, me.name, sid, false);
    if (r->>'n')::int > 0 then
      n := n + (r->>'n')::int; hrs := hrs + (r->>'hours')::numeric; sheets := sheets + 1;
      if (r->>'finished')::boolean then fin := fin + 1; end if;
    end if;
  end loop;
  return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'sheets', sheets, 'finished_sheets', fin);
end $$;

revoke all on function public.ap_digest()                                         from public, anon, authenticated;
revoke all on function public.ap_apply_sheet(text, text, text, boolean)           from public, anon, authenticated;
revoke all on function public.line_approve_all(text, int, boolean)                from public, anon, authenticated;
grant execute on function public.ap_digest()                                      to service_role;
grant execute on function public.line_approve_all(text, int, boolean)             to service_role;

-- ===== Rich menu: ปุ่ม "รออนุมัติ" และ "สถานะของฉัน" ใน LINE =====
-- ap_my_pending: รายการที่ถึงคิวของผู้ใช้ (ทุกใบงาน) จัดกลุ่มตามใบงาน — ไม่บันทึกว่าแจ้งแล้ว (ใช้เมื่อกดเมนูเอง)
create or replace function public.ap_my_pending(p_line_user text) returns jsonb
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare me public.employees%rowtype; res jsonb;
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ — ผูกบัญชีในแอปก่อน'); end if;
  with ent as (
    select t.id as sid, t.emp_id as oid, t.day as dd, a.x as e, a.i as idx, public.ap_next(t.emp_id, a.x) as nr
      from public.timesheets t, jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where t.status = 'Pending' and t.emp_id <> me.id and coalesce(a.x->'ap'->>'s', 'P') = 'P'
  ),
  due as (
    select distinct ent.* from ent
     where ent.nr is not null and (ent.e->>'rb') is distinct from me.id
       and exists (select 1 from public.approver_scopes s
                    where s.emp_id = me.id and s.role = ent.nr and public.ap_scope_ok(s, ent.oid, ent.e->>'code'))
  ),
  grp as (
    select d.sid, d.oid, d.dd,
           (select em.name from public.employees em where em.id = d.oid) as oname,
           (select trim(coalesce(em.dept, '') || ' ' || coalesce(dp.name, '')) from public.employees em
              left join public.departments dp on dp.id = em.dept where em.id = d.oid) as odept,
           count(*) as n, sum((d.e->>'hours')::numeric) as h,
           jsonb_agg(jsonb_build_object(
             'tx', d.oid || '-' || to_char(d.dd, 'DDMMYY') || '-' || lpad(d.idx::text, 2, '0'),
             'code', coalesce(d.e->>'code', d.e->>'sgaId', '-'), 'name', public.ap_code_name(d.e->>'code'),
             'h', d.e->>'hours', 'new', false) order by d.idx) as items
      from due d group by d.sid, d.oid, d.dd
  )
  select jsonb_build_object('ok', true, 'n_all', coalesce(sum(g.n), 0)::int, 'n_new', coalesce(sum(g.n), 0)::int,
                            'hours', coalesce(sum(g.h), 0), 'sheets', count(*)::int,
                            'groups', coalesce(jsonb_agg(jsonb_build_object('sheet', g.sid, 'owner_id', g.oid, 'owner', g.oname,
                                       'dept', g.odept, 'day', g.dd, 'items', g.items) order by g.dd, g.oid), '[]'::jsonb))
    into res from grp g;
  return res;
end $$;

-- ap_my_status: สรุปสถานะของฉัน (วันนี้ / เดือนนี้ / รออนุมัติ / ถูกส่งกลับ) ตามเวลาไทย
create or replace function public.ap_my_status(p_line_user text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; today date := (now() at time zone 'Asia/Bangkok')::date; res jsonb;
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ — ผูกบัญชีในแอปก่อน'); end if;
  select jsonb_build_object(
    'ok', true, 'name', me.name, 'dept', me.dept, 'today', today,
    'today_hours', coalesce((select sum((x->>'hours')::numeric) from public.timesheets t, jsonb_array_elements(t.entries) x
                              where t.emp_id = me.id and t.day = today), 0),
    'today_status', (select t.status from public.timesheets t where t.emp_id = me.id and t.day = today),
    'month_hours', coalesce((select sum((x->>'hours')::numeric) from public.timesheets t, jsonb_array_elements(t.entries) x
                              where t.emp_id = me.id and date_trunc('month', t.day) = date_trunc('month', today)), 0),
    'pending_entries', coalesce((select count(*) from public.timesheets t, jsonb_array_elements(t.entries) x
                                  where t.emp_id = me.id and t.status = 'Pending' and coalesce(x->'ap'->>'s', 'P') = 'P'), 0),
    'approved_entries', coalesce((select count(*) from public.timesheets t, jsonb_array_elements(t.entries) x
                                   where t.emp_id = me.id and t.day >= today - 30
                                     and (x->'ap'->>'s' = 'A' or (x->'ap' is null and t.status = 'Submitted'))), 0),
    'rejected_sheets', coalesce((select jsonb_agg(jsonb_build_object('day', t.day, 'note', t.reject_note) order by t.day desc)
                                  from public.timesheets t where t.emp_id = me.id and t.status = 'Draft' and coalesce(t.reject_note, '') <> ''), '[]'::jsonb),
    'draft_days', coalesce((select count(*) from public.timesheets t where t.emp_id = me.id and t.status = 'Draft'
                             and t.day >= today - 14 and jsonb_array_length(t.entries) > 0), 0))
    into res;
  return res;
end $$;

revoke all on function public.ap_my_pending(text) from public, anon, authenticated;
revoke all on function public.ap_my_status(text)  from public, anon, authenticated;
grant execute on function public.ap_my_pending(text) to service_role;
grant execute on function public.ap_my_status(text)  to service_role;

-- 7) trigger: ใบงานเปลี่ยนเป็นรออนุมัติ/ขยับขั้น → แจ้งผู้อนุมัติ · อนุมัติครบ/ส่งกลับ → แจ้งเจ้าของใบงาน
--    (ใช้ค่า line_notify_url / line_notify_secret ใน private_config ชุดเดียวกับการแจ้งสมาชิกใหม่ ต้องตั้งไว้แล้ว)
create or replace function public.notify_line_ts() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_url text; v_sec text; v_kind text;
begin
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is null or v_sec is null then return new; end if;
    if new.status = 'Pending' and (tg_op = 'INSERT' or old.status is distinct from 'Pending' or old.entries is distinct from new.entries) then
      v_kind := 'approval_queue';
    elsif tg_op = 'UPDATE' and old.status = 'Pending' and new.status = 'Submitted' then
      v_kind := 'sheet_approved';
    elsif tg_op = 'UPDATE' and old.status = 'Pending' and new.status = 'Draft' and coalesce(new.reject_note, '') <> '' then
      v_kind := 'sheet_rejected';
    end if;
    if v_kind is not null then
      perform net.http_post(
        url     := v_url,
        headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
        body    := jsonb_build_object('kind', v_kind, 'sheet_id', new.id, 'emp_id', new.emp_id));
    end if;
  exception when others then
    null;   -- ห้ามให้การแจ้งเตือนทำให้การบันทึก/อนุมัติล้มเหลว
  end;
  return new;
end $$;

drop trigger if exists line_notify_ts on public.timesheets;
create trigger line_notify_ts after insert or update on public.timesheets
  for each row execute function public.notify_line_ts();

-- ===== supabase_update_attachments.sql =====
-- v67: แนบไฟล์ / ถ่ายภาพประกอบรายการงาน (Supabase Storage)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_budget_delegate.sql เพราะใช้ฟังก์ชัน can_enter_for) — รันซ้ำได้
--
-- bucket "timesheet-files" เป็นแบบ private (ไม่เปิดสาธารณะ) เปิดดูไฟล์ผ่านลิงก์ชั่วคราว 10 นาทีเท่านั้น
-- โครงสร้างไฟล์: <รหัสพนักงานเจ้าของใบงาน>/<รหัสใบงาน>/<รหัสรายการ>/<ไฟล์>
-- สิทธิ์:  เจ้าของใบงาน และผู้บันทึกแทน อัปโหลด/ลบได้ · ผู้อนุมัติ/ผู้ดูแลระบบดูได้ · คนอื่นเข้าไม่ได้

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('timesheet-files', 'timesheet-files', false, 10485760, array[
  'image/jpeg','image/png','image/webp','image/heic','image/heif','image/gif',
  'application/pdf','text/plain','text/csv',
  'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint','application/vnd.openxmlformats-officedocument.presentationml.presentation'])
on conflict (id) do update
  set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists tsf_read on storage.objects;
create policy tsf_read on storage.objects for select to authenticated
  using (bucket_id = 'timesheet-files'
         and (public.is_admin() or public.is_approver()
              or (storage.foldername(name))[1] = public.my_emp_id()
              or public.can_enter_for((storage.foldername(name))[1])));

drop policy if exists tsf_insert on storage.objects;
create policy tsf_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'timesheet-files'
              and ((storage.foldername(name))[1] = public.my_emp_id()
                   or public.can_enter_for((storage.foldername(name))[1])));

drop policy if exists tsf_delete on storage.objects;
create policy tsf_delete on storage.objects for delete to authenticated
  using (bucket_id = 'timesheet-files'
         and ((storage.foldername(name))[1] = public.my_emp_id()
              or public.can_enter_for((storage.foldername(name))[1])
              or public.is_super_admin()));

-- ===== supabase_update_admin_step.sql =====
-- v68: เพิ่ม Role อนุมัติ "ธุรการ (Admin)" เป็นขั้นที่ 1 (ก่อน PM / Mgr / ผอ. / COO / CEO)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลังไฟล์อัปเดตก่อนหน้าทั้งหมด) — รันซ้ำได้ (เลื่อนขั้นเดิมเพียงครั้งเดียว)
--
-- สิ่งที่ทำ: 1) อนุญาตค่า Role 'adm' และขั้นที่ 6 ในตารางสิทธิ์/ผู้อนุมัติ
--            2) ครั้งแรก: เลื่อนขั้นเดิมของทุก Role ลง 1 ขั้น (ขั้น 1→2 … 5→6) แล้วให้ธุรการ (Admin) เป็นขั้นที่ 1 ทั้ง COST และ SG&A
--               (ลำดับสัมพัทธ์และการตั้งค่าเดิมของคุณคงไว้ — เช่น PM ขั้น 1 → ขั้น 2, CEO ขั้น 5 → ขั้น 6; ปรับแก้ได้ในหน้า Role and permission)
--            3) กำหนดสิทธิ์ดูข้อมูลค่าใช้จ่ายเริ่มต้นของธุรการ (เห็นชั่วโมง ตามขอบเขตผู้อนุมัติ) ปรับได้ภายหลัง
-- หมายเหตุ: ขั้นที่ไม่มีผู้อนุมัติธุรการในขอบเขตของรายการ จะถูกข้ามอัตโนมัติ — ยังไม่กระทบจนกว่าจะกำหนดผู้อนุมัติธุรการ

-- 1) ปลด constraint เดิมของ role (ชื่ออาจต่างกันตามเวอร์ชัน จึงค้นหาจากนิยาม) แล้วสร้างใหม่ให้รวม 'adm'
do $$
declare c record;
begin
  for c in
    select conname, conrelid::regclass as tbl
      from pg_constraint
     where contype = 'c'
       and conrelid in ('public.approval_perms'::regclass, 'public.approver_scopes'::regclass)
       and pg_get_constraintdef(oid) ilike '%role%'
  loop
    execute format('alter table %s drop constraint %I', c.tbl, c.conname);
  end loop;
end $$;

alter table public.approval_perms  add constraint approval_perms_role_check  check (role in ('adm','pm','mgr','dir','coo','ceo'));
alter table public.approver_scopes add constraint approver_scopes_role_check check (role in ('adm','pm','mgr','dir','coo','ceo'));
alter table public.approval_perms drop constraint if exists approval_perms_perm_check;
alter table public.approval_perms add constraint approval_perms_perm_check check (perm in ('yes','no','na','1','2','3','4','5','6'));

-- 2) เลื่อนขั้นเดิมลง 1 ขั้น แล้วเพิ่ม Admin เป็นขั้นที่ 1 (ทำครั้งเดียว — ตรวจจากการยังไม่มีแถวของ adm)
do $$
begin
  if not exists (select 1 from public.approval_perms where role = 'adm') then
    update public.approval_perms set perm = (perm::int + 1)::text where perm ~ '^[1-5]$';
    insert into public.approval_perms (role, cat, perm) values ('adm', 'cost', '1'), ('adm', 'sga', '1')
    on conflict (role, cat) do nothing;
  end if;
end $$;

-- 3) สิทธิ์ดูข้อมูลค่าใช้จ่ายเริ่มต้นของธุรการ (ตาราง cost_access มาจากไฟล์ supabase_update_cost_access*.sql)
do $$
begin
  if to_regclass('public.cost_access') is not null then
    execute 'alter table public.cost_access drop constraint if exists cost_access_subject_check';   -- subject รับ Role อนุมัติใหม่ได้
    insert into public.cost_access (subject, level) values ('adm', 'hours') on conflict (subject) do nothing;
    if exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'cost_access' and column_name = 'scope') then
      update public.cost_access set scope = 'scoped' where subject = 'adm' and scope = 'all';
    end if;
  end if;
end $$;

-- ===== supabase_update_hub.sql =====
-- v70: หน้าหลักแยกระบบย่อย — (1) รหัส PIN เข้าระบบ  (2) ลงเวลาเข้า-ออกงาน/ออกนอกสถานที่ + GPS + AI-Beacon  (3) ระบบลางาน เชื่อมชั่วโมงของ Workload
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_budget_delegate.sql) — รันซ้ำได้
-- ตัวเลขโควตาวันลาเป็นค่าเริ่มต้นสมมติ ต้องให้ผู้รับผิดชอบ (HR) ตรวจและแก้ให้ตรงนโยบายบริษัทก่อนใช้จริง (ตั้งค่าข้อมูล › ประเภทการลา)

create extension if not exists pgcrypto with schema extensions;

-- ======================================================================
-- 1) PIN 6 หลัก (ตรวจที่ฐานข้อมูล · เก็บแบบแฮช · ผิด 5 ครั้งล็อก 15 นาที)
-- ======================================================================
create table if not exists public.user_pins (
  emp_id       text primary key references public.employees(id) on delete cascade,
  pin_hash     text not null,
  fails        int  not null default 0,
  locked_until timestamptz,
  updated_at   timestamptz not null default now()
);
alter table public.user_pins enable row level security;
revoke all on public.user_pins from anon, authenticated;     -- เข้าถึงผ่านฟังก์ชันด้านล่างเท่านั้น

create or replace function public.pin_status() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  select * into p from public.user_pins where emp_id = v_emp;
  return jsonb_build_object('ok', true, 'has_pin', p.emp_id is not null,
    'locked_until', case when p.locked_until > now() then p.locked_until end);
end $$;

-- ตรวจ PIN (ผิดติดกัน 5 ครั้ง ล็อก 15 นาที)
create or replace function public.verify_pin(p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  select * into p from public.user_pins where emp_id = v_emp for update;
  if p.emp_id is null then return jsonb_build_object('ok', false, 'error', 'NO_PIN'); end if;
  if p.locked_until is not null and p.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'LOCKED', 'locked_until', p.locked_until);
  end if;
  if p.pin_hash = extensions.crypt(coalesce(p_pin, ''), p.pin_hash) then
    update public.user_pins set fails = 0, locked_until = null where emp_id = v_emp;
    return jsonb_build_object('ok', true);
  end if;
  update public.user_pins
     set fails = case when fails + 1 >= 5 then 0 else fails + 1 end,
         locked_until = case when fails + 1 >= 5 then now() + interval '15 minutes' end
   where emp_id = v_emp;
  select * into p from public.user_pins where emp_id = v_emp;
  return jsonb_build_object('ok', false, 'error', case when p.locked_until > now() then 'LOCKED' else 'WRONG' end,
                            'remaining', 5 - p.fails, 'locked_until', case when p.locked_until > now() then p.locked_until end);
end $$;

-- ตั้ง/เปลี่ยน PIN: (ยังไม่มี PIN) หรือ (ใส่ PIN เดิมถูก) หรือ (เพิ่งล็อกอินด้วยรหัสผ่านภายใน 5 นาที = กรณีลืม PIN)
create or replace function public.set_pin(p_new text, p_old text default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype; v_auth bigint; v_ok boolean := false;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  if p_new is null or p_new !~ '^\d{6}$' then return jsonb_build_object('ok', false, 'error', 'FORMAT'); end if;
  if p_new ~ '^(\d)\1{5}$' or p_new in ('123456', '654321', '012345', '123123') then return jsonb_build_object('ok', false, 'error', 'WEAK'); end if;
  select * into p from public.user_pins where emp_id = v_emp for update;
  if p.emp_id is null then v_ok := true;
  else
    if p.locked_until is not null and p.locked_until > now() then return jsonb_build_object('ok', false, 'error', 'LOCKED', 'locked_until', p.locked_until); end if;
    if p_old is not null and p.pin_hash = extensions.crypt(p_old, p.pin_hash) then v_ok := true; end if;
    if not v_ok then   -- เพิ่งยืนยันตัวตนด้วยรหัสผ่านใน 5 นาทีที่ผ่านมา (JWT amr.timestamp)
      begin v_auth := (auth.jwt() -> 'amr' -> 0 ->> 'timestamp')::bigint; exception when others then v_auth := null; end;
      if v_auth is not null and extract(epoch from now()) - v_auth <= 300 then v_ok := true; end if;
    end if;
  end if;
  if not v_ok then return jsonb_build_object('ok', false, 'error', 'PIN_REQUIRED'); end if;
  insert into public.user_pins (emp_id, pin_hash) values (v_emp, extensions.crypt(p_new, extensions.gen_salt('bf')))
  on conflict (emp_id) do update set pin_hash = excluded.pin_hash, fails = 0, locked_until = null, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- Super Admin รีเซ็ต PIN ให้พนักงาน (พนักงานตั้งใหม่ตอนเข้าระบบครั้งถัดไป)
create or replace function public.admin_reset_pin(p_emp text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  delete from public.user_pins where emp_id = p_emp;
end $$;

revoke all on function public.pin_status(), public.verify_pin(text), public.set_pin(text, text), public.admin_reset_pin(text) from public, anon;
grant execute on function public.pin_status(), public.verify_pin(text), public.set_pin(text, text), public.admin_reset_pin(text) to authenticated;

-- ======================================================================
-- 2) ลงเวลาเข้า-ออกงาน / ออกไปทำงานนอกสถานที่ (GPS + AI-Beacon)
-- ======================================================================
create table if not exists public.work_sites (            -- จุดทำงาน/สำนักงาน พร้อมรัศมีที่ถือว่าอยู่ในพื้นที่
  id       text primary key,
  name     text not null,
  lat      double precision not null,
  lng      double precision not null,
  radius_m int not null default 150 check (radius_m between 20 and 5000),
  active   boolean not null default true
);
create table if not exists public.beacons (                -- อุปกรณ์ Beacon (hwid ตามที่ลงทะเบียนกับ LINE Beacon / AI-Beacon)
  hwid    text primary key,
  name    text not null default '',
  site_id text references public.work_sites(id) on delete set null,
  active  boolean not null default true
);
create table if not exists public.attendance_logs (
  id          uuid primary key default gen_random_uuid(),
  emp_id      text not null references public.employees(id) on delete cascade,
  kind        text not null check (kind in ('in', 'out', 'offsite_start', 'offsite_end')),
  at          timestamptz not null default now(),
  lat         double precision,
  lng         double precision,
  accuracy_m  real,
  site_id     text,
  site_name   text not null default '',
  dist_m      int,
  source      text not null default 'app' check (source in ('app', 'beacon', 'admin')),
  note        text not null default '',
  hwid        text
);
create index if not exists attendance_emp_at on public.attendance_logs (emp_id, at desc);

alter table public.work_sites       enable row level security;
alter table public.beacons          enable row level security;
alter table public.attendance_logs  enable row level security;
revoke all on public.work_sites, public.beacons, public.attendance_logs from anon;

drop policy if exists sites_read on public.work_sites;  create policy sites_read on public.work_sites for select to authenticated using (true);
drop policy if exists sites_super on public.work_sites; create policy sites_super on public.work_sites for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
drop policy if exists beacons_read on public.beacons;   create policy beacons_read on public.beacons for select to authenticated using (public.is_admin());
drop policy if exists beacons_super on public.beacons;  create policy beacons_super on public.beacons for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
-- บันทึกเวลาเขียนผ่านฟังก์ชันเท่านั้น · อ่านได้เฉพาะของตัวเอง และผู้ดูแลระบบ
drop policy if exists att_read on public.attendance_logs;
create policy att_read on public.attendance_logs for select to authenticated using (emp_id = public.my_emp_id() or public.is_admin());

-- ระยะห่าง (เมตร) แบบ haversine
create or replace function public.geo_dist_m(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision) returns double precision
language sql immutable as $$
  select 2 * 6371000 * asin(sqrt(power(sin(radians(lat2 - lat1) / 2), 2) + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)))
$$;

-- ลงเวลา: in / out / offsite_start / offsite_end  (ลำดับ: เริ่ม→เข้า→[ออกนอก→กลับ]→ออก · ตรวจที่ฐานข้อมูล)
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in'            and v_last is not null and v_last <> 'out'                      then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานไปแล้ว'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;

-- AI-Beacon / LINE Beacon: เมื่อพนักงานเข้าใกล้ beacon ครั้งแรกของวัน = ลงเวลาเข้างานอัตโนมัติ (เรียกโดย line-webhook ด้วย service_role)
create or replace function public.att_beacon(p_line_user text, p_hwid text, p_event text default 'enter') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; b public.beacons%rowtype; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; w public.work_sites%rowtype; r public.attendance_logs%rowtype;
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้'); end if;
  select * into b from public.beacons where hwid = p_hwid and active;
  if b.hwid is null then return jsonb_build_object('ok', false, 'msg', 'ไม่ใช่ Beacon ที่ลงทะเบียนไว้'); end if;
  if p_event <> 'enter' then return jsonb_build_object('ok', true, 'ignored', true); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if v_last is not null and v_last <> 'out' then
    return jsonb_build_object('ok', true, 'dup', true, 'name', e.name);       -- วันนี้ลงเวลาเข้าแล้ว ไม่ซ้ำ
  end if;
  if b.site_id is not null then select * into w from public.work_sites where id = b.site_id; end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, site_id, site_name, source, note, hwid)
  values (e.id, 'in', clock_timestamp(), w.lat, w.lng, w.id, coalesce(w.name, b.name), 'beacon', 'ลงเวลาอัตโนมัติจาก Beacon ' || coalesce(nullif(b.name, ''), b.hwid), p_hwid)
  returning * into r;
  return jsonb_build_object('ok', true, 'kind', 'in', 'at', r.at, 'name', e.name, 'site', r.site_name);
end $$;

revoke all on function public.geo_dist_m(double precision, double precision, double precision, double precision) from public, anon;
grant execute on function public.geo_dist_m(double precision, double precision, double precision, double precision) to authenticated;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;
revoke all on function public.att_beacon(text, text, text) from public, anon, authenticated;
grant execute on function public.att_beacon(text, text, text) to service_role;

-- ======================================================================
-- 3) ระบบลางาน (เชื่อมกับการคำนวณชั่วโมงของ Workload: วันลาที่อนุมัติแล้วไม่ต้องบันทึกงาน / เป้าหมายลดลง)
-- ======================================================================
create table if not exists public.leave_types (
  id         text primary key,
  name       text not null,
  quota_days numeric(5,1),                 -- วันต่อปี (null = ไม่จำกัด)
  paid       boolean not null default true,
  color      text not null default '#4f6df5',
  active     boolean not null default true,
  sort       int not null default 0
);
-- ค่าเริ่มต้น (สมมติ — ให้ HR ตรวจ/แก้ตามนโยบายบริษัทและกฎหมายแรงงาน)
insert into public.leave_types (id, name, quota_days, paid, color, sort) values
  ('sick',     'ลาป่วย',        30,  true,  '#e5484d', 1),
  ('personal', 'ลากิจ',         6,   true,  '#f29b2f', 2),
  ('vacation', 'ลาพักร้อน',     6,   true,  '#14a37f', 3),
  ('maternity','ลาคลอด',        98,  true,  '#a259d9', 4),
  ('ordain',   'ลาอุปสมบท/ประกอบพิธีฮัจย์', 15, true, '#2bb3c0', 5),
  ('unpaid',   'ลาไม่รับค่าจ้าง', null, false, '#6a7a93', 6)
on conflict (id) do nothing;

create table if not exists public.leave_requests (
  id          uuid primary key default gen_random_uuid(),
  emp_id      text not null references public.employees(id) on delete cascade,
  type_id     text not null references public.leave_types(id),
  start_date  date not null,
  end_date    date not null,
  part        text not null default 'full' check (part in ('full', 'am', 'pm')),   -- ครึ่งวันใช้ได้เมื่อลาวันเดียว
  days        numeric(5,1) not null,        -- จำนวนวันทำการ (ไม่นับเสาร์-อาทิตย์/วันหยุด) คำนวณที่ฐานข้อมูล
  reason      text not null default '',
  status      text not null default 'Pending' check (status in ('Pending', 'Approved', 'Rejected', 'Cancelled')),
  decided_by  text,
  decided_at  timestamptz,
  decide_note text not null default '',
  created_at  timestamptz not null default now(),
  check (end_date >= start_date)
);
create index if not exists leave_emp on public.leave_requests (emp_id, start_date);

alter table public.leave_types    enable row level security;
alter table public.leave_requests enable row level security;
revoke all on public.leave_types, public.leave_requests from anon;
drop policy if exists lt_read on public.leave_types;  create policy lt_read on public.leave_types for select to authenticated using (true);
drop policy if exists lt_super on public.leave_types; create policy lt_super on public.leave_types for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
-- อ่านได้: ของตัวเอง · ผู้ดูแลระบบ · ผู้อนุมัติ (ใช้คำนวณเป้าหมายชั่วโมงในรายงาน) · เขียนผ่านฟังก์ชันเท่านั้น
drop policy if exists lr_read on public.leave_requests;
create policy lr_read on public.leave_requests for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.is_approver());

create or replace function public.leave_submit(p_type text, p_start date, p_end date, p_part text default 'full', p_reason text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; lt public.leave_types%rowtype; d date; v_days numeric := 0; v_used numeric; r public.leave_requests%rowtype; v_part text := coalesce(p_part, 'full');
begin
  select * into e from public.employees where id = public.my_emp_id();
  if e.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into lt from public.leave_types where id = p_type and active;
  if lt.id is null then raise exception 'BAD_TYPE:ไม่พบประเภทการลา'; end if;
  if p_start is null or p_end is null or p_end < p_start then raise exception 'BAD_DATE:ช่วงวันที่ไม่ถูกต้อง'; end if;
  if v_part <> 'full' and p_start <> p_end then raise exception 'BAD_DATE:ลาครึ่งวันเลือกได้เฉพาะลาวันเดียว'; end if;
  for d in select generate_series(p_start::timestamp, p_end::timestamp, interval '1 day')::date loop
    if extract(dow from d) = 0 then continue; end if;
    if extract(dow from d) = 6 and not e.work_sat then continue; end if;
    if exists (select 1 from public.holidays h where h.day = d) then continue; end if;
    v_days := v_days + 1;
  end loop;
  if v_days = 0 then raise exception 'NO_WORKDAY:ช่วงที่เลือกไม่มีวันทำการ (เสาร์-อาทิตย์/วันหยุด)'; end if;
  if v_part <> 'full' then v_days := 0.5; end if;
  if exists (select 1 from public.leave_requests x where x.emp_id = e.id and x.status in ('Pending', 'Approved')
               and x.start_date <= p_end and x.end_date >= p_start
               and not (x.part <> 'full' and v_part <> 'full' and x.part <> v_part)) then
    raise exception 'OVERLAP:มีรายการลาที่ซ้อนกับช่วงวันนี้อยู่แล้ว';
  end if;
  if lt.quota_days is not null then
    select coalesce(sum(days), 0) into v_used from public.leave_requests x
     where x.emp_id = e.id and x.type_id = lt.id and x.status in ('Pending', 'Approved') and extract(year from x.start_date) = extract(year from p_start);
    if v_used + v_days > lt.quota_days then raise exception 'QUOTA:วันลา% เกินสิทธิ์ (ใช้/รออนุมัติ % จาก % วัน)', lt.name, v_used, lt.quota_days; end if;
  end if;
  insert into public.leave_requests (emp_id, type_id, start_date, end_date, part, days, reason)
  values (e.id, lt.id, p_start, p_end, v_part, v_days, left(coalesce(p_reason, ''), 500)) returning * into r;
  return to_jsonb(r);
end $$;

-- อนุมัติ/ไม่อนุมัติ: Super Admin หรือผู้อนุมัติ (Mgr / ผอ. / COO / CEO) ที่มีขอบเขตครอบคลุมพนักงาน (ฝ่าย / รายบุคคล / ทั้งบริษัท) · ห้ามอนุมัติของตัวเอง
create or replace function public.leave_decide(p_id uuid, p_approve boolean, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; r public.leave_requests%rowtype; o public.employees%rowtype; v_ok boolean;
begin
  select * into me from public.employees where id = public.my_emp_id() and active and approved;
  if me.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into r from public.leave_requests where id = p_id for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status <> 'Pending' then raise exception 'NOT_PENDING:รายการนี้ถูกดำเนินการไปแล้ว'; end if;
  if r.emp_id = me.id and not public.is_super_admin() then raise exception 'FORBIDDEN:อนุมัติการลาของตัวเองไม่ได้'; end if;
  select * into o from public.employees where id = r.emp_id;
  v_ok := public.is_super_admin() or exists (
    select 1 from public.approver_scopes s
     where s.emp_id = me.id and s.role in ('mgr', 'dir', 'coo', 'ceo')
       and (s.scope_type = 'all' or (s.scope_type = 'dept' and s.scope_key = o.dept) or (s.scope_type = 'emp' and s.scope_key = o.id)));
  if not v_ok then raise exception 'FORBIDDEN:ไม่มีสิทธิ์อนุมัติการลาของพนักงานคนนี้'; end if;
  update public.leave_requests
     set status = case when p_approve then 'Approved' else 'Rejected' end, decided_by = me.id, decided_at = now(), decide_note = left(coalesce(p_note, ''), 300)
   where id = p_id returning * into r;
  return to_jsonb(r);
end $$;

create or replace function public.leave_cancel(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); r public.leave_requests%rowtype;
begin
  select * into r from public.leave_requests where id = p_id and emp_id = v_emp for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status = 'Pending' or (r.status = 'Approved' and r.start_date > (now() at time zone 'Asia/Bangkok')::date) then
    update public.leave_requests set status = 'Cancelled', decided_at = now(), decide_note = 'ยกเลิกโดยผู้ลา' where id = p_id returning * into r;
    return to_jsonb(r);
  end if;
  raise exception 'NOT_ALLOWED:ยกเลิกได้เฉพาะรายการที่รออนุมัติ หรือที่อนุมัติแล้วและยังไม่ถึงวันลา';
end $$;

revoke all on function public.leave_submit(text, date, date, text, text), public.leave_decide(uuid, boolean, text), public.leave_cancel(uuid) from public, anon;
grant execute on function public.leave_submit(text, date, date, text, text), public.leave_decide(uuid, boolean, text), public.leave_cancel(uuid) to authenticated;


-- ===== supabase_update_hub2.sql (v71) =====
-- v71: ลงเวลาเข้า-ออกงานได้เฉพาะ "วันทำงาน" ตามปฏิทินของระบบ DWS (วันหยุดในตาราง holidays · เสาร์-อาทิตย์ · พนักงาน Site ที่ติ๊กทำงานวันเสาร์)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub.sql) — รันซ้ำได้

create or replace function public.is_work_day(p_emp text, p_day date) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.holidays h where h.day = p_day)
     and case extract(dow from p_day)::int
           when 0 then false
           when 6 then coalesce((select e.work_sat from public.employees e where e.id = p_emp), false)
           else true end
$$;
revoke all on function public.is_work_day(text, date) from public, anon;
grant execute on function public.is_work_day(text, date) to authenticated, service_role;

-- ลงเวลา: เริ่มวัน (เข้างาน) และออกนอกสถานที่ ทำได้เฉพาะวันทำงาน · ออกงาน/กลับจากนอกสถานที่ปิดรอบที่ค้างอยู่ได้เสมอ
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in'            and v_last is not null and v_last <> 'out'                      then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานไปแล้ว'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;

-- AI-Beacon: ไม่ลงเวลาให้อัตโนมัติในวันที่ไม่ใช่วันทำงาน
create or replace function public.att_beacon(p_line_user text, p_hwid text, p_event text default 'enter') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; b public.beacons%rowtype; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; w public.work_sites%rowtype; r public.attendance_logs%rowtype;
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้'); end if;
  select * into b from public.beacons where hwid = p_hwid and active;
  if b.hwid is null then return jsonb_build_object('ok', false, 'msg', 'ไม่ใช่ Beacon ที่ลงทะเบียนไว้'); end if;
  if p_event <> 'enter' then return jsonb_build_object('ok', true, 'ignored', true); end if;
  if not public.is_work_day(e.id, v_day) then return jsonb_build_object('ok', true, 'ignored', true, 'nonwork', true, 'name', e.name); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if v_last is not null and v_last <> 'out' then
    return jsonb_build_object('ok', true, 'dup', true, 'name', e.name);
  end if;
  if b.site_id is not null then select * into w from public.work_sites where id = b.site_id; end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, site_id, site_name, source, note, hwid)
  values (e.id, 'in', clock_timestamp(), w.lat, w.lng, w.id, coalesce(w.name, b.name), 'beacon', 'ลงเวลาอัตโนมัติจาก Beacon ' || coalesce(nullif(b.name, ''), b.hwid), p_hwid)
  returning * into r;
  return jsonb_build_object('ok', true, 'kind', 'in', 'at', r.at, 'name', e.name, 'site', r.site_name);
end $$;

revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;
revoke all on function public.att_beacon(text, text, text) from public, anon, authenticated;
grant execute on function public.att_beacon(text, text, text) to service_role;



-- ===== supabase_update_hub3.sql (v73) =====
-- v73: ผู้อนุมัติของระบบ "ลางาน" และ "ลงเวลา" กำหนดแยกต่างหากจาก Workload (ไม่ใช้ Role and permission / approver_scopes ของ Workload)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub2.sql) — รันซ้ำได้

create table if not exists public.hub_approvers (
  id         text primary key,                                         -- emp|module|type|key
  emp_id     text not null references public.employees(id) on delete cascade,
  module     text not null check (module in ('leave', 'att')),         -- leave = อนุมัติการลา · att = ดูภาพรวม/ประวัติลงเวลา
  scope_type text not null check (scope_type in ('all', 'dept', 'emp')),
  scope_key  text not null default '*',
  created_at timestamptz not null default now()
);
alter table public.hub_approvers enable row level security;
drop policy if exists hap_read  on public.hub_approvers; create policy hap_read  on public.hub_approvers for select to authenticated using (true);
drop policy if exists hap_super on public.hub_approvers; create policy hap_super on public.hub_approvers for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());

-- ผู้เรียกเป็นผู้อนุมัติของโมดูลนี้ และขอบเขตครอบคลุมพนักงานคนนั้นหรือไม่ (ไม่รวมตัวเอง ยกเว้น Super Admin)
create or replace function public.hub_can(p_module text, p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or (
    p_emp is distinct from public.my_emp_id() and exists (
      select 1 from public.hub_approvers a join public.employees o on o.id = p_emp
       where a.emp_id = public.my_emp_id() and a.module = p_module
         and (a.scope_type = 'all' or (a.scope_type = 'dept' and a.scope_key = o.dept) or (a.scope_type = 'emp' and a.scope_key = o.id))))
$$;
revoke all on function public.hub_can(text, text) from public, anon;
grant execute on function public.hub_can(text, text) to authenticated;

-- ย้ายค่าเดิม (ผู้อนุมัติ Mgr/ผอ./COO/CEO ที่เคยใช้อนุมัติลา) มาเป็นผู้อนุมัติลางานครั้งแรก — หลังจากนี้แก้แยกได้ในเมนู "ผู้อนุมัติ" ของระบบลางาน
insert into public.hub_approvers (id, emp_id, module, scope_type, scope_key)
select s.emp_id || '|leave|' || s.scope_type || '|' || s.scope_key, s.emp_id, 'leave', s.scope_type, s.scope_key
  from public.approver_scopes s
 where s.role in ('mgr', 'dir', 'coo', 'ceo') and s.scope_type in ('all', 'dept', 'emp')
on conflict (id) do nothing;

-- อ่านการลา: ของตัวเอง · ผู้ดูแล · ผู้อนุมัติ Workload (ใช้คำนวณเป้าหมายชั่วโมง) · ผู้อนุมัติลางาน
drop policy if exists lr_read on public.leave_requests;
create policy lr_read on public.leave_requests for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.is_approver() or public.hub_can('leave', emp_id));

-- ดูบันทึกลงเวลา: ของตัวเอง · ผู้ดูแล · ผู้อนุมัติลงเวลาตามขอบเขต
drop policy if exists att_read on public.attendance_logs;
create policy att_read on public.attendance_logs for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.hub_can('att', emp_id));

-- อนุมัติ/ไม่อนุมัติการลา: ใช้ผู้อนุมัติของระบบลางาน (hub_approvers) เท่านั้น
create or replace function public.leave_decide(p_id uuid, p_approve boolean, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; r public.leave_requests%rowtype;
begin
  select * into me from public.employees where id = public.my_emp_id() and active and approved;
  if me.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into r from public.leave_requests where id = p_id for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status <> 'Pending' then raise exception 'NOT_PENDING:รายการนี้ถูกดำเนินการไปแล้ว'; end if;
  if r.emp_id = me.id and not public.is_super_admin() then raise exception 'FORBIDDEN:อนุมัติการลาของตัวเองไม่ได้'; end if;
  if not public.hub_can('leave', r.emp_id) then raise exception 'FORBIDDEN:ไม่มีสิทธิ์อนุมัติการลาของพนักงานคนนี้'; end if;
  update public.leave_requests
     set status = case when p_approve then 'Approved' else 'Rejected' end, decided_by = me.id, decided_at = now(), decide_note = left(coalesce(p_note, ''), 300)
   where id = p_id returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.leave_decide(uuid, boolean, text) from public, anon;
grant execute on function public.leave_decide(uuid, boolean, text) to authenticated;



-- ===== supabase_update_hub4.sql (v89) =====
-- v89: บันทึกชั่วโมงงานได้ก็ต่อเมื่อ "ลงเวลาเข้างานจริง" ของวันนั้นแล้ว (ลงเวลาในแอป หรือ AI-Beacon)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub3.sql) — รันซ้ำได้
-- ตั้งค่า: ตาราง app_settings คีย์ att_required  ค่า {"on": true, "from": "YYYY-MM-DD"}
--   on   = เปิด/ปิดการบังคับ (ปิด: update public.app_settings set value = jsonb_set(value,'{on}','false') where key='att_required';)
--   from = บังคับตั้งแต่วันที่นี้เป็นต้นไป (ค่าตั้งต้น = วันที่รัน SQL นี้ ใบงานย้อนหลังก่อนหน้านั้นไม่ถูกบังคับ)
-- ยกเว้น: Super Admin · วันที่ไม่ใช่วันทำงาน · วันที่ลาเต็มวันที่อนุมัติแล้ว

insert into public.app_settings (key, value)
values ('att_required', jsonb_build_object('on', true, 'from', ((now() at time zone 'Asia/Bangkok')::date)::text))
on conflict (key) do nothing;

create or replace function public.att_required_for(p_emp text, p_day date) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare s jsonb;
begin
  select value into s from public.app_settings where key = 'att_required';
  if s is null or coalesce((s->>'on')::boolean, true) is not true then return false; end if;
  if p_day < coalesce(nullif(s->>'from', '')::date, date '1900-01-01') then return false; end if;
  if not public.is_work_day(p_emp, p_day) then return false; end if;
  if exists (select 1 from public.leave_requests l where l.emp_id = p_emp and l.status = 'Approved' and l.part = 'full'
              and p_day between l.start_date and l.end_date) then return false; end if;
  return true;
end $$;
revoke all on function public.att_required_for(text, date) from public, anon;
grant execute on function public.att_required_for(text, date) to authenticated, service_role;

-- ตัวป้องกัน: เพิ่ม/แก้ใบงานให้ชั่วโมงรวมเพิ่มขึ้น ต้องมีการลงเวลาเข้างาน (kind = 'in') ของวันนั้นก่อน
-- (การอนุมัติ/ส่งกลับที่ไม่เพิ่มชั่วโมง ไม่ถูกบล็อก)
create or replace function public.ts_att_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_new numeric := 0; v_old numeric := 0;
begin
  select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_new from jsonb_array_elements(coalesce(new.entries, '[]'::jsonb)) e;
  if tg_op = 'UPDATE' then
    select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_old from jsonb_array_elements(coalesce(old.entries, '[]'::jsonb)) e;
  end if;
  if v_new <= v_old then return new; end if;
  if auth.uid() is null or (public.is_super_admin() and new.emp_id is distinct from public.my_emp_id()) then return new; end if;   -- งานระบบ / Super Admin ทำแทนผู้อื่น (ใบงานของตัวเองถูกบังคับเหมือนทุกคน)
  if not public.att_required_for(new.emp_id, new.day) then return new; end if;
  if not exists (select 1 from public.attendance_logs a where a.emp_id = new.emp_id and a.kind = 'in'
                  and (a.at at time zone 'Asia/Bangkok')::date = new.day) then
    raise exception 'NO_CLOCK_IN:ยังไม่ได้ลงเวลาเข้างานของวันที่ % — ไม่สามารถบันทึกชั่วโมงงานได้ (ลงเวลาที่ระบบลงเวลา หรือผ่าน AI-Beacon ก่อน)', to_char(new.day, 'DD/MM/YYYY');
  end if;
  return new;
end $$;
drop trigger if exists trg_ts_att_guard on public.timesheets;
create trigger trg_ts_att_guard before insert or update on public.timesheets for each row execute function public.ts_att_guard();



-- ===== supabase_update_hub5.sql (v91) =====
-- v91: (1) จำนวนชั่วโมงที่บันทึกงานได้ = ชั่วโมงที่ได้จากการลงเวลาเข้างานจริง  (2) โหมดทดลอง: ลงเวลาย้อนหลังเพื่อทดสอบระบบ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub4.sql) — รันซ้ำได้
--
-- (1) กติกา: ชั่วโมงรวมที่บันทึกได้ในวันนั้น ≤ floor(ชั่วโมงที่ทำงาน)  โดยนับจากลงเวลาเข้างานครั้งแรกถึงลงเวลาออกงานครั้งสุดท้าย
--           วันนี้ที่ยังไม่ออกงาน นับถึงเวลาปัจจุบัน · วันย้อนหลังที่ลืมลงเวลาออก อนุญาตสูงสุด 8 ชม. · บันทึกขั้นต่ำ 1 ชม./รายการ (เดิม)
-- (2) โหมดทดลองลงเวลาย้อนหลัง: คีย์ app_settings 'att_backfill' = {"on": true, "days": 45}
--     ปิดโหมดทดลอง:  update public.app_settings set value = jsonb_set(value,'{on}','false') where key='att_backfill';
--     ล้างข้อมูลทดลองทั้งหมด:  delete from public.attendance_logs where source = 'test';

alter table public.attendance_logs drop constraint if exists attendance_logs_source_check;
alter table public.attendance_logs add constraint attendance_logs_source_check check (source in ('app', 'beacon', 'admin', 'test'));

insert into public.app_settings (key, value) values ('att_backfill', '{"on": true, "days": 45}'::jsonb) on conflict (key) do nothing;

-- ชั่วโมงที่ได้จากการลงเวลาของวันนั้น (null = ไม่มีการลงเวลาเข้างาน)
create or replace function public.att_hours_for(p_emp text, p_day date) returns integer
language plpgsql stable security definer set search_path = public as $$
declare t_in timestamptz; t_out timestamptz; v_h numeric;
begin
  select min(a.at) into t_in from public.attendance_logs a where a.emp_id = p_emp and a.kind = 'in' and (a.at at time zone 'Asia/Bangkok')::date = p_day;
  if t_in is null then return null; end if;
  select max(a.at) into t_out from public.attendance_logs a where a.emp_id = p_emp and a.kind = 'out' and a.at > t_in and (a.at at time zone 'Asia/Bangkok')::date = p_day;
  if t_out is not null then v_h := extract(epoch from (t_out - t_in)) / 3600;
  elsif p_day = (now() at time zone 'Asia/Bangkok')::date then v_h := extract(epoch from (now() - t_in)) / 3600;
  else return 8; end if;
  return least(8, floor(v_h))::int;
end $$;
revoke all on function public.att_hours_for(text, date) from public, anon;
grant execute on function public.att_hours_for(text, date) to authenticated, service_role;

-- ตัวป้องกันใบงาน: ต้องมีการลงเวลาเข้างาน และชั่วโมงรวมต้องไม่เกินชั่วโมงที่ได้จากการลงเวลา
create or replace function public.ts_att_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_new numeric := 0; v_old numeric := 0; v_allow integer;
begin
  select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_new from jsonb_array_elements(coalesce(new.entries, '[]'::jsonb)) e;
  if tg_op = 'UPDATE' then
    select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_old from jsonb_array_elements(coalesce(old.entries, '[]'::jsonb)) e;
  end if;
  if v_new <= v_old then return new; end if;
  if auth.uid() is null or (public.is_super_admin() and new.emp_id is distinct from public.my_emp_id()) then return new; end if;
  if not public.att_required_for(new.emp_id, new.day) then return new; end if;
  v_allow := public.att_hours_for(new.emp_id, new.day);
  if v_allow is null then
    raise exception 'NO_CLOCK_IN:ยังไม่ได้ลงเวลาเข้างานของวันที่ % — ไม่สามารถบันทึกชั่วโมงงานได้ (ลงเวลาที่ระบบลงเวลา หรือผ่าน AI-Beacon ก่อน)', to_char(new.day, 'DD/MM/YYYY');
  end if;
  if v_new > v_allow then
    raise exception 'HOURS_EXCEED:ชั่วโมงงานรวม % ชม. เกินชั่วโมงที่ได้จากการลงเวลา % ชม. ของวันที่ %', v_new, v_allow, to_char(new.day, 'DD/MM/YYYY');
  end if;
  return new;
end $$;

-- โหมดทดลอง: ลงเวลาย้อนหลัง (เฉพาะตัวเอง · วันทำงาน · ไม่ใช่วันในอนาคต · ภายใน days วัน) — บันทึกเป็น source = 'test'
create or replace function public.att_backfill(p_day date, p_in text, p_out text default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); s jsonb; v_today date := (now() at time zone 'Asia/Bangkok')::date; t_in timestamptz; t_out timestamptz; v_days int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  select value into s from public.app_settings where key = 'att_backfill';
  if s is null or coalesce((s->>'on')::boolean, false) is not true then raise exception 'DISABLED:โหมดทดลองลงเวลาย้อนหลังถูกปิดอยู่'; end if;
  v_days := coalesce((s->>'days')::int, 45);
  if p_day is null or p_day > v_today then raise exception 'BAD_DATE:เลือกได้เฉพาะวันนี้หรือย้อนหลัง'; end if;
  if p_day < v_today - v_days then raise exception 'BAD_DATE:ย้อนหลังได้ไม่เกิน % วัน', v_days; end if;
  if not public.is_work_day(v_emp, p_day) then raise exception 'NOT_WORK_DAY:วันที่เลือกไม่ใช่วันทำงานตามปฏิทิน'; end if;
  if exists (select 1 from public.attendance_logs a where a.emp_id = v_emp and a.kind = 'in' and (a.at at time zone 'Asia/Bangkok')::date = p_day) then
    raise exception 'DUPLICATE:วันนี้มีการลงเวลาเข้างานอยู่แล้ว (ลบรายการทดลองก่อนหากต้องการลงใหม่)';
  end if;
  t_in := (p_day::text || ' ' || p_in || ':00+07')::timestamptz;
  insert into public.attendance_logs (emp_id, kind, at, source, note) values (v_emp, 'in', t_in, 'test', left('[ทดลองย้อนหลัง] ' || coalesce(p_note, ''), 300));
  if p_out is not null and p_out <> '' then
    t_out := (p_day::text || ' ' || p_out || ':00+07')::timestamptz;
    if t_out <= t_in then raise exception 'BAD_TIME:เวลาออกงานต้องหลังเวลาเข้างาน'; end if;
    insert into public.attendance_logs (emp_id, kind, at, source, note) values (v_emp, 'out', t_out, 'test', '[ทดลองย้อนหลัง]');
  end if;
  return jsonb_build_object('ok', true, 'day', p_day, 'hours', public.att_hours_for(v_emp, p_day));
end $$;

-- ลบรายการลงเวลาทดลองของตัวเองในวันที่เลือก
create or replace function public.att_backfill_clear(p_day date) returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  delete from public.attendance_logs where emp_id = public.my_emp_id() and source = 'test' and (at at time zone 'Asia/Bangkok')::date = p_day;
  get diagnostics n = row_count; return n;
end $$;

revoke all on function public.att_backfill(date, text, text, text), public.att_backfill_clear(date) from public, anon;
grant execute on function public.att_backfill(date, text, text, text), public.att_backfill_clear(date) to authenticated;



-- ===== supabase_update_hub6.sql (v92) =====
-- v92: โหมดทดลองจับเวลาจริง — ลงเวลาได้ทุกวัน (รวมเสาร์-อาทิตย์/วันหยุด) และชั่วโมงที่บันทึกงานได้เดินตามเวลาจริง ครบชั่วโมงจึงบันทึกได้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub5.sql) — รันซ้ำได้
-- เปิด/ปิดโหมดทดลอง:  คีย์ app_settings 'att_test' = {"on": true}
--   ปิด:  update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_test';
--   ล้างข้อมูลลงเวลาทดลองทั้งหมด (เฉพาะที่ย้อนหลัง):  delete from public.attendance_logs where source = 'test';
-- ในโหมดทดลอง: is_work_day() ตอบว่าเป็นวันทำงานทุกวัน (ใช้กับระบบลงเวลา/ตรวจใบงานเท่านั้น ไม่กระทบปฏิทินและการลา)

insert into public.app_settings (key, value) values ('att_test', '{"on": true}'::jsonb) on conflict (key) do nothing;

create or replace function public.is_work_day(p_emp text, p_day date) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false)
      or ( not exists (select 1 from public.holidays h where h.day = p_day)
           and case extract(dow from p_day)::int
                 when 0 then false
                 when 6 then coalesce((select e.work_sat from public.employees e where e.id = p_emp), false)
                 else true end )
$$;

-- ชั่วโมงที่ได้จากการลงเวลา: รวมทุกช่วง (เข้า→ออก) ของวันนั้น · ช่วงที่ยังไม่ออกงาน: วันนี้นับถึงตอนนี้ (เดินตามเวลาจริง) · วันย้อนหลังที่ลืมออกงาน = 8 ชม.
create or replace function public.att_hours_for(p_emp text, p_day date) returns integer
language plpgsql stable security definer set search_path = public as $$
declare r record; v_open timestamptz; v_tot numeric := 0; v_any boolean := false; v_today boolean := (p_day = (now() at time zone 'Asia/Bangkok')::date);
begin
  for r in select kind, at from public.attendance_logs
            where emp_id = p_emp and kind in ('in', 'out') and (at at time zone 'Asia/Bangkok')::date = p_day order by at loop
    if r.kind = 'in' then
      v_any := true; if v_open is null then v_open := r.at; end if;
    elsif v_open is not null then
      v_tot := v_tot + extract(epoch from (r.at - v_open)); v_open := null;
    end if;
  end loop;
  if not v_any then return null; end if;
  if v_open is not null then
    if v_today then v_tot := v_tot + extract(epoch from (clock_timestamp() - v_open)); else return 8; end if;
  end if;
  return greatest(0, least(8, floor(v_tot / 3600)))::int;
end $$;



-- ===== supabase_update_hub7.sql (v93) =====
-- v93: Super Admin แก้ไข / ลบ / เพิ่ม / ใส่หมายเหตุ รายการลงเวลา (attendance_logs) — เขียนผ่านฟังก์ชันเท่านั้น และบันทึกผู้แก้ไข
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub6.sql) — รันซ้ำได้

alter table public.attendance_logs add column if not exists edited_by text;
alter table public.attendance_logs add column if not exists edited_at timestamptz;

-- แก้ไขประเภท/เวลา/หมายเหตุ ของรายการลงเวลา
create or replace function public.att_admin_update(p_id uuid, p_kind text, p_at timestamptz, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare r public.attendance_logs%rowtype;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_at is null then raise exception 'BAD_TIME:ระบุเวลา'; end if;
  update public.attendance_logs set kind = p_kind, at = p_at, note = left(coalesce(p_note, ''), 300),
         edited_by = public.my_emp_id(), edited_at = now()
   where id = p_id returning * into r;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  return to_jsonb(r);
end $$;

-- ลบรายการลงเวลา
create or replace function public.att_admin_delete(p_id uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  delete from public.attendance_logs where id = p_id;
  get diagnostics n = row_count;
  return n > 0;
end $$;

-- เพิ่มรายการลงเวลาให้พนักงาน (เช่น ลืมลงเวลา) — source = 'admin'
create or replace function public.att_admin_add(p_emp text, p_kind text, p_at timestamptz, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare r public.attendance_logs%rowtype;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  if not exists (select 1 from public.employees where id = p_emp) then raise exception 'NOT_FOUND:ไม่พบพนักงาน'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  insert into public.attendance_logs (emp_id, kind, at, source, note, edited_by, edited_at)
  values (p_emp, p_kind, p_at, 'admin', left(coalesce(p_note, ''), 300), public.my_emp_id(), now()) returning * into r;
  return to_jsonb(r);
end $$;

revoke all on function public.att_admin_update(uuid, text, timestamptz, text), public.att_admin_delete(uuid), public.att_admin_add(text, text, timestamptz, text) from public, anon;
grant execute on function public.att_admin_update(uuid, text, timestamptz, text), public.att_admin_delete(uuid), public.att_admin_add(text, text, timestamptz, text) to authenticated;



-- ===== supabase_update_hub8.sql (v94) =====
-- v94: บันทึกงานได้ 8 ชม./วัน (ตามเวลาในระบบ) เมื่อมีการลงเวลาเข้างานแล้ว · ขั้นต่ำ 1 ชม. ต่อรายการ (ไม่จำกัดตามชั่วโมงที่ผ่านไป)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub7.sql) — รันซ้ำได้
create or replace function public.att_hours_for(p_emp text, p_day date) returns integer
language plpgsql stable security definer set search_path = public as $$
begin
  if exists (select 1 from public.attendance_logs a where a.emp_id = p_emp and a.kind = 'in' and (a.at at time zone 'Asia/Bangkok')::date = p_day) then
    return 8;      -- มีการลงเวลาเข้างานแล้ว = บันทึกงานได้เต็ม 8 ชม./วัน
  end if;
  return null;     -- ยังไม่ลงเวลาเข้างาน = บันทึกไม่ได้
end $$;



-- v96: ชั่วโมงที่บันทึกงานได้ = ชั่วโมงเต็มที่ผ่านไปจริงนับจากลงเวลาเข้างาน (สูงสุด 8 ชม./วัน) · ขั้นต่ำ 1 ชม./รายการ (ยกเลิกกติกา 8 ชม. ทันทีของ hub8)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub8.sql) — รันซ้ำได้
-- รวมทุกช่วง (เข้า→ออก) ของวันนั้น · ช่วงที่ยังไม่ออก: วันนี้นับถึงตอนนี้ · วันย้อนหลังที่ลืมลงเวลาออก = 8 ชม.

create or replace function public.att_hours_for(p_emp text, p_day date) returns integer
language plpgsql stable security definer set search_path = public as $$
declare r record; v_open timestamptz; v_tot numeric := 0; v_any boolean := false; v_today boolean := (p_day = (now() at time zone 'Asia/Bangkok')::date);
begin
  for r in select kind, at from public.attendance_logs
            where emp_id = p_emp and kind in ('in', 'out') and (at at time zone 'Asia/Bangkok')::date = p_day order by at loop
    if r.kind = 'in' then
      v_any := true; if v_open is null then v_open := r.at; end if;
    elsif v_open is not null then
      v_tot := v_tot + extract(epoch from (r.at - v_open)); v_open := null;
    end if;
  end loop;
  if not v_any then return null; end if;
  if v_open is not null then
    if v_today then v_tot := v_tot + extract(epoch from (clock_timestamp() - v_open)); else return 8; end if;
  end if;
  return greatest(0, least(8, floor(v_tot / 3600)))::int;
end $$;
revoke all on function public.att_hours_for(text, date) from public, anon;
grant execute on function public.att_hours_for(text, date) to authenticated, service_role;


-- v98: Pre-approval (ส่งอนุมัติรายรายการก่อนครบ 8 ชม.) ใช้งานผ่าน LINE ได้ — แจ้งเตือน / กดอนุมัติ / รายการรออนุมัติ / สถานะ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_line_approval.sql และ hub9) — รันซ้ำได้ · ไม่ต้อง deploy Edge Function ใหม่
-- หลักการ: ใบงานที่ "เปิดให้อนุมัติ" = Pending หรือ Draft ที่มีรายการ ap.s = 'P' (ส่ง Pre-approval ไว้)
--          รายการที่รออนุมัติ = ap.s = 'P' หรือ (ไม่มี ap และใบเป็น Pending) — รายการใน Draft ที่ยังไม่ส่งจะไม่ถูกนับ
--          การอนุมัติผ่าน LINE ไม่เปลี่ยนสถานะใบที่ยังเป็น Draft (ใบเป็น Submitted ได้เมื่อพนักงานส่ง final และทุกรายการอนุมัติครบ)

create or replace function public.ap_sheet_open(p_status text, p_entries jsonb) returns boolean
language sql immutable as $$
  select p_status = 'Pending' or (p_status = 'Draft' and p_entries @> '[{"ap":{"s":"P"}}]'::jsonb)
$$;
create or replace function public.ap_ent_p(p_status text, p_e jsonb) returns boolean
language sql immutable as $$
  select coalesce(p_e->'ap'->>'s', '') = 'P' or (p_e->'ap' is null and p_status = 'Pending')
$$;

drop function if exists public.ap_queue(text);
create or replace function public.ap_queue(p_sheet text)
returns table (line_user_id text, role text, sub text, n int, hours numeric, labels text, owner_id text, owner_name text, day date, owner_dept text)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare t public.timesheets%rowtype;
begin
  perform pg_advisory_xact_lock(hashtext('ap_queue|' || p_sheet));
  select * into t from public.timesheets where id = p_sheet and public.ap_sheet_open(status, entries);
  if t.id is null then return; end if;

  return query
  with ent as (
    select a.x as e, a.i as idx, a.x->>'id' as eid, public.ap_next(t.emp_id, a.x) as nr, coalesce(a.x->'ap'->>'sub', '') as sb
      from jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where public.ap_ent_p(t.status, a.x)
  ),
  cand as (
    select distinct ent.e, ent.idx, ent.eid, ent.nr, ent.sb, s.emp_id as approver
      from ent join public.approver_scopes s
        on s.role = ent.nr and s.emp_id <> t.emp_id and public.ap_scope_ok(s, t.emp_id, ent.e->>'code')
     where ent.nr is not null
  ),
  fresh as (
    select c.*, em.line_user_id as lu
      from cand c join public.employees em
        on em.id = c.approver and em.active and em.approved and em.line_user_id is not null
     where (c.e->>'rb') is distinct from c.approver
       and not exists (select 1 from public.ap_notified nt
                        where nt.key = p_sheet || '|' || c.eid || '|' || c.nr || '|' || c.sb || '|' || c.approver)
  ),
  ins as (
    insert into public.ap_notified (key)
    select distinct p_sheet || '|' || f.eid || '|' || f.nr || '|' || f.sb || '|' || f.approver from fresh f
    on conflict do nothing
    returning key
  )
  select f.lu, f.nr, f.sb, count(*)::int,
         coalesce(sum((f.e->>'hours')::numeric), 0),
         string_agg(t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(f.idx::text, 2, '0') || ' · '
                    || coalesce(f.e->>'code', f.e->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(f.e->>'code'), ''), '')
                    || ' · ' || coalesce(f.e->>'hours', '0') || ' ชม.', E'\n' order by f.idx),
         t.emp_id, (select em.name from public.employees em where em.id = t.emp_id), t.day,
         (select trim(coalesce(em.dept, '') || ' ' || coalesce(d.name, '')) from public.employees em
            left join public.departments d on d.id = em.dept where em.id = t.emp_id)
    from fresh f
   group by f.lu, f.nr, f.sb;
end $$;

create or replace function public.line_approve(p_line_user text, p_sheet text, p_role text, p_sub text, p_dry boolean default false)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  me public.employees%rowtype; t public.timesheets%rowtype;
  x jsonb; ne jsonb; ap jsonb; arr jsonb := '[]'::jsonb;
  n int := 0; k int := 0; hrs numeric := 0; labels text := ''; all_a boolean; owner_name text; owner_dept text;
  now_ text := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;

  select * into t from public.timesheets where id = p_sheet for update;
  if t.id is null or not public.ap_sheet_open(t.status, t.entries) then
    return jsonb_build_object('ok', false, 'msg', 'ใบงานนี้ไม่ได้อยู่ในสถานะรออนุมัติแล้ว (อาจมีการอนุมัติ/ส่งกลับ/แก้ไขไปแล้ว)');
  end if;
  if t.emp_id = me.id then return jsonb_build_object('ok', false, 'msg', 'อนุมัติรายการของตัวเองไม่ได้'); end if;
  select em.name, trim(coalesce(em.dept, '') || ' ' || coalesce(d.name, '')) into owner_name, owner_dept
    from public.employees em left join public.departments d on d.id = em.dept where em.id = t.emp_id;

  for x in select value from jsonb_array_elements(t.entries) loop
    ne := x; k := k + 1;
    if public.ap_ent_p(t.status, x)
       and (coalesce(p_sub, '') = '' or coalesce(x->'ap'->>'sub', '') = p_sub)
       and public.ap_next(t.emp_id, x) = p_role
       and (x->>'rb') is distinct from me.id
       and exists (select 1 from public.approver_scopes s
                    where s.emp_id = me.id and s.role = p_role and public.ap_scope_ok(s, t.emp_id, x->>'code')) then
      n := n + 1; hrs := hrs + coalesce((x->>'hours')::numeric, 0);
      labels := labels || case when labels = '' then '' else E'\n' end
                || t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(k::text, 2, '0') || ' · '
                || coalesce(x->>'code', x->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(x->>'code'), ''), '')
                || ' · ' || coalesce(x->>'hours', '0') || ' ชม.';
      if not p_dry then
        ap := coalesce(x->'ap', '{}'::jsonb);
        ne := jsonb_set(x, '{ap}',
              jsonb_build_object('s', 'P',
                                 'done', coalesce(ap->'done', '[]'::jsonb) || to_jsonb(p_role),
                                 'hist', coalesce(ap->'hist', '[]'::jsonb) || jsonb_build_array(jsonb_build_object('role', p_role, 'by', me.name, 'at', now_)),
                                 'by', me.name, 'at', now_)
              || case when ap->'sub' is not null then jsonb_build_object('sub', ap->'sub') else '{}'::jsonb end, true);
        if public.ap_next(t.emp_id, ne) is null then ne := jsonb_set(ne, '{ap,s}', '"A"'::jsonb); end if;
      end if;
    end if;
    arr := arr || jsonb_build_array(ne);
  end loop;

  if n = 0 then
    return jsonb_build_object('ok', false, 'msg', 'ไม่มีรายการที่คุณอนุมัติได้ในใบนี้ (ไม่ใช่คิวของคุณ หรือมีคนอนุมัติ/พนักงานแก้ไขไปแล้ว)');
  end if;
  if p_dry then
    return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', owner_name, 'dept', owner_dept, 'day', t.day, 'finished', false);
  end if;

  select bool_and(coalesce(y->'ap'->>'s', 'P') = 'A') into all_a from jsonb_array_elements(arr) y;
  update public.timesheets
     set entries = arr,
         status = case when t.status = 'Draft' then 'Draft' when all_a then 'Submitted' else 'Pending' end,
         approved_by = me.name, approved_at = now(),
         reject_note = case when all_a and t.status <> 'Draft' then '' else reject_note end
   where id = t.id;
  return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', owner_name, 'dept', owner_dept, 'day', t.day, 'finished', (all_a and t.status <> 'Draft'));
end $$;

create or replace function public.ap_digest()
returns table (line_user_id text, approver_id text, approver_name text, n_new int, n_all int, hours numeric, sheets int, groups jsonb)
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
begin
  perform pg_advisory_xact_lock(hashtext('ap_digest'));
  return query
  with ent as (
    select t.id as sid, t.emp_id as oid, t.day as dd, a.x as e, a.i as idx, a.x->>'id' as eid,
           public.ap_next(t.emp_id, a.x) as nr, coalesce(a.x->'ap'->>'sub', '') as sb
      from public.timesheets t, jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where public.ap_sheet_open(t.status, t.entries) and public.ap_ent_p(t.status, a.x)
  ),
  cand as (
    select distinct ent.sid, ent.oid, ent.dd, ent.e, ent.idx, ent.eid, ent.nr, ent.sb, s.emp_id as approver
      from ent join public.approver_scopes s
        on s.role = ent.nr and s.emp_id <> ent.oid and public.ap_scope_ok(s, ent.oid, ent.e->>'code')
     where ent.nr is not null and (ent.e->>'rb') is distinct from s.emp_id
  ),
  due as (
    select c.*, em.line_user_id as lu, em.name as aname,
           exists (select 1 from public.ap_notified nt
                    where nt.key = c.sid || '|' || c.eid || '|' || c.nr || '|' || c.sb || '|' || c.approver) as seen
      from cand c join public.employees em
        on em.id = c.approver and em.active and em.approved and em.line_user_id is not null
  ),
  targets as (select d.approver from due d group by d.approver having bool_or(not d.seen)),
  ins as (
    insert into public.ap_notified (key)
    select distinct d.sid || '|' || d.eid || '|' || d.nr || '|' || d.sb || '|' || d.approver
      from due d where d.approver in (select approver from targets) and not d.seen
    on conflict do nothing
    returning key
  ),
  grp as (
    select d.approver, d.lu, d.aname, d.sid, d.oid, d.dd,
           (select em.name from public.employees em where em.id = d.oid) as oname,
           (select trim(coalesce(em.dept, '') || ' ' || coalesce(dp.name, '')) from public.employees em
              left join public.departments dp on dp.id = em.dept where em.id = d.oid) as odept,
           count(*) as n, count(*) filter (where not d.seen) as nn, sum((d.e->>'hours')::numeric) as h,
           jsonb_agg(jsonb_build_object(
             'tx', d.oid || '-' || to_char(d.dd, 'DDMMYY') || '-' || lpad(d.idx::text, 2, '0'),
             'code', coalesce(d.e->>'code', d.e->>'sgaId', '-'),
             'name', public.ap_code_name(d.e->>'code'),
             'h', d.e->>'hours', 'new', not d.seen) order by d.idx) as items
      from due d where d.approver in (select approver from targets)
     group by d.approver, d.lu, d.aname, d.sid, d.oid, d.dd
  )
  select g.lu, g.approver, g.aname, sum(g.nn)::int, sum(g.n)::int, sum(g.h), count(*)::int,
         jsonb_agg(jsonb_build_object('sheet', g.sid, 'owner_id', g.oid, 'owner', g.oname, 'dept', g.odept, 'day', g.dd, 'items', g.items)
                   order by g.dd, g.oid)
    from grp g
   where (select count(*) from ins) >= 0
   group by g.lu, g.approver, g.aname;
end $$;

create or replace function public.ap_apply_sheet(p_me_id text, p_me_name text, p_sheet text, p_dry boolean)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  t public.timesheets%rowtype; x jsonb; ne jsonb; ap jsonb; arr jsonb := '[]'::jsonb; labels jsonb := '[]'::jsonb;
  n int := 0; k int := 0; hrs numeric := 0; all_a boolean; nr text; oname text;
  now_ text := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if p_dry then
    select * into t from public.timesheets where id = p_sheet and public.ap_sheet_open(status, entries);
  else
    select * into t from public.timesheets where id = p_sheet and public.ap_sheet_open(status, entries) for update;
  end if;
  if t.id is null or t.emp_id = p_me_id then return jsonb_build_object('n', 0); end if;
  select name into oname from public.employees where id = t.emp_id;

  for x in select value from jsonb_array_elements(t.entries) loop
    ne := x; k := k + 1;
    if public.ap_ent_p(t.status, x) then
      nr := public.ap_next(t.emp_id, x);
      if nr is not null and (x->>'rb') is distinct from p_me_id
         and exists (select 1 from public.approver_scopes s
                      where s.emp_id = p_me_id and s.role = nr and public.ap_scope_ok(s, t.emp_id, x->>'code')) then
        n := n + 1; hrs := hrs + coalesce((x->>'hours')::numeric, 0);
        labels := labels || jsonb_build_array(
          t.emp_id || '-' || to_char(t.day, 'DDMMYY') || '-' || lpad(k::text, 2, '0') || ' · '
          || coalesce(x->>'code', x->>'sgaId', '-') || coalesce(' ' || nullif(public.ap_code_name(x->>'code'), ''), '')
          || ' · ' || coalesce(x->>'hours', '0') || ' ชม.');
        if not p_dry then
          ap := coalesce(x->'ap', '{}'::jsonb);
          ne := jsonb_set(x, '{ap}',
                jsonb_build_object('s', 'P',
                                   'done', coalesce(ap->'done', '[]'::jsonb) || to_jsonb(nr),
                                   'hist', coalesce(ap->'hist', '[]'::jsonb) || jsonb_build_array(jsonb_build_object('role', nr, 'by', p_me_name, 'at', now_)),
                                   'by', p_me_name, 'at', now_)
                || case when ap->'sub' is not null then jsonb_build_object('sub', ap->'sub') else '{}'::jsonb end, true);
          if public.ap_next(t.emp_id, ne) is null then ne := jsonb_set(ne, '{ap,s}', '"A"'::jsonb); end if;
        end if;
      end if;
    end if;
    arr := arr || jsonb_build_array(ne);
  end loop;

  if n = 0 or p_dry then
    return jsonb_build_object('n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', oname, 'finished', false);
  end if;
  select bool_and(coalesce(y->'ap'->>'s', 'P') = 'A') into all_a from jsonb_array_elements(arr) y;
  update public.timesheets
     set entries = arr, status = case when t.status = 'Draft' then 'Draft' when all_a then 'Submitted' else 'Pending' end,
         approved_by = p_me_name, approved_at = now(),
         reject_note = case when all_a and t.status <> 'Draft' then '' else reject_note end
   where id = t.id;
  return jsonb_build_object('n', n, 'hours', hrs, 'labels', labels, 'owner_id', t.emp_id, 'owner', oname, 'finished', (all_a and t.status <> 'Draft'));
end $$;

create or replace function public.line_approve_all(p_line_user text, p_expect int default null, p_dry boolean default false)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  me public.employees%rowtype; sid text; r jsonb;
  n int := 0; hrs numeric := 0; sheets int := 0; fin int := 0; labels jsonb := '[]'::jsonb; owners text[] := '{}';
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;

  for sid in select t.id from public.timesheets t where public.ap_sheet_open(t.status, t.entries) and t.emp_id <> me.id order by t.id loop
    r := public.ap_apply_sheet(me.id, me.name, sid, true);
    if (r->>'n')::int > 0 then
      n := n + (r->>'n')::int; hrs := hrs + (r->>'hours')::numeric; sheets := sheets + 1;
      owners := array_append(owners, r->>'owner_id');
      if jsonb_array_length(labels) < 30 then labels := labels || (r->'labels'); end if;
    end if;
  end loop;
  if n = 0 then return jsonb_build_object('ok', false, 'msg', 'ไม่มีรายการที่รออนุมัติของคุณแล้ว (อาจมีคนอนุมัติ/ส่งกลับ/แก้ไขไปแล้ว)'); end if;

  if p_dry then
    return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'sheets', sheets,
                              'people', (select count(distinct o) from unnest(owners) o), 'labels', labels);
  end if;
  if p_expect is not null and p_expect <> n then
    return jsonb_build_object('ok', false, 'n', n,
      'msg', 'จำนวนรายการรออนุมัติเปลี่ยนจาก ' || p_expect || ' เป็น ' || n || ' รายการ (มีรายการใหม่เข้ามา หรือมีผู้อื่นอนุมัติแล้ว) — ยังไม่ได้อนุมัติ กรุณากดปุ่ม "อนุมัติทั้งหมด" ในการ์ดอีกครั้งเพื่อดูจำนวนล่าสุด');
  end if;

  n := 0; hrs := 0; sheets := 0;
  for sid in select t.id from public.timesheets t where public.ap_sheet_open(t.status, t.entries) and t.emp_id <> me.id order by t.id loop
    r := public.ap_apply_sheet(me.id, me.name, sid, false);
    if (r->>'n')::int > 0 then
      n := n + (r->>'n')::int; hrs := hrs + (r->>'hours')::numeric; sheets := sheets + 1;
      if (r->>'finished')::boolean then fin := fin + 1; end if;
    end if;
  end loop;
  return jsonb_build_object('ok', true, 'n', n, 'hours', hrs, 'sheets', sheets, 'finished_sheets', fin);
end $$;

create or replace function public.ap_my_pending(p_line_user text) returns jsonb
language plpgsql security definer set search_path = public as $$
#variable_conflict use_column
declare me public.employees%rowtype; res jsonb;
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ — ผูกบัญชีในแอปก่อน'); end if;
  with ent as (
    select t.id as sid, t.emp_id as oid, t.day as dd, a.x as e, a.i as idx, public.ap_next(t.emp_id, a.x) as nr
      from public.timesheets t, jsonb_array_elements(t.entries) with ordinality as a(x, i)
     where public.ap_sheet_open(t.status, t.entries) and t.emp_id <> me.id and public.ap_ent_p(t.status, a.x)
  ),
  due as (
    select distinct ent.* from ent
     where ent.nr is not null and (ent.e->>'rb') is distinct from me.id
       and exists (select 1 from public.approver_scopes s
                    where s.emp_id = me.id and s.role = ent.nr and public.ap_scope_ok(s, ent.oid, ent.e->>'code'))
  ),
  grp as (
    select d.sid, d.oid, d.dd,
           (select em.name from public.employees em where em.id = d.oid) as oname,
           (select trim(coalesce(em.dept, '') || ' ' || coalesce(dp.name, '')) from public.employees em
              left join public.departments dp on dp.id = em.dept where em.id = d.oid) as odept,
           count(*) as n, sum((d.e->>'hours')::numeric) as h,
           jsonb_agg(jsonb_build_object(
             'tx', d.oid || '-' || to_char(d.dd, 'DDMMYY') || '-' || lpad(d.idx::text, 2, '0'),
             'code', coalesce(d.e->>'code', d.e->>'sgaId', '-'), 'name', public.ap_code_name(d.e->>'code'),
             'h', d.e->>'hours', 'new', false) order by d.idx) as items
      from due d group by d.sid, d.oid, d.dd
  )
  select jsonb_build_object('ok', true, 'n_all', coalesce(sum(g.n), 0)::int, 'n_new', coalesce(sum(g.n), 0)::int,
                            'hours', coalesce(sum(g.h), 0), 'sheets', count(*)::int,
                            'groups', coalesce(jsonb_agg(jsonb_build_object('sheet', g.sid, 'owner_id', g.oid, 'owner', g.oname,
                                       'dept', g.odept, 'day', g.dd, 'items', g.items) order by g.dd, g.oid), '[]'::jsonb))
    into res from grp g;
  return res;
end $$;

create or replace function public.ap_my_status(p_line_user text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; today date := (now() at time zone 'Asia/Bangkok')::date; res jsonb;
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ — ผูกบัญชีในแอปก่อน'); end if;
  select jsonb_build_object(
    'ok', true, 'name', me.name, 'dept', me.dept, 'today', today,
    'today_hours', coalesce((select sum((x->>'hours')::numeric) from public.timesheets t, jsonb_array_elements(t.entries) x
                              where t.emp_id = me.id and t.day = today), 0),
    'today_status', (select t.status from public.timesheets t where t.emp_id = me.id and t.day = today),
    'month_hours', coalesce((select sum((x->>'hours')::numeric) from public.timesheets t, jsonb_array_elements(t.entries) x
                              where t.emp_id = me.id and date_trunc('month', t.day) = date_trunc('month', today)), 0),
    'pending_entries', coalesce((select count(*) from public.timesheets t, jsonb_array_elements(t.entries) x
                                  where t.emp_id = me.id and public.ap_ent_p(t.status, x)), 0),
    'approved_entries', coalesce((select count(*) from public.timesheets t, jsonb_array_elements(t.entries) x
                                   where t.emp_id = me.id and t.day >= today - 30
                                     and (x->'ap'->>'s' = 'A' or (x->'ap' is null and t.status = 'Submitted'))), 0),
    'rejected_sheets', coalesce((select jsonb_agg(jsonb_build_object('day', t.day, 'note', t.reject_note) order by t.day desc)
                                  from public.timesheets t where t.emp_id = me.id and t.status = 'Draft' and coalesce(t.reject_note, '') <> ''), '[]'::jsonb),
    'draft_days', coalesce((select count(*) from public.timesheets t where t.emp_id = me.id and t.status = 'Draft'
                             and t.day >= today - 14 and jsonb_array_length(t.entries) > 0), 0))
    into res;
  return res;
end $$;

create or replace function public.notify_line_ts() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_url text; v_sec text; v_kind text;
begin
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is null or v_sec is null then return new; end if;
    if new.status = 'Pending' and (tg_op = 'INSERT' or old.status is distinct from 'Pending' or old.entries is distinct from new.entries) then
      v_kind := 'approval_queue';
    elsif new.status = 'Draft' and new.entries @> '[{"ap":{"s":"P"}}]'::jsonb and (tg_op = 'INSERT' or old.entries is distinct from new.entries) then
      v_kind := 'approval_queue';    -- Pre-approval: รายการที่ส่งอนุมัติล่วงหน้า (ใบยังเป็น Draft)
    elsif tg_op = 'UPDATE' and old.status = 'Pending' and new.status = 'Submitted' then
      v_kind := 'sheet_approved';
    elsif tg_op = 'UPDATE' and old.status = 'Pending' and new.status = 'Draft' and coalesce(new.reject_note, '') <> '' then
      v_kind := 'sheet_rejected';
    elsif tg_op = 'UPDATE' and old.status = 'Draft' and new.status = 'Draft' and coalesce(new.reject_note, '') <> '' and new.reject_note is distinct from old.reject_note then
      v_kind := 'sheet_rejected';    -- Pre-approval: ผู้อนุมัติส่งกลับรายการ
    end if;
    if v_kind is not null then
      perform net.http_post(
        url     := v_url,
        headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
        body    := jsonb_build_object('kind', v_kind, 'sheet_id', new.id, 'emp_id', new.emp_id));
    end if;
  exception when others then
    null;   -- ห้ามให้การแจ้งเตือนทำให้การบันทึก/อนุมัติล้มเหลว
  end;
  return new;
end $$;

drop trigger if exists line_notify_ts on public.timesheets;
create trigger line_notify_ts after insert or update on public.timesheets
  for each row execute function public.notify_line_ts();

grant execute on function public.ap_queue(text)                                     to service_role;
grant execute on function public.line_approve(text, text, text, text, boolean)      to service_role;
grant execute on function public.ap_digest()                                        to service_role;
grant execute on function public.line_approve_all(text, int, boolean)               to service_role;
grant execute on function public.ap_my_pending(text)                                to service_role;
grant execute on function public.ap_my_status(text)                                 to service_role;


-- v102: พักเที่ยงอัตโนมัติ — ทำงานครบ 4 ชม. หยุดจับเวลา 1 ชม. (Have Lunch) แล้วเดินต่อจนครบ 8 ชม. (เวลางานสุทธิ = เวลาเปิดงานสะสม ถ้า <4 ชม.; = 4 ชม. ช่วง 4-5 ชม.; = สะสม-1 ชม. เมื่อ ≥5 ชม.)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub10.sql) — รันซ้ำได้
-- รวมทุกช่วง (เข้า→ออก) ของวันนั้น · ช่วงที่ยังไม่ออก: วันนี้นับถึงตอนนี้ · วันย้อนหลังที่ลืมลงเวลาออก = 8 ชม.

create or replace function public.att_hours_for(p_emp text, p_day date) returns integer
language plpgsql stable security definer set search_path = public as $$
declare r record; v_open timestamptz; v_tot numeric := 0; v_any boolean := false; v_today boolean := (p_day = (now() at time zone 'Asia/Bangkok')::date);
begin
  for r in select kind, at from public.attendance_logs
            where emp_id = p_emp and kind in ('in', 'out') and (at at time zone 'Asia/Bangkok')::date = p_day order by at loop
    if r.kind = 'in' then
      v_any := true; if v_open is null then v_open := r.at; end if;
    elsif v_open is not null then
      v_tot := v_tot + extract(epoch from (r.at - v_open)); v_open := null;
    end if;
  end loop;
  if not v_any then return null; end if;
  if v_open is not null then
    if v_today then v_tot := v_tot + extract(epoch from (clock_timestamp() - v_open)); else return 8; end if;
  end if;
  if v_tot >= 18000 then v_tot := v_tot - 3600; elsif v_tot >= 14400 then v_tot := 14400; end if;   -- พักเที่ยง 1 ชม. หลังทำงานครบ 4 ชม.
  return greatest(0, least(8, floor(v_tot / 3600)))::int;
end $$;
revoke all on function public.att_hours_for(text, date) from public, anon;
grant execute on function public.att_hours_for(text, date) to authenticated, service_role;


-- v108: รายการลาของฉัน — ปุ่ม "แก้ไข" และ "ยกเลิก"
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub.sql / hub3) — รันซ้ำได้
-- กติกา: ผู้ลาแก้ไข/ยกเลิกได้เฉพาะรายการของตัวเอง สถานะรออนุมัติ หรืออนุมัติแล้ว และยังไม่พ้นวันลา (วันสิ้นสุดลา ≥ วันนี้)
--        แก้ไขรายการที่อนุมัติแล้ว → กลับเป็น "รออนุมัติ" (ต้องให้ผู้อนุมัติอนุมัติใหม่)

create or replace function public.leave_update(p_id uuid, p_type text, p_start date, p_end date, p_part text default 'full', p_reason text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; lt public.leave_types%rowtype; o public.leave_requests%rowtype; r public.leave_requests%rowtype;
        d date; v_days numeric := 0; v_used numeric; v_part text := coalesce(p_part, 'full'); v_today date := (now() at time zone 'Asia/Bangkok')::date;
begin
  select * into e from public.employees where id = public.my_emp_id();
  if e.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into o from public.leave_requests where id = p_id and emp_id = e.id for update;
  if o.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if o.status not in ('Pending', 'Approved') or o.end_date < v_today then
    raise exception 'NOT_ALLOWED:แก้ไขได้เฉพาะรายการที่รออนุมัติ หรืออนุมัติแล้วและยังไม่พ้นวันลา';
  end if;
  select * into lt from public.leave_types where id = p_type and active;
  if lt.id is null then raise exception 'BAD_TYPE:ไม่พบประเภทการลา'; end if;
  if p_start is null or p_end is null or p_end < p_start then raise exception 'BAD_DATE:ช่วงวันที่ไม่ถูกต้อง'; end if;
  if p_end < v_today then raise exception 'BAD_DATE:ไม่สามารถแก้ไขเป็นวันที่ผ่านมาแล้ว'; end if;
  if v_part <> 'full' and p_start <> p_end then raise exception 'BAD_DATE:ลาครึ่งวันเลือกได้เฉพาะลาวันเดียว'; end if;
  for d in select generate_series(p_start::timestamp, p_end::timestamp, interval '1 day')::date loop
    if extract(dow from d) = 0 then continue; end if;
    if extract(dow from d) = 6 and not e.work_sat then continue; end if;
    if exists (select 1 from public.holidays h where h.day = d) then continue; end if;
    v_days := v_days + 1;
  end loop;
  if v_days = 0 then raise exception 'NO_WORKDAY:ช่วงที่เลือกไม่มีวันทำการ (เสาร์-อาทิตย์/วันหยุด)'; end if;
  if v_part <> 'full' then v_days := 0.5; end if;
  if exists (select 1 from public.leave_requests x where x.emp_id = e.id and x.id <> p_id and x.status in ('Pending', 'Approved')
               and x.start_date <= p_end and x.end_date >= p_start
               and not (x.part <> 'full' and v_part <> 'full' and x.part <> v_part)) then
    raise exception 'OVERLAP:มีรายการลาที่ซ้อนกับช่วงวันนี้อยู่แล้ว';
  end if;
  if lt.quota_days is not null then
    select coalesce(sum(days), 0) into v_used from public.leave_requests x
     where x.emp_id = e.id and x.id <> p_id and x.type_id = lt.id and x.status in ('Pending', 'Approved') and extract(year from x.start_date) = extract(year from p_start);
    if v_used + v_days > lt.quota_days then raise exception 'QUOTA:วันลา% เกินสิทธิ์ (ใช้/รออนุมัติ % จาก % วัน)', lt.name, v_used, lt.quota_days; end if;
  end if;
  update public.leave_requests
     set type_id = lt.id, start_date = p_start, end_date = p_end, part = v_part, days = v_days, reason = left(coalesce(p_reason, ''), 500),
         status = 'Pending', decided_by = null, decided_at = null,
         decide_note = case when o.status = 'Approved' then 'แก้ไขโดยผู้ลา — รออนุมัติใหม่' else '' end
   where id = p_id returning * into r;
  return to_jsonb(r);
end $$;

-- ยกเลิก: รออนุมัติ หรืออนุมัติแล้วที่ยังไม่พ้นวันลา (รวมวันลาที่เป็นวันนี้)
create or replace function public.leave_cancel(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); r public.leave_requests%rowtype;
begin
  select * into r from public.leave_requests where id = p_id and emp_id = v_emp for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status = 'Pending' or (r.status = 'Approved' and r.end_date >= (now() at time zone 'Asia/Bangkok')::date) then
    update public.leave_requests set status = 'Cancelled', decided_at = now(), decide_note = 'ยกเลิกโดยผู้ลา' where id = p_id returning * into r;
    return to_jsonb(r);
  end if;
  raise exception 'NOT_ALLOWED:ยกเลิกได้เฉพาะรายการที่รออนุมัติ หรือที่อนุมัติแล้วและยังไม่พ้นวันลา';
end $$;

revoke all on function public.leave_update(uuid, text, date, date, text, text) from public, anon;
grant execute on function public.leave_update(uuid, text, date, date, text, text) to authenticated;


-- v110: กำหนดผู้ใช้งานจุดสำนักงาน (work_sites) — ทุกคน / รายฝ่าย / รายคน
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub.sql / hub2) — รันซ้ำได้
-- กติกา: จุดที่ "ไม่มีการกำหนด" = ทุกคนใช้ได้ (เหมือนเดิม) · เมื่อกำหนดแล้ว เฉพาะพนักงานที่ตรงกับขอบเขต (ทุกคน / ฝ่าย / รายคน) จะถูกตรวจพื้นที่ลงเวลากับจุดนี้

create table if not exists public.work_site_assign (
  id         text primary key,                                   -- site_id|scope_type|scope_key
  site_id    text not null references public.work_sites(id) on delete cascade,
  scope_type text not null check (scope_type in ('all', 'dept', 'emp')),
  scope_key  text not null default '*'
);
alter table public.work_site_assign enable row level security;
revoke all on public.work_site_assign from anon;
drop policy if exists wsa_super on public.work_site_assign;
create policy wsa_super on public.work_site_assign for all to authenticated
  using (public.is_super_admin()) with check (public.is_super_admin());

create or replace function public.site_applies(p_emp text, p_site text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.work_site_assign a where a.site_id = p_site)
      or exists (select 1 from public.work_site_assign a join public.employees e on e.id = p_emp
                  where a.site_id = p_site
                    and (a.scope_type = 'all' or (a.scope_type = 'emp' and a.scope_key = e.id) or (a.scope_type = 'dept' and a.scope_key = e.dept)))
$$;

-- จุดที่ใช้ได้กับฉัน (ใช้ในหน้าลงเวลา)
create or replace function public.my_work_sites() returns setof public.work_sites
language sql stable security definer set search_path = public as $$
  select w.* from public.work_sites w where w.active and public.site_applies(public.my_emp_id(), w.id)
$$;
revoke all on function public.site_applies(text, text), public.my_work_sites() from public, anon;
grant execute on function public.site_applies(text, text), public.my_work_sites() to authenticated, service_role;

-- ลงเวลา: เทียบ GPS เฉพาะจุดที่กำหนดให้พนักงานคนนั้น
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in'            and v_last is not null and v_last <> 'out'                      then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานไปแล้ว'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;


-- v113: ครบ 8 ชม. แล้วยังไม่ลงเวลาออกงาน → ห้ามส่งรายการ final จนกว่าจะลงเวลาออก + ใส่เหตุผล · แจ้งเตือน LINE เมื่อเกิน 8 ชม. 30 นาที
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub13.sql) — รันซ้ำได้
-- เวลาทำงานสุทธิ (net) = เวลาเปิดงานสะสม หักพักเที่ยง (ครบ 4 ชม. หยุด 1 ชม.) · 100% = 8 ชม. สุทธิ · แจ้งเตือน LINE เมื่อสุทธิ ≥ 8 ชม. 30 นาที (ส่งครั้งเดียวต่อวัน)
-- ต้อง deploy Edge Function line-notify.ts (function "hyper-api") ใหม่ จึงจะส่ง LINE ได้ · pg_cron เรียกทุก 10 นาที

create or replace function public.att_net_state(p_emp text, p_day date) returns table (any_in boolean, is_open boolean, net_secs numeric)
language plpgsql stable security definer set search_path = public as $$
declare r record; v_open timestamptz; v_tot numeric := 0; v_any boolean := false; v_today boolean := (p_day = (now() at time zone 'Asia/Bangkok')::date);
begin
  for r in select kind, at from public.attendance_logs
            where emp_id = p_emp and kind in ('in', 'out') and (at at time zone 'Asia/Bangkok')::date = p_day order by at loop
    if r.kind = 'in' then
      v_any := true; if v_open is null then v_open := r.at; end if;
    elsif v_open is not null then
      v_tot := v_tot + extract(epoch from (r.at - v_open)); v_open := null;
    end if;
  end loop;
  if v_open is not null and v_today then v_tot := v_tot + extract(epoch from (clock_timestamp() - v_open)); end if;
  if v_tot >= 18000 then v_tot := v_tot - 3600; elsif v_tot >= 14400 then v_tot := 14400; end if;   -- พักเที่ยง 1 ชม. หลังครบ 4 ชม.
  return query select v_any, v_open is not null, v_tot;
end $$;
revoke all on function public.att_net_state(text, date) from public, anon;
grant execute on function public.att_net_state(text, date) to authenticated, service_role;

-- ห้ามส่งใบงานเป็น final (Draft → Pending) ของวันนี้ ถ้าทำงานครบ 8 ชม. แล้วแต่ยังไม่ลงเวลาออกงาน
create or replace function public.ts_final_out_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare s record;
begin
  if new.status <> 'Pending' or (tg_op = 'UPDATE' and old.status = 'Pending') then return new; end if;
  if auth.uid() is null or (public.is_super_admin() and new.emp_id is distinct from public.my_emp_id()) then return new; end if;
  if new.day <> (now() at time zone 'Asia/Bangkok')::date then return new; end if;
  if not public.att_required_for(new.emp_id, new.day) then return new; end if;
  select * into s from public.att_net_state(new.emp_id, new.day);
  if s.any_in and s.is_open and s.net_secs >= 28800 then
    raise exception 'CLOCK_OUT_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้วแต่ยังไม่ได้ลงเวลาออกงาน — กรุณาลงเวลาออกงานพร้อมระบุเหตุผล แล้วจึงส่งรายการบันทึกงาน';
  end if;
  return new;
end $$;
drop trigger if exists trg_ts_final_out_guard on public.timesheets;
create trigger trg_ts_final_out_guard before insert or update on public.timesheets for each row execute function public.ts_final_out_guard();

-- พนักงานที่ทำงานสุทธิ ≥ 8 ชม. 30 นาที แต่ยังไม่ลงเวลาออก (แจ้งครั้งเดียวต่อวัน) — ใช้โดย Edge Function (service_role)
create table if not exists public.att_out_notified (
  emp_id text not null, day date not null, at timestamptz not null default now(), primary key (emp_id, day)
);
alter table public.att_out_notified enable row level security;
revoke all on public.att_out_notified from anon, authenticated;

create or replace function public.att_overdue_out() returns table (emp_id text, name text, line_user_id text, in_at timestamptz, net_secs numeric)
language plpgsql security definer set search_path = public as $$
declare e record; s record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_in timestamptz;
begin
  perform pg_advisory_xact_lock(hashtext('att_overdue_out'));
  for e in select m.id, m.name, m.line_user_id from public.employees m
            where m.active and m.approved and m.line_user_id is not null
              and exists (select 1 from public.attendance_logs a where a.emp_id = m.id and a.kind = 'in' and (a.at at time zone 'Asia/Bangkok')::date = v_day)
              and not exists (select 1 from public.att_out_notified n where n.emp_id = m.id and n.day = v_day) loop
    select * into s from public.att_net_state(e.id, v_day);
    if s.is_open and s.net_secs >= 30600 then
      select min(a.at) into v_in from public.attendance_logs a where a.emp_id = e.id and a.kind = 'in' and (a.at at time zone 'Asia/Bangkok')::date = v_day;
      insert into public.att_out_notified (emp_id, day) values (e.id, v_day) on conflict do nothing;
      emp_id := e.id; name := e.name; line_user_id := e.line_user_id; in_at := v_in; net_secs := s.net_secs;
      return next;
    end if;
  end loop;
end $$;
revoke all on function public.att_overdue_out() from public, anon, authenticated;
grant execute on function public.att_overdue_out() to service_role;

-- ตั้งเวลาเรียกทุก 10 นาที (ต้องเปิด pg_cron และตั้ง private_config line_notify_url / line_notify_secret ไว้แล้ว เหมือนการแจ้งเตือนใบงาน)
do $do$
begin
  begin perform cron.unschedule('att-out-overdue'); exception when others then null; end;
  perform cron.schedule('att-out-overdue', '*/10 * * * *', $cron$
    select net.http_post(
      url     := (select value from public.private_config where key = 'line_notify_url'),
      headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', (select value from public.private_config where key = 'line_notify_secret')),
      body    := jsonb_build_object('kind', 'clockout_overdue'));
  $cron$);
exception when others then
  raise notice 'ตั้ง pg_cron ไม่สำเร็จ (%): เปิด Database > Extensions > pg_cron แล้วรันไฟล์นี้ซ้ำ', sqlerrm;
end $do$;

-- ลงเวลา: ออกงานหลังครบ 8 ชม. ต้องระบุเหตุผลในหมายเหตุ
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in'            and v_last is not null and v_last <> 'out'                      then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานไปแล้ว'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;


-- v114: ผู้ที่เพิ่มเพื่อนใหม่ยังไม่เห็น Rich menu จนกว่าจะผูกบัญชี LINE สำเร็จ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ต้องมี private_config line_notify_url / line_notify_secret และ pg_net เหมือนการแจ้งเตือนอื่น) — รันซ้ำได้
-- หลักการ: เลิกใช้ Rich menu "เริ่มต้นของทุกคน" → ใส่เมนูให้รายคนเมื่อผูกบัญชีสำเร็จ / เอาออกเมื่อยกเลิกการผูก (Edge Function line-notify kind = richmenu_sync)
-- ต้อง deploy line-notify.ts (function "hyper-api") ใหม่ แล้วสั่งสลับเมนูหนึ่งครั้งเพื่อ "ยกเลิกเมนูเริ่มต้น + ใส่เมนูให้คนที่ผูกอยู่แล้ว":
--   select net.http_post(url := (select value from public.private_config where key='line_notify_url'),
--          headers := jsonb_build_object('Content-Type','application/json','x-webhook-secret',(select value from public.private_config where key='line_notify_secret')),
--          body := jsonb_build_object('kind','richmenu','mode','day'));   -- ตอนกลางคืนใช้ 'night'

create or replace function public.notify_line_menu() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_url text; v_sec text;
begin
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is null or v_sec is null then return new; end if;
    if old.line_user_id is not null and old.line_user_id is distinct from new.line_user_id then
      perform net.http_post(url := v_url, headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
                            body := jsonb_build_object('kind', 'richmenu_sync', 'line_user', old.line_user_id));   -- ยกเลิกการผูก/สลับเจ้าของ: ตรวจซ้ำที่ปลายทาง
    end if;
    if new.line_user_id is not null and new.line_user_id is distinct from old.line_user_id then
      perform net.http_post(url := v_url, headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
                            body := jsonb_build_object('kind', 'richmenu_sync', 'line_user', new.line_user_id));   -- ผูกสำเร็จ: ใส่ Rich menu
    end if;
  exception when others then
    null;   -- ห้ามให้การแจ้ง LINE ทำให้การผูกบัญชีล้มเหลว
  end;
  return new;
end $$;

drop trigger if exists employees_line_menu on public.employees;
create trigger employees_line_menu after update of line_user_id on public.employees
  for each row execute function public.notify_line_menu();

-- v115: ผู้สมัครใหม่ผูกบัญชี LINE ไม่ได้จนกว่า Admin จะอนุมัติ (approved = true)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_line.sql) — รันซ้ำได้
-- และต้อง deploy line-webhook.ts (function "clever-task") ใหม่ เพื่อให้ข้อความต้อนรับ/ตอบกลับไม่แนบลิงก์ผูกบัญชี

create or replace function public.request_line_link() returns text
language plpgsql security definer set search_path = public as $$
declare v_emp text; v_code text;
begin
  select id into v_emp from public.employees where user_id = auth.uid() and active and approved;
  if v_emp is null then raise exception 'NOT_APPROVED:บัญชียังไม่ได้รับอนุมัติจาก Admin — ผูก LINE ได้หลังได้รับอนุมัติ'; end if;
  loop
    v_code := lpad((floor(random() * 1000000))::int::text, 6, '0');
    exit when not exists (select 1 from public.line_link_codes where code = v_code and exp > now());
  end loop;
  insert into public.line_link_codes (emp_id, code, exp) values (v_emp, v_code, now() + interval '10 minutes')
  on conflict (emp_id) do update set code = excluded.code, exp = excluded.exp;
  return v_code;
end $$;

create or replace function public.link_line_by_code(p_code text, p_line_user text) returns text
language plpgsql security definer set search_path = public as $$
declare v_emp text; v_name text; v_ok boolean;
begin
  select emp_id into v_emp from public.line_link_codes where code = p_code and exp > now();
  if v_emp is null then return null; end if;
  select approved and active into v_ok from public.employees where id = v_emp;
  if v_ok is not true then
    delete from public.line_link_codes where emp_id = v_emp;
    return '!NOT_APPROVED';   -- ยังไม่ได้รับอนุมัติ: ไม่ผูกบัญชี
  end if;
  update public.employees set line_user_id = null where line_user_id = p_line_user and id <> v_emp;   -- 1 LINE ต่อ 1 พนักงาน
  update public.employees set line_user_id = p_line_user where id = v_emp returning name into v_name;
  delete from public.line_link_codes where emp_id = v_emp;
  return v_name;
end $$;

revoke all on function public.request_line_link() from public, anon;
revoke all on function public.link_line_by_code(text, text) from public, anon, authenticated;
grant execute on function public.request_line_link() to authenticated;
grant execute on function public.link_line_by_code(text, text) to service_role;

-- v117: ผู้สมัครใหม่เปิดลิงก์ LIFF ใน LINE → ระบบจำ LINE ไว้ (line_pending_id) → Admin อนุมัติ → ผูก LINE ให้อัตโนมัติ + Rich menu + แจ้งผลทาง LINE
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub15.sql และ hub16) — รันซ้ำได้
-- ต้อง deploy Edge Function ใหม่ 3 ตัว: bright-handler (line-login.ts), clever-task (line-webhook.ts), hyper-api (line-notify.ts)

alter table public.employees add column if not exists line_pending_id text;

-- ก่อนบันทึกการอนุมัติ (approved: false → true): ถ้ามี LINE ที่จำไว้และยังไม่ได้ผูก → ผูกให้ทันที (1 LINE ต่อ 1 พนักงาน)
-- trigger line_notify (แจ้ง "อนุมัติแล้ว") และ employees_line_menu (ใส่ Rich menu) ทำงานต่อโดยอัตโนมัติ
create or replace function public.employees_autolink_line() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.approved is true and old.approved is not true and new.line_pending_id is not null and new.line_user_id is null then
    update public.employees set line_user_id = null where line_user_id = new.line_pending_id and id <> new.id;
    new.line_user_id := new.line_pending_id;
    new.line_pending_id := null;
  end if;
  return new;
end $$;

drop trigger if exists employees_autolink_line on public.employees;
create trigger employees_autolink_line before update on public.employees
  for each row execute function public.employees_autolink_line();

-- v119: ลงเวลาเข้างานได้ "วันละครั้งเดียว" — ออกงานแล้วลงเข้างานซ้ำไม่ได้ (ลืมลงเวลา/แก้ไข ให้ Super Admin ใช้เมนูแก้ไขบันทึกลงเวลา)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub14.sql) — รันซ้ำได้
-- (ลงเวลาด้วย AI-Beacon นับเฉพาะครั้งแรกของวันอยู่แล้ว)

create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;


-- v121: สมัครสมาชิกใหม่ต้อง "รหัสพนักงาน + อีเมลบริษัท" ตรงกับข้อมูลพนักงานในฐานข้อมูล (นำเข้าจาก Empeo/ไฟล์สมาชิกไว้ก่อน)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_no_preapprove.sql) — รันซ้ำได้
-- กติกา: ต้องมีแถวพนักงานที่ id = รหัสที่กรอก และ lower(email) = อีเมลที่กรอก · ยังไม่เคยมีผู้สมัคร (user_id ว่าง) · พนักงานยัง active
--        ไม่ตรง = สมัครไม่ได้ (ไม่สร้างแถวพนักงานใหม่อัตโนมัติอีกต่อไป) · สมัครแล้วยังต้องรอ Admin อนุมัติเหมือนเดิม

-- ตรวจก่อนสมัคร (เรียกจากหน้าสมัคร ก่อนสร้างบัญชี) — ตอบเฉพาะ OK / MISMATCH / TAKEN ไม่เปิดเผยข้อมูลอื่น
create or replace function public.check_signup(p_emp text, p_email text) returns text
language plpgsql stable security definer set search_path = public as $$
declare e public.employees%rowtype;
begin
  select * into e from public.employees
   where lower(trim(id)) = lower(trim(coalesce(p_emp, ''))) and lower(trim(coalesce(email, ''))) = lower(trim(coalesce(p_email, ''))) and active
   limit 1;
  if e.id is null then return 'MISMATCH'; end if;
  if e.user_id is not null then return 'TAKEN'; end if;
  return 'OK';
end $$;
revoke all on function public.check_signup(text, text) from public;
grant execute on function public.check_signup(text, text) to anon, authenticated;

-- ตัวสร้างบัญชีผู้สมัคร: ผูกกับแถวพนักงานที่รหัสและอีเมลตรงกันเท่านั้น (บังคับรออนุมัติเสมอ) · ไม่ตรง → ปฏิเสธการสมัคร
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_emp text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
begin
  update public.employees set user_id = new.id, approved = false
   where lower(trim(id)) = lower(coalesce(v_emp, '')) and lower(trim(coalesce(email, ''))) = lower(trim(new.email))
     and user_id is null and active;
  if found then return new; end if;
  raise exception 'SIGNUP_MISMATCH: รหัสพนักงานและอีเมลไม่ตรงกับข้อมูลในระบบ';
end $$;

-- v122: ผู้อนุมัติลางาน/ลงเวลา (hub_approvers) มองไม่เห็นข้อมูลพนักงานในขอบเขตของตน → การ์ด "รออนุมัติการลา" ไม่ขึ้น / อนุมัติไม่ได้
-- สาเหตุ: ตาราง employees อนุญาตให้อ่านเฉพาะของตัวเอง / Admin / ผู้อนุมัติ Workload / ผู้บันทึกแทน — ไม่มีสิทธิ์สำหรับผู้อนุมัติของระบบลางาน-ลงเวลา
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub3.sql) — รันซ้ำได้
-- ผลลัพธ์: ผู้อนุมัติอ่านข้อมูลพนักงานที่อยู่ในขอบเขต (ทั้งหมด / รายฝ่าย / รายคน) ที่ตั้งไว้ในเมนู "ผู้อนุมัติ" ได้ — อ่านอย่างเดียว

drop policy if exists emp_hub_read on public.employees;
create policy emp_hub_read on public.employees for select to authenticated
  using (public.hub_can('leave', id) or public.hub_can('att', id));

-- v122: ลงเวลาเข้า/ออกงานได้เฉพาะในจุดที่กำหนดให้พนักงาน (work_sites + กำหนดผู้ใช้) · ต้องมี GPS · นอกพื้นที่ = ปฏิเสธ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub18.sql และ hub13) — รันซ้ำได้
-- ปิดการบังคับชั่วคราว:  insert into public.app_settings (key, value) values ('att_site_required', '{"on": false}'::jsonb) on conflict (key) do update set value = excluded.value;
-- (ออกไปทำงานนอกสถานที่ / กลับ ไม่ถูกบังคับพื้นที่ · AI-Beacon ผูกกับจุดของ Beacon อยู่แล้ว)

create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  -- ลงเวลาเข้า/ออกงานได้เฉพาะ "ในจุดที่กำหนดให้พนักงานคนนี้" (ตั้งผู้ใช้จุดที่เมนูลงเวลา > จุดสำนักงาน) · ต้องมี GPS
  -- เปิด/ปิด: app_settings 'att_site_required' = {"on": true/false} (ค่าเริ่มต้น เปิด) · โหมดทดลอง att_test เปิดอยู่ = ข้ามการตรวจพื้นที่ · ไม่มีจุดที่ใช้ได้เลย = ไม่บังคับ
  if p_kind in ('in', 'out')
     and coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_site_required'), true)
     and not coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false)
     and exists (select 1 from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) then
    if p_lat is null or p_lng is null then
      raise exception 'NO_GPS:ต้องเปิด GPS และอนุญาตให้ใช้ตำแหน่ง จึงจะลงเวลาได้';
    end if;
    if v_sid is null or v_d > v_rad + least(coalesce(p_acc, 0), 50) then
      raise exception 'OUT_OF_SITE:อยู่นอกจุดลงเวลาที่กำหนด — ใกล้สุด % ห่าง % ม. (รัศมี % ม.) กรุณาไปลงเวลาในพื้นที่', coalesce(v_sname, '-'), round(coalesce(v_d, 0)), coalesce(v_rad, 0);
    end if;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;


-- v123: ลงเวลาต้องถ่ายรูป selfie — ลายน้ำ วัน-เวลา และพิกัด lat/long ใส่อัตโนมัติ · ไม่มีรูป = ลงเวลาไม่ได้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub21.sql และ hub20) — รันซ้ำได้
-- ปิดการบังคับชั่วคราว:  insert into public.app_settings (key, value) values ('att_photo_required', '{"on": false}'::jsonb) on conflict (key) do update set value = excluded.value;
-- รูปเก็บใน bucket private "timesheet-files" เส้นทาง <รหัสพนักงาน>/att/<วันที่>/<ชนิด>-<เวลา>.jpg · เจ้าของ/ผู้ดูแล/ผู้อนุมัติ (ลงเวลา) ดูได้ · พนักงานลบรูปเองไม่ได้ (เฉพาะ Super Admin)

alter table public.attendance_logs add column if not exists photo_path text;

drop policy if exists tsf_read on storage.objects;
create policy tsf_read on storage.objects for select to authenticated
  using (bucket_id = 'timesheet-files'
         and (public.is_admin() or public.is_approver()
              or (storage.foldername(name))[1] = public.my_emp_id()
              or public.can_enter_for((storage.foldername(name))[1])
              or ((storage.foldername(name))[2] = 'att' and public.hub_can('att', (storage.foldername(name))[1]))));

drop policy if exists tsf_delete on storage.objects;
create policy tsf_delete on storage.objects for delete to authenticated
  using (bucket_id = 'timesheet-files'
         and (public.is_super_admin()
              or (coalesce((storage.foldername(name))[2], '') <> 'att'
                  and ((storage.foldername(name))[1] = public.my_emp_id() or public.can_enter_for((storage.foldername(name))[1])))));

-- เปลี่ยนฟังก์ชันลงเวลาเป็นรุ่นที่รับรูป (ลบรุ่นเดิม ไม่ให้ซ้ำซ้อน)
drop function if exists public.att_punch(text, double precision, double precision, real, text);

create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '', p_photo text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  -- ต้องแนบรูป selfie (อัปโหลดไว้ใน bucket timesheet-files โฟลเดอร์ <รหัสพนักงาน>/att/...) ทุกครั้งที่ลงเวลา — ไม่มีรูป = ไม่ให้ลงเวลา
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_photo_required'), true) then
    if p_photo is null or coalesce((storage.foldername(p_photo))[1], '') <> v_emp or coalesce((storage.foldername(p_photo))[2], '') <> 'att'
       or not exists (select 1 from storage.objects o where o.bucket_id = 'timesheet-files' and o.name = p_photo) then
      raise exception 'NO_PHOTO:ต้องถ่ายรูป selfie ก่อนลงเวลา (ไม่มีรูปแนบ ลงเวลาไม่ได้)';
    end if;
  end if;
  -- ลงเวลาเข้า/ออกงานได้เฉพาะ "ในจุดที่กำหนดให้พนักงานคนนี้" (ตั้งผู้ใช้จุดที่เมนูลงเวลา > จุดสำนักงาน) · ต้องมี GPS
  -- เปิด/ปิด: app_settings 'att_site_required' = {"on": true/false} (ค่าเริ่มต้น เปิด) · โหมดทดลอง att_test เปิดอยู่ = ข้ามการตรวจพื้นที่ · ไม่มีจุดที่ใช้ได้เลย = ไม่บังคับ
  if p_kind in ('in', 'out')
     and coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_site_required'), true)
     and not coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false)
     and exists (select 1 from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) then
    if p_lat is null or p_lng is null then
      raise exception 'NO_GPS:ต้องเปิด GPS และอนุญาตให้ใช้ตำแหน่ง จึงจะลงเวลาได้';
    end if;
    if v_sid is null or v_d > v_rad + least(coalesce(p_acc, 0), 50) then
      raise exception 'OUT_OF_SITE:อยู่นอกจุดลงเวลาที่กำหนด — ใกล้สุด % ห่าง % ม. (รัศมี % ม.) กรุณาไปลงเวลาในพื้นที่', coalesce(v_sname, '-'), round(coalesce(v_d, 0)), coalesce(v_rad, 0);
    end if;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note, photo_path)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300), p_photo)
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text, text) to authenticated;


-- v124: ไม่ใช่จุดลงเวลาที่ตั้งไว้ = ไม่ให้บันทึกลงเวลา (ทุกประเภท: เข้า/ออก/ออกนอกสถานที่/กลับ) · พนักงานที่ไม่มีจุดที่กำหนดให้เลย ลงเวลาไม่ได้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub22.sql) — รันซ้ำได้
-- เดิม (v122): บังคับเฉพาะเข้า/ออกงาน และคนที่ไม่มีจุดที่ใช้ได้เลยจะไม่ถูกบังคับ → ตอนนี้ปิดช่องทั้งสองแล้ว
-- ปิดการบังคับชั่วคราว (หรือโหมดทดลอง att_test เปิดอยู่ = ข้ามการตรวจ):
--   insert into public.app_settings (key, value) values ('att_site_required', '{"on": false}'::jsonb) on conflict (key) do update set value = excluded.value;

create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '', p_photo text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  -- ต้องแนบรูป selfie (อัปโหลดไว้ใน bucket timesheet-files โฟลเดอร์ <รหัสพนักงาน>/att/...) ทุกครั้งที่ลงเวลา — ไม่มีรูป = ไม่ให้ลงเวลา
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_photo_required'), true) then
    if p_photo is null or coalesce((storage.foldername(p_photo))[1], '') <> v_emp or coalesce((storage.foldername(p_photo))[2], '') <> 'att'
       or not exists (select 1 from storage.objects o where o.bucket_id = 'timesheet-files' and o.name = p_photo) then
      raise exception 'NO_PHOTO:ต้องถ่ายรูป selfie ก่อนลงเวลา (ไม่มีรูปแนบ ลงเวลาไม่ได้)';
    end if;
  end if;
  -- ลงเวลาเข้า/ออกงานได้เฉพาะ "ในจุดที่กำหนดให้พนักงานคนนี้" (ตั้งผู้ใช้จุดที่เมนูลงเวลา > จุดสำนักงาน) · ต้องมี GPS
  -- เปิด/ปิด: app_settings 'att_site_required' = {"on": true/false} (ค่าเริ่มต้น เปิด) · โหมดทดลอง att_test เปิดอยู่ = ข้ามการตรวจพื้นที่ · ไม่มีจุดที่ใช้ได้เลย = ไม่บังคับ
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_site_required'), true)
     and not coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false) then
    if not exists (select 1 from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) then
      raise exception 'NO_SITE:ยังไม่ได้กำหนดจุดลงเวลาให้คุณ — ลงเวลาไม่ได้ กรุณาติดต่อ Admin เพื่อกำหนดจุดลงเวลา';
    end if;
    if p_lat is null or p_lng is null then
      raise exception 'NO_GPS:ต้องเปิด GPS และอนุญาตให้ใช้ตำแหน่ง จึงจะลงเวลาได้';
    end if;
    if v_sid is null or v_d > v_rad + least(coalesce(p_acc, 0), 50) then
      raise exception 'OUT_OF_SITE:อยู่นอกจุดลงเวลาที่กำหนด — ใกล้สุด % ห่าง % ม. (รัศมี % ม.) กรุณาไปลงเวลาในพื้นที่', coalesce(v_sname, '-'), round(coalesce(v_d, 0)), coalesce(v_rad, 0);
    end if;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note, photo_path)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300), p_photo)
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text, text) to authenticated;


-- v125: ติดตามการเคลื่อนไหวระหว่าง "ออกไปทำงานนอกสถานที่" บนแผนที่ (แบบ LINEMAN) — เก็บเส้นทางเฉพาะช่วงที่อยู่ระหว่างออกนอกสถานที่
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub20.sql) — รันซ้ำได้
-- แอปส่งตำแหน่งทุก ~15 วินาที ขณะเปิดแอปค้างไว้และสถานะเป็น "ออกนอกสถานที่" (หยุดเองเมื่อกด "กลับจากนอกสถานที่" หรือลงเวลาออก)
-- ดูแผนที่ได้: เจ้าของ · ผู้ดูแล · ผู้อนุมัติลงเวลา (เมนูผู้อนุมัติ) ตามขอบเขต · เก็บ 90 วัน (ล้างด้วย select public.att_tracks_cleanup();)

create table if not exists public.att_tracks (
  id     bigint generated always as identity primary key,
  emp_id text not null references public.employees(id) on delete cascade,
  log_id uuid,                                       -- รายการ "ออกไปทำงานนอกสถานที่" ที่เป็นเจ้าของเส้นทางนี้
  at     timestamptz not null default now(),
  lat    double precision not null,
  lng    double precision not null,
  acc    real,
  speed  real
);
create index if not exists att_tracks_emp_at on public.att_tracks (emp_id, at desc);
create index if not exists att_tracks_log on public.att_tracks (log_id, at);
alter table public.att_tracks enable row level security;
revoke all on public.att_tracks from anon, authenticated;
grant select on public.att_tracks to authenticated;
drop policy if exists trk_read on public.att_tracks;
create policy trk_read on public.att_tracks for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.hub_can('att', emp_id));

-- พนักงานส่งตำแหน่ง (ได้เฉพาะตอนที่สถานะล่าสุดของวันนี้ = ออกไปทำงานนอกสถานที่)
create or replace function public.att_track(p_lat double precision, p_lng double precision, p_acc real default null, p_speed real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_day date := (now() at time zone 'Asia/Bangkok')::date; l public.attendance_logs%rowtype; v_last timestamptz;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into l from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if l.id is null or l.kind <> 'offsite_start' then raise exception 'NOT_OFFSITE:ไม่ได้อยู่ระหว่างออกไปทำงานนอกสถานที่'; end if;
  if p_lat is null or p_lng is null or p_lat not between -90 and 90 or p_lng not between -180 and 180 then raise exception 'BAD_POS'; end if;
  select max(at) into v_last from public.att_tracks where log_id = l.id;
  if v_last is not null and v_last > now() - interval '8 seconds' then return jsonb_build_object('ok', true, 'skipped', true); end if;
  insert into public.att_tracks (emp_id, log_id, lat, lng, acc, speed) values (v_emp, l.id, p_lat, p_lng, p_acc, p_speed);
  return jsonb_build_object('ok', true, 'at', now());
end $$;
revoke all on function public.att_track(double precision, double precision, real, real) from public, anon;
grant execute on function public.att_track(double precision, double precision, real, real) to authenticated;

create or replace function public.att_tracks_cleanup() returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  delete from public.att_tracks where at < now() - interval '90 days';
  get diagnostics n = row_count; return n;
end $$;
revoke all on function public.att_tracks_cleanup() from public, anon;
grant execute on function public.att_tracks_cleanup() to authenticated;

-- v126: หลังกลับจากออกนอกสถานที่ → เก็บสรุปการเดินทาง: (1) ระยะทางรวม (2) จุดที่อยู่นิ่งเกิน 30 นาที
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub24.sql) — รันซ้ำได้
-- คำนวณจากจุดตำแหน่งที่แอปส่งระหว่างออกนอกสถานที่ (att_tracks) + พิกัดตอนออก/ตอนกลับ
--   ระยะทาง: รวมระยะระหว่างจุดที่ขยับจากจุดก่อนหน้า ≥ 20 ม. (ตัดสัญญาณ GPS แกว่งตอนอยู่นิ่ง)
--   จุดนิ่ง: ช่วงที่ตำแหน่งอยู่ในรัศมี 60 ม. จากจุดตั้งต้น นานเกิน 30 นาที (เก็บ ตำแหน่ง / เวลาเริ่ม-สิ้นสุด / จำนวนนาที)
-- ถ้าแอปถูกปิด/ล็อกจอระหว่างทาง จุดจะขาดช่วง ระยะทางอาจน้อยกว่าจริง (ระบบเดินทางเป็นเส้นตรงระหว่างจุดที่ได้รับ)

create table if not exists public.att_trips (
  log_id      uuid primary key,                         -- รายการ "ออกไปทำงานนอกสถานที่"
  emp_id      text not null references public.employees(id) on delete cascade,
  start_at    timestamptz not null,
  end_at      timestamptz,
  distance_m  integer not null default 0,
  stops       jsonb not null default '[]'::jsonb,       -- [{lat,lng,from,to,minutes}]
  n_points    integer not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists att_trips_emp on public.att_trips (emp_id, start_at desc);
alter table public.att_trips enable row level security;
revoke all on public.att_trips from anon, authenticated;
grant select on public.att_trips to authenticated;
drop policy if exists trips_read on public.att_trips;
create policy trips_read on public.att_trips for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.hub_can('att', emp_id));

create or replace function public.att_trip_compute(p_log uuid) returns void
language plpgsql security definer set search_path = public as $$
declare
  s public.attendance_logs%rowtype; e public.attendance_logs%rowtype; r record;
  v_dist double precision := 0; v_n int := 0; d double precision; v_first boolean := true;
  la double precision; ln double precision;                                          -- จุดล่าสุดที่นับระยะทาง
  ca_lat double precision; ca_lng double precision; c_from timestamptz; c_to timestamptz; c_slat double precision := 0; c_slng double precision := 0; c_cnt int := 0;
  v_stops jsonb := '[]'::jsonb;
begin
  select * into s from public.attendance_logs where id = p_log and kind = 'offsite_start';
  if s.id is null then return; end if;
  select * into e from public.attendance_logs where emp_id = s.emp_id and kind in ('offsite_end', 'out') and at > s.at order by at limit 1;
  for r in
    select q.at, q.lat, q.lng from (
      select s.at as at, s.lat as lat, s.lng as lng where s.lat is not null and s.lng is not null
      union all select t.at, t.lat, t.lng from public.att_tracks t where t.log_id = p_log
      union all select e.at, e.lat, e.lng where e.id is not null and e.lat is not null and e.lng is not null
    ) q order by q.at
  loop
    v_n := v_n + 1;
    if v_first then
      la := r.lat; ln := r.lng; ca_lat := r.lat; ca_lng := r.lng; c_from := r.at; c_to := r.at; c_slat := r.lat; c_slng := r.lng; c_cnt := 1; v_first := false;
      continue;
    end if;
    d := public.geo_dist_m(la, ln, r.lat, r.lng);
    if d >= 20 then v_dist := v_dist + d; la := r.lat; ln := r.lng; end if;
    if public.geo_dist_m(ca_lat, ca_lng, r.lat, r.lng) <= 60 then
      c_to := r.at; c_slat := c_slat + r.lat; c_slng := c_slng + r.lng; c_cnt := c_cnt + 1;
    else
      if c_to - c_from >= interval '30 minutes' then
        v_stops := v_stops || jsonb_build_array(jsonb_build_object('lat', round((c_slat / c_cnt)::numeric, 6), 'lng', round((c_slng / c_cnt)::numeric, 6),
                     'from', c_from, 'to', c_to, 'minutes', round(extract(epoch from (c_to - c_from)) / 60)::int));
      end if;
      ca_lat := r.lat; ca_lng := r.lng; c_from := r.at; c_to := r.at; c_slat := r.lat; c_slng := r.lng; c_cnt := 1;
    end if;
  end loop;
  if not v_first and c_to - c_from >= interval '30 minutes' then
    v_stops := v_stops || jsonb_build_array(jsonb_build_object('lat', round((c_slat / c_cnt)::numeric, 6), 'lng', round((c_slng / c_cnt)::numeric, 6),
                 'from', c_from, 'to', c_to, 'minutes', round(extract(epoch from (c_to - c_from)) / 60)::int));
  end if;
  insert into public.att_trips (log_id, emp_id, start_at, end_at, distance_m, stops, n_points)
  values (p_log, s.emp_id, s.at, e.at, round(v_dist)::int, v_stops, v_n)
  on conflict (log_id) do update set end_at = excluded.end_at, distance_m = excluded.distance_m, stops = excluded.stops, n_points = excluded.n_points;
end $$;
revoke all on function public.att_trip_compute(uuid) from public, anon, authenticated;

-- เมื่อบันทึก "กลับจากนอกสถานที่" → คำนวณสรุปการเดินทางของรอบนั้นทันที (ล้มเหลวไม่กระทบการลงเวลา)
create or replace function public.att_trip_on_return() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_start uuid;
begin
  begin
    select id into v_start from public.attendance_logs where emp_id = new.emp_id and kind = 'offsite_start' and at < new.at order by at desc limit 1;
    if v_start is not null then perform public.att_trip_compute(v_start); end if;
  exception when others then null;
  end;
  return new;
end $$;
drop trigger if exists trg_att_trip on public.attendance_logs;
create trigger trg_att_trip after insert on public.attendance_logs for each row when (new.kind in ('offsite_end', 'out')) execute function public.att_trip_on_return();

-- คำนวณย้อนหลังให้รอบที่กลับมาแล้ว (ถ้ามีจุดตำแหน่งเก็บไว้)
do $$ declare x uuid; begin
  for x in select l.id from public.attendance_logs l where l.kind = 'offsite_start'
             and exists (select 1 from public.attendance_logs e where e.emp_id = l.emp_id and e.kind in ('offsite_end', 'out') and e.at > l.at) loop
    begin perform public.att_trip_compute(x); exception when others then null; end;
  end loop;
end $$;

-- v130: แผนที่ติดตามการเดินทางเห็นได้เฉพาะ Super Admin (ข้อมูลตำแหน่งระหว่างออกนอกสถานที่ = ข้อมูลส่วนบุคคล จำกัดผู้เข้าถึง)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub25.sql) — รันซ้ำได้
-- att_tracks (จุดตำแหน่ง): อ่านได้เฉพาะ Super Admin และเจ้าของ · att_trips (สรุประยะทาง/จุดนิ่ง): Super Admin และเจ้าของ
-- (เดิม Admin และผู้อนุมัติลงเวลาอ่านได้ — เอาออกแล้ว)

drop policy if exists trk_read on public.att_tracks;
create policy trk_read on public.att_tracks for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_super_admin());

drop policy if exists trips_read on public.att_trips;
create policy trips_read on public.att_trips for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_super_admin());

-- v133: บันทึก comment งานระหว่างออกนอกสถานที่ (นับเป็นรายการ 1, 2, 3 … ต่อการเดินทางหนึ่งรอบ) พร้อมตำแหน่ง GPS ตอนบันทึก
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub26.sql) — รันซ้ำได้
-- ใช้แสดงจำนวน comment บนหัวรถในแผนที่ติดตามของ Super Admin และหมุดหมายเลขตามจุดที่บันทึก

create table if not exists public.att_trip_notes (
  id     bigint generated always as identity primary key,
  emp_id text not null references public.employees(id) on delete cascade,
  log_id uuid not null,                       -- รายการ "ออกไปทำงานนอกสถานที่" ของรอบนี้
  seq    integer not null,                    -- ลำดับ comment ในรอบ: 1, 2, 3 …
  note   text not null,
  at     timestamptz not null default now(),
  lat    double precision,
  lng    double precision,
  acc    real,
  unique (log_id, seq)
);
create index if not exists att_trip_notes_log on public.att_trip_notes (log_id, seq);
alter table public.att_trip_notes enable row level security;
revoke all on public.att_trip_notes from anon, authenticated;
grant select on public.att_trip_notes to authenticated;
drop policy if exists tnote_read on public.att_trip_notes;
create policy tnote_read on public.att_trip_notes for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_super_admin());

-- พนักงานบันทึก comment งาน (ได้เฉพาะตอนสถานะล่าสุดของวันนี้ = ออกไปทำงานนอกสถานที่)
create or replace function public.att_trip_note(p_note text, p_lat double precision default null, p_lng double precision default null, p_acc real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_day date := (now() at time zone 'Asia/Bangkok')::date; l public.attendance_logs%rowtype; v_seq integer; v_note text := left(trim(coalesce(p_note, '')), 300);
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if v_note = '' then raise exception 'EMPTY_NOTE:กรุณาใส่ comment งาน'; end if;
  select * into l from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if l.id is null or l.kind <> 'offsite_start' then raise exception 'NOT_OFFSITE:บันทึก comment ได้เฉพาะระหว่างออกไปทำงานนอกสถานที่'; end if;
  perform pg_advisory_xact_lock(hashtext('trip_note|' || l.id::text));
  select coalesce(max(seq), 0) + 1 into v_seq from public.att_trip_notes where log_id = l.id;
  insert into public.att_trip_notes (emp_id, log_id, seq, note, lat, lng, acc)
  values (v_emp, l.id, v_seq, v_note, p_lat, p_lng, p_acc);
  return jsonb_build_object('ok', true, 'seq', v_seq, 'at', now(), 'log_id', l.id);
end $$;
revoke all on function public.att_trip_note(text, double precision, double precision, real) from public, anon;
grant execute on function public.att_trip_note(text, double precision, double precision, real) to authenticated;

-- v136: แจ้งเตือนทาง LINE ระบบลางาน — (1) มีคำขอลาใหม่/แก้ไขคำขอ → แจ้งผู้อนุมัติลา (ตามขอบเขต hub_approvers + Super Admin) (2) อนุมัติ/ไม่อนุมัติ → แจ้งผู้ลา
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub12.sql และต้องตั้ง private_config line_notify_url / line_notify_secret ไว้แล้ว เหมือนการแจ้งเตือนอื่น) — รันซ้ำได้
-- ต้อง deploy Edge Function line-notify.ts (function "hyper-api") ใหม่ด้วย

create or replace function public.notify_leave() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_url text; v_sec text; v_kind text;
begin
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is null or v_sec is null then return new; end if;
    if tg_op = 'INSERT' then
      if new.status = 'Pending' then v_kind := 'leave_new'; end if;
    else
      if new.status = 'Pending' and (old.status is distinct from 'Pending' or old.start_date <> new.start_date or old.end_date <> new.end_date
                                     or old.type_id <> new.type_id or old.part <> new.part) then
        v_kind := 'leave_new';                    -- ขอใหม่ หรือแก้ไขคำขอ (ทำให้กลับเป็นรออนุมัติ)
      elsif old.status = 'Pending' and new.status in ('Approved', 'Rejected') then
        v_kind := 'leave_decided';                -- ผลการอนุมัติ → แจ้งผู้ลา
      end if;
    end if;
    if v_kind is not null then
      perform net.http_post(url := v_url,
        headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
        body := jsonb_build_object('kind', v_kind, 'leave_id', new.id));
    end if;
  exception when others then
    null;   -- ห้ามให้การแจ้งเตือนทำให้การขอลา/อนุมัติล้มเหลว
  end;
  return new;
end $$;

drop trigger if exists leave_notify on public.leave_requests;
create trigger leave_notify after insert or update on public.leave_requests
  for each row execute function public.notify_leave();

-- ===== hub29 =====
-- v137: อนุมัติ/ไม่อนุมัติการลาในแชต LINE ได้เลย (การ์ดคำขอลามีปุ่ม "✅ อนุมัติ" กดครั้งเดียว และ "❌ ไม่อนุมัติ" → พิมพ์เหตุผลตอบกลับ)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub28.sql) — รันซ้ำได้
-- ต้อง deploy Edge Function: line-notify.ts (hyper-api) และ line-webhook.ts (clever-task) ใหม่
-- สิทธิ์ตรวจที่ฐานข้อมูลเหมือนในแอป: Super Admin หรือผู้อนุมัติลาตามขอบเขต (hub_approvers) · อนุมัติใบลาของตัวเองผ่าน LINE ไม่ได้

create table if not exists public.line_leave_reject (
  line_user text primary key,
  leave_id  uuid not null,
  exp       timestamptz not null
);
alter table public.line_leave_reject enable row level security;
revoke all on public.line_leave_reject from anon, authenticated;

-- อนุมัติ/ไม่อนุมัติใบลาจาก LINE userId · p_dry = true ตรวจสิทธิ์อย่างเดียว ไม่บันทึก
create or replace function public.line_leave_decide(p_line_user text, p_leave uuid, p_approve boolean, p_note text default '', p_dry boolean default false) returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; r public.leave_requests%rowtype; o public.employees%rowtype; v_ok boolean; v_type text;
begin
  select * into me from public.employees where line_user_id = p_line_user and active and approved;
  if me.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;
  select * into r from public.leave_requests where id = p_leave for update;
  if r.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบใบลานี้'); end if;
  if r.status <> 'Pending' then
    return jsonb_build_object('ok', false, 'msg', 'ใบลานี้ดำเนินการไปแล้ว (' || case r.status when 'Approved' then 'อนุมัติแล้ว' when 'Rejected' then 'ไม่อนุมัติแล้ว' else 'ยกเลิกแล้ว' end || ')');
  end if;
  if r.emp_id = me.id then return jsonb_build_object('ok', false, 'msg', 'อนุมัติใบลาของตัวเองผ่าน LINE ไม่ได้'); end if;
  select * into o from public.employees where id = r.emp_id;
  v_ok := me.role = 'super_admin' or exists (
    select 1 from public.hub_approvers a
     where a.emp_id = me.id and a.module = 'leave'
       and (a.scope_type = 'all' or (a.scope_type = 'dept' and a.scope_key = o.dept) or (a.scope_type = 'emp' and a.scope_key = o.id)));
  if not v_ok then return jsonb_build_object('ok', false, 'msg', 'คุณไม่มีสิทธิ์อนุมัติการลาของพนักงานคนนี้'); end if;
  select name into v_type from public.leave_types where id = r.type_id;
  if not p_dry then
    update public.leave_requests
       set status = case when p_approve then 'Approved' else 'Rejected' end, decided_by = me.id, decided_at = now(), decide_note = left(coalesce(p_note, ''), 300)
     where id = p_leave;
  end if;
  return jsonb_build_object('ok', true, 'emp', o.name, 'emp_id', o.id, 'type', v_type, 'start', r.start_date, 'end', r.end_date, 'days', r.days, 'part', r.part);
end $$;
revoke all on function public.line_leave_decide(text, uuid, boolean, text, boolean) from public, anon, authenticated;
grant execute on function public.line_leave_decide(text, uuid, boolean, text, boolean) to service_role;

-- กด "ไม่อนุมัติ": รอข้อความถัดไปของผู้กดเป็นเหตุผล (หมดอายุ 5 นาที)
create or replace function public.line_leave_reject_wait(p_line_user text, p_leave uuid) returns void
language sql security definer set search_path = public as $$
  insert into public.line_leave_reject (line_user, leave_id, exp) values (p_line_user, p_leave, now() + interval '5 minutes')
  on conflict (line_user) do update set leave_id = excluded.leave_id, exp = excluded.exp
$$;
revoke all on function public.line_leave_reject_wait(text, uuid) from public, anon, authenticated;
grant execute on function public.line_leave_reject_wait(text, uuid) to service_role;

-- ข้อความที่ผู้ใช้พิมพ์ตอบ: ถ้ากำลังรอเหตุผลไม่อนุมัติ → ใช้เป็นเหตุผลแล้วบันทึกไม่อนุมัติ ("ยกเลิก" = ยกเลิกการไม่อนุมัติ)
create or replace function public.line_leave_take_reason(p_line_user text, p_text text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare w public.line_leave_reject%rowtype; res jsonb;
begin
  select * into w from public.line_leave_reject where line_user = p_line_user and exp > now();
  if w.line_user is null then
    delete from public.line_leave_reject where line_user = p_line_user;
    return jsonb_build_object('pending', false);
  end if;
  delete from public.line_leave_reject where line_user = p_line_user;
  if lower(trim(p_text)) in ('ยกเลิก', 'cancel') then return jsonb_build_object('pending', true, 'cancelled', true); end if;
  res := public.line_leave_decide(p_line_user, w.leave_id, false, p_text, false);
  return jsonb_build_object('pending', true, 'cancelled', false, 'result', res);
end $$;
revoke all on function public.line_leave_take_reason(text, text) from public, anon, authenticated;
grant execute on function public.line_leave_take_reason(text, text) to service_role;

-- ===== hub30 =====
-- v154: เปิดโหมดทดลอง — บันทึกชั่วโมงงานได้เต็ม 8 ชม. ทันทีหลังลงเวลาเข้างาน ไม่ต้องรอให้เวลาผ่านไปครบ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub29.sql) — รันซ้ำได้
-- โหมดทดลอง = app_settings 'att_test' {"on": true}  (ยังต้องลงเวลาเข้างานก่อน แต่ชั่วโมงที่บันทึกได้ไม่ผูกกับเวลาที่ผ่านไป)
-- ปิดโหมดทดลองก่อนใช้งานจริง:  update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_test';

insert into public.app_settings (key, value) values ('att_test', '{"on": true}'::jsonb)
on conflict (key) do update set value = '{"on": true}'::jsonb;

create or replace function public.ts_att_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_new numeric := 0; v_old numeric := 0; v_allow integer; v_test boolean := false;
begin
  select coalesce((value->>'on')::boolean, false) into v_test from public.app_settings where key = 'att_test';
  select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_new from jsonb_array_elements(coalesce(new.entries, '[]'::jsonb)) e;
  if tg_op = 'UPDATE' then
    select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_old from jsonb_array_elements(coalesce(old.entries, '[]'::jsonb)) e;
  end if;
  if v_new <= v_old then return new; end if;
  if auth.uid() is null or (public.is_super_admin() and new.emp_id is distinct from public.my_emp_id()) then return new; end if;
  if not public.att_required_for(new.emp_id, new.day) then return new; end if;
  v_allow := public.att_hours_for(new.emp_id, new.day);
  if v_allow is null then
    raise exception 'NO_CLOCK_IN:ยังไม่ได้ลงเวลาเข้างานของวันที่ % — ไม่สามารถบันทึกชั่วโมงงานได้ (ลงเวลาที่ระบบลงเวลา หรือผ่าน AI-Beacon ก่อน)', to_char(new.day, 'DD/MM/YYYY');
  end if;
  if coalesce(v_test, false) then v_allow := 8; end if;   -- โหมดทดลอง: ไม่ต้องรอเวลาผ่านไปครบ
  if v_new > v_allow then
    raise exception 'HOURS_EXCEED:ชั่วโมงงานรวม % ชม. เกินชั่วโมงที่ได้จากการลงเวลา % ชม. ของวันที่ %', v_new, v_allow, to_char(new.day, 'DD/MM/YYYY');
  end if;
  return new;
end $$;

-- ===== hub31 =====
-- v155: โหมดทดลอง (att_test) — ลงเวลาเข้างานได้หลายครั้งต่อวัน (ลงเข้า-ออก-เข้า ต่อได้เรื่อย ๆ) และลงได้ทุกวัน แม้ไม่ใช่วันทำงาน
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub30.sql) — รันซ้ำได้
-- ปิดโหมดทดลองก่อนใช้งานจริง (กลับเป็นลงเวลาเข้างานได้วันละครั้ง):  update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_test';
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '', p_photo text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not v_test and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null and not (v_test and v_last = 'out') then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  -- ต้องแนบรูป selfie (อัปโหลดไว้ใน bucket timesheet-files โฟลเดอร์ <รหัสพนักงาน>/att/...) ทุกครั้งที่ลงเวลา — ไม่มีรูป = ไม่ให้ลงเวลา
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_photo_required'), true) then
    if p_photo is null or coalesce((storage.foldername(p_photo))[1], '') <> v_emp or coalesce((storage.foldername(p_photo))[2], '') <> 'att'
       or not exists (select 1 from storage.objects o where o.bucket_id = 'timesheet-files' and o.name = p_photo) then
      raise exception 'NO_PHOTO:ต้องถ่ายรูป selfie ก่อนลงเวลา (ไม่มีรูปแนบ ลงเวลาไม่ได้)';
    end if;
  end if;
  -- ลงเวลาเข้า/ออกงานได้เฉพาะ "ในจุดที่กำหนดให้พนักงานคนนี้" (ตั้งผู้ใช้จุดที่เมนูลงเวลา > จุดสำนักงาน) · ต้องมี GPS
  -- เปิด/ปิด: app_settings 'att_site_required' = {"on": true/false} (ค่าเริ่มต้น เปิด) · โหมดทดลอง att_test เปิดอยู่ = ข้ามการตรวจพื้นที่ · ไม่มีจุดที่ใช้ได้เลย = ไม่บังคับ
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_site_required'), true)
     and not coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false) then
    if not exists (select 1 from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) then
      raise exception 'NO_SITE:ยังไม่ได้กำหนดจุดลงเวลาให้คุณ — ลงเวลาไม่ได้ กรุณาติดต่อ Admin เพื่อกำหนดจุดลงเวลา';
    end if;
    if p_lat is null or p_lng is null then
      raise exception 'NO_GPS:ต้องเปิด GPS และอนุญาตให้ใช้ตำแหน่ง จึงจะลงเวลาได้';
    end if;
    if v_sid is null or v_d > v_rad + least(coalesce(p_acc, 0), 50) then
      raise exception 'OUT_OF_SITE:อยู่นอกจุดลงเวลาที่กำหนด — ใกล้สุด % ห่าง % ม. (รัศมี % ม.) กรุณาไปลงเวลาในพื้นที่', coalesce(v_sname, '-'), round(coalesce(v_d, 0)), coalesce(v_rad, 0);
    end if;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note, photo_path)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300), p_photo)
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text, text) to authenticated;


-- ===== hub32 =====
-- v156: พนักงานแก้ไข/ลบรายการที่อนุมัติแล้ว (ใบ Submitted) ได้ — ระบบจะยกเลิกการอนุมัติ ใบกลับเป็น Draft แล้วต้องส่งอนุมัติใหม่ทุกขั้น
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub31.sql) — รันซ้ำได้
-- เปิด/ปิด: app_settings 'ts_edit_approved' = {"on": true/false}  (ค่าเริ่มต้น เปิด)
--   ปิด:  update public.app_settings set value = '{"on": false}'::jsonb where key = 'ts_edit_approved';

insert into public.app_settings (key, value) values ('ts_edit_approved', '{"on": true}'::jsonb) on conflict (key) do nothing;

create or replace function public.ts_reopen_approved(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare t public.timesheets%rowtype; v_on boolean;
begin
  select coalesce((value->>'on')::boolean, true) into v_on from public.app_settings where key = 'ts_edit_approved';
  if coalesce(v_on, true) is not true then raise exception 'DISABLED:ปิดการแก้ไขรายการที่อนุมัติแล้วอยู่ — ติดต่อ Admin'; end if;
  select * into t from public.timesheets where id = p_id for update;
  if t.id is null then raise exception 'NOT_FOUND:ไม่พบใบบันทึกงาน'; end if;
  if not (t.emp_id = public.my_emp_id() or public.can_enter_for(t.emp_id)) then raise exception 'FORBIDDEN:แก้ไขได้เฉพาะใบของตัวเอง'; end if;
  if t.status <> 'Submitted' then raise exception 'NOT_SUBMITTED:ใบนี้ไม่ได้อยู่สถานะอนุมัติแล้ว'; end if;
  update public.timesheets
     set status = 'Draft', submitted_at = null, approved_by = '', approved_at = null, reject_note = '',
         entries = coalesce((select jsonb_agg(e - 'ap') from jsonb_array_elements(coalesce(entries, '[]'::jsonb)) e), '[]'::jsonb)
   where id = p_id returning * into t;
  return to_jsonb(t);
end $$;
revoke all on function public.ts_reopen_approved(text) from public, anon;
grant execute on function public.ts_reopen_approved(text) to authenticated;

-- ===== hub33 =====
-- v157: แจ้งเตือนทาง LINE เมื่อเข้ารัศมีจุดลงเวลา + กดลงเวลาเข้า/ออกงานผ่าน LINE ได้เลย
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub32.sql) — รันซ้ำได้
-- ต้อง deploy Edge Function line-notify.ts (hyper-api) และ line-webhook.ts (clever-task) ใหม่ด้วย
-- วิธีที่ระบบรู้ว่า "เข้ารัศมี":  (1) แอปเปิดอยู่และอนุญาตตำแหน่ง → แอปตรวจเทียบกับจุด/รัศมีที่ตั้งไว้ (att_geo_enter)
--                                 (2) พนักงานส่งตำแหน่ง (Share location) หรือพิมพ์ "ลงเวลา" ในแชต LINE (line_att_nearest)
--                                 (3) AI-Beacon / LINE Beacon ที่ติดตั้งในพื้นที่ (ระบบเดิม att_beacon — ตรวจเข้ารัศมีเบื้องหลังได้จริง)
-- การลงเวลาผ่าน LINE ไม่ต้องถ่าย selfie (บันทึก source = 'line') · ปิดได้: update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_line_punch';

alter table public.attendance_logs drop constraint if exists attendance_logs_source_check;
alter table public.attendance_logs add constraint attendance_logs_source_check check (source in ('app', 'beacon', 'admin', 'test', 'line'));
insert into public.app_settings (key, value) values ('att_line_punch', '{"on": true}'::jsonb) on conflict (key) do nothing;

create table if not exists public.att_line_prompt (
  id uuid primary key default gen_random_uuid(),
  emp_id text not null references public.employees(id) on delete cascade,
  site_id text, lat double precision, lng double precision, acc real,
  used boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.att_line_prompt enable row level security;
revoke all on public.att_line_prompt from anon, authenticated;
create index if not exists att_line_prompt_emp_idx on public.att_line_prompt (emp_id, created_at desc);

-- (1) แอปตรวจพบว่าเข้ารัศมี → ส่งการ์ด LINE พร้อมปุ่มลงเวลา (ครั้งเดียวต่อจุดต่อ 6 ชม.)
create or replace function public.att_geo_enter(p_lat double precision, p_lng double precision, p_acc real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); s record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; v_id uuid; v_url text; v_sec text;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  if v_emp is null or p_lat is null or p_lng is null then return jsonb_build_object('notified', false); end if;
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_line_punch'), true) is not true then return jsonb_build_object('notified', false); end if;
  if not exists (select 1 from public.employees where id = v_emp and active and approved and line_user_id is not null) then return jsonb_build_object('notified', false); end if;
  select x.* into s from (select w.id, w.name, w.radius_m, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng) as d
                            from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) x
   where x.d <= x.radius_m + least(coalesce(p_acc, 0), 50) order by x.d limit 1;
  if s.id is null then return jsonb_build_object('notified', false, 'inside', false); end if;
  if not v_test and not public.is_work_day(v_emp, v_day) then return jsonb_build_object('notified', false); end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if not (v_last is null or (v_test and v_last = 'out')) then return jsonb_build_object('notified', false, 'inside', true); end if;   -- ลงเวลาเข้างานแล้ว ไม่ต้องแจ้ง
  if exists (select 1 from public.att_line_prompt where emp_id = v_emp and site_id = s.id and created_at > now() - interval '6 hours') then
    return jsonb_build_object('notified', false, 'dup', true);
  end if;
  insert into public.att_line_prompt (emp_id, site_id, lat, lng, acc) values (v_emp, s.id, p_lat, p_lng, p_acc) returning id into v_id;
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is not null and v_sec is not null then
      perform net.http_post(url := v_url, headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
                            body := jsonb_build_object('kind', 'geo_enter', 'prompt_id', v_id));
    end if;
  exception when others then null;
  end;
  return jsonb_build_object('notified', true, 'site', s.name);
end $$;
revoke all on function public.att_geo_enter(double precision, double precision, real) from public, anon;
grant execute on function public.att_geo_enter(double precision, double precision, real) to authenticated;

-- (2) พนักงานส่งตำแหน่งในแชต LINE → หาจุดที่ใกล้สุดและบอกว่าลงเวลาอะไรได้ (service_role เท่านั้น)
create or replace function public.line_att_nearest(p_line_user text, p_lat double precision, p_lng double precision, p_acc real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; s record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; v_kind text; v_id uuid;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_line_punch'), true) is not true then
    return jsonb_build_object('ok', false, 'msg', 'ขณะนี้ปิดการลงเวลาผ่าน LINE — กรุณาลงเวลาในแอป');
  end if;
  select x.* into s from (select w.id, w.name, w.radius_m, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng) as d
                            from public.work_sites w where w.active and public.site_applies(e.id, w.id)) x order by x.d limit 1;
  if s.id is null then return jsonb_build_object('ok', false, 'msg', 'ยังไม่ได้กำหนดจุดลงเวลาให้คุณ — กรุณาติดต่อ Admin'); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  v_kind := case when v_last is null or (v_test and v_last = 'out') then 'in' when v_last in ('in', 'offsite_end') then 'out' else null end;
  if s.d > s.radius_m + least(coalesce(p_acc, 0), 50) and not v_test then
    return jsonb_build_object('ok', true, 'inside', false, 'name', e.name, 'site', s.name, 'dist', round(s.d), 'radius', s.radius_m);
  end if;
  if v_kind is null then return jsonb_build_object('ok', true, 'inside', true, 'name', e.name, 'site', s.name, 'dist', round(s.d), 'radius', s.radius_m, 'kind', null, 'last', v_last); end if;
  insert into public.att_line_prompt (emp_id, site_id, lat, lng, acc) values (e.id, s.id, p_lat, p_lng, p_acc) returning id into v_id;
  return jsonb_build_object('ok', true, 'inside', true, 'name', e.name, 'site', s.name, 'dist', round(s.d), 'radius', s.radius_m, 'kind', v_kind, 'prompt', v_id);
end $$;
revoke all on function public.line_att_nearest(text, double precision, double precision, real) from public, anon, authenticated;
grant execute on function public.line_att_nearest(text, double precision, double precision, real) to service_role;

-- กดปุ่มในการ์ด LINE → บันทึกลงเวลา (ตรวจกติกาเดียวกับในแอป: วันทำงาน · ลำดับเข้า/ออก · อยู่ในรัศมี · ใช้พิกัดจากตอนตรวจพบ ภายใน 20 นาที)
create or replace function public.line_att_punch(p_line_user text, p_prompt uuid, p_kind text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; pr public.att_line_prompt%rowtype; w record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; r public.attendance_logs%rowtype; v_st record;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_line_punch'), true) is not true then
    return jsonb_build_object('ok', false, 'msg', 'ขณะนี้ปิดการลงเวลาผ่าน LINE — กรุณาลงเวลาในแอป');
  end if;
  if p_kind not in ('in', 'out') then return jsonb_build_object('ok', false, 'msg', 'คำสั่งไม่ถูกต้อง'); end if;
  select * into pr from public.att_line_prompt where id = p_prompt and emp_id = e.id for update;
  if pr.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบคำขอลงเวลานี้ — กรุณาส่งตำแหน่งใหม่'); end if;
  if pr.used then return jsonb_build_object('ok', false, 'msg', 'คำขอนี้ลงเวลาไปแล้ว'); end if;
  if now() - pr.created_at > interval '20 minutes' then return jsonb_build_object('ok', false, 'msg', 'คำขอหมดอายุ (เกิน 20 นาที) — กรุณาส่งตำแหน่งใหม่เพื่อลงเวลา'); end if;
  if p_kind = 'in' and not v_test and not public.is_work_day(e.id, v_day) then return jsonb_build_object('ok', false, 'msg', 'วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้'); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and not (v_last is null or (v_test and v_last = 'out')) then return jsonb_build_object('ok', false, 'msg', 'ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว)'); end if;
  if p_kind = 'out' and v_last not in ('in', 'offsite_end') then return jsonb_build_object('ok', false, 'msg', case when v_last is null then 'ยังไม่ได้ลงเวลาเข้างาน' when v_last = 'offsite_start' then 'กรุณาบันทึกกลับจากนอกสถานที่ในแอปก่อน' else 'ลงเวลาออกงานไปแล้ว' end); end if;
  if exists (select 1 from public.attendance_logs where emp_id = e.id and kind = p_kind and at > now() - interval '30 seconds') then return jsonb_build_object('ok', false, 'msg', 'บันทึกซ้ำเร็วเกินไป'); end if;
  select x.* into w from (select s.id, s.name, s.radius_m, public.geo_dist_m(pr.lat, pr.lng, s.lat, s.lng) as d
                            from public.work_sites s where s.active and public.site_applies(e.id, s.id)) x order by x.d limit 1;
  if not v_test then
    if w.id is null then return jsonb_build_object('ok', false, 'msg', 'ยังไม่ได้กำหนดจุดลงเวลาให้คุณ — กรุณาติดต่อ Admin'); end if;
    if w.d > w.radius_m + least(coalesce(pr.acc, 0), 50) then
      return jsonb_build_object('ok', false, 'msg', format('อยู่นอกจุดลงเวลา — ใกล้สุด %s ห่าง %s ม. (รัศมี %s ม.)', w.name, round(w.d), w.radius_m));
    end if;
  end if;
  if p_kind = 'out' then
    select * into v_st from public.att_net_state(e.id, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      return jsonb_build_object('ok', false, 'msg', 'ทำงานครบ 8 ชั่วโมงแล้ว — ต้องระบุเหตุผลการออกงาน กรุณาลงเวลาออกในแอป');
    end if;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (e.id, p_kind, clock_timestamp(), pr.lat, pr.lng, pr.acc, w.id, coalesce(w.name, ''), case when w.id is not null then round(w.d)::int end, 'line', '[ลงเวลาผ่าน LINE]')
  returning * into r;
  update public.att_line_prompt set used = true where id = pr.id;
  return jsonb_build_object('ok', true, 'kind', p_kind, 'at', r.at, 'name', e.name, 'site', coalesce(w.name, ''));
end $$;
revoke all on function public.line_att_punch(text, uuid, text) from public, anon, authenticated;
grant execute on function public.line_att_punch(text, uuid, text) to service_role;

-- ===== hub34 =====
-- v158: LINE แจ้งเตือนอย่างเดียว — ไม่ลงเวลาผ่าน LINE (ต้องไปลงเวลาที่แอปเท่านั้น เพื่อคง selfie + GPS + ตรวจจุด)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub33.sql) — รันซ้ำได้
-- เปิด/ปิดการแจ้งเตือนเข้ารัศมี: update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_line_notify';

drop function if exists public.line_att_punch(text, uuid, text);
insert into public.app_settings (key, value) values ('att_line_notify', '{"on": true}'::jsonb) on conflict (key) do nothing;
create or replace function public.att_geo_enter(p_lat double precision, p_lng double precision, p_acc real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); s record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; v_id uuid; v_url text; v_sec text;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  if v_emp is null or p_lat is null or p_lng is null then return jsonb_build_object('notified', false); end if;
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_line_notify'), true) is not true then return jsonb_build_object('notified', false); end if;
  if not exists (select 1 from public.employees where id = v_emp and active and approved and line_user_id is not null) then return jsonb_build_object('notified', false); end if;
  select x.* into s from (select w.id, w.name, w.radius_m, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng) as d
                            from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) x
   where x.d <= x.radius_m + least(coalesce(p_acc, 0), 50) order by x.d limit 1;
  if s.id is null then return jsonb_build_object('notified', false, 'inside', false); end if;
  if not v_test and not public.is_work_day(v_emp, v_day) then return jsonb_build_object('notified', false); end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if not (v_last is null or (v_test and v_last = 'out')) then return jsonb_build_object('notified', false, 'inside', true); end if;   -- ลงเวลาเข้างานแล้ว ไม่ต้องแจ้ง
  if exists (select 1 from public.att_line_prompt where emp_id = v_emp and site_id = s.id and created_at > now() - interval '6 hours') then
    return jsonb_build_object('notified', false, 'dup', true);
  end if;
  insert into public.att_line_prompt (emp_id, site_id, lat, lng, acc) values (v_emp, s.id, p_lat, p_lng, p_acc) returning id into v_id;
  begin
    select value into v_url from public.private_config where key = 'line_notify_url';
    select value into v_sec from public.private_config where key = 'line_notify_secret';
    if v_url is not null and v_sec is not null then
      perform net.http_post(url := v_url, headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
                            body := jsonb_build_object('kind', 'geo_enter', 'prompt_id', v_id));
    end if;
  exception when others then null;
  end;
  return jsonb_build_object('notified', true, 'site', s.name);
end $$;
revoke all on function public.att_geo_enter(double precision, double precision, real) from public, anon;
grant execute on function public.att_geo_enter(double precision, double precision, real) to authenticated;

-- ส่งตำแหน่งในแชต LINE → บอกว่าอยู่ในรัศมีจุดลงเวลาหรือไม่ (ไม่บันทึกลงเวลา)
create or replace function public.line_att_nearest(p_line_user text, p_lat double precision, p_lng double precision, p_acc real default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; s record;
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้ในระบบ'); end if;
  select x.* into s from (select w.id, w.name, w.radius_m, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng) as d
                            from public.work_sites w where w.active and public.site_applies(e.id, w.id)) x order by x.d limit 1;
  if s.id is null then return jsonb_build_object('ok', false, 'msg', 'ยังไม่ได้กำหนดจุดลงเวลาให้คุณ — กรุณาติดต่อ Admin'); end if;
  return jsonb_build_object('ok', true, 'name', e.name, 'site', s.name, 'dist', round(s.d), 'radius', s.radius_m,
                            'inside', s.d <= s.radius_m + least(coalesce(p_acc, 0), 50));
end $$;
revoke all on function public.line_att_nearest(text, double precision, double precision, real) from public, anon, authenticated;
grant execute on function public.line_att_nearest(text, double precision, double precision, real) to service_role;

-- ===== hub35 =====
-- v159: เอาการตรวจตำแหน่งผ่านแชต LINE ออก (LINE แจ้งเตือนเข้ารัศมีอย่างเดียว · ลงเวลาที่แอป)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub34.sql) — รันซ้ำได้
drop function if exists public.line_att_nearest(text, double precision, double precision, real);

-- ===== hub36 =====
-- v163: แก้ไข/ตรวจสอบการแจ้งเตือน LINE เมื่อเข้ารัศมี — ส่งเหตุผลกลับมาให้เห็นว่าทำไมแจ้ง/ไม่แจ้ง + ปุ่มทดสอบในแอป
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub35.sql) — รันซ้ำได้
-- ต้องรัน hub33 ก่อน (สร้างตาราง att_line_prompt) และ deploy Edge Function line-notify.ts (hyper-api) ที่มี kind 'geo_enter'

drop function if exists public.att_geo_enter(double precision, double precision, real);
create or replace function public.att_geo_enter(p_lat double precision, p_lng double precision, p_acc real default null, p_force boolean default false) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); s record; n record; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; v_id uuid; v_url text; v_sec text;
  v_test boolean := coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_test'), false);
begin
  if v_emp is null or p_lat is null or p_lng is null then return jsonb_build_object('notified', false, 'reason', 'no_emp'); end if;
  if coalesce((select (value->>'on')::boolean from public.app_settings where key = 'att_line_notify'), true) is not true then return jsonb_build_object('notified', false, 'reason', 'off'); end if;
  if not exists (select 1 from public.employees where id = v_emp and active and approved and line_user_id is not null) then return jsonb_build_object('notified', false, 'reason', 'no_line'); end if;
  select x.* into n from (select w.id, w.name, w.radius_m, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng) as d
                            from public.work_sites w where w.active and public.site_applies(v_emp, w.id)) x order by x.d limit 1;
  if n.id is null then return jsonb_build_object('notified', false, 'reason', 'no_site'); end if;
  if n.d > n.radius_m + least(coalesce(p_acc, 0), 50) then
    return jsonb_build_object('notified', false, 'reason', 'outside', 'site', n.name, 'dist', round(n.d), 'radius', n.radius_m, 'acc', round(coalesce(p_acc, 0)));
  end if;
  s := n;
  if not v_test and not public.is_work_day(v_emp, v_day) then return jsonb_build_object('notified', false, 'reason', 'nonwork'); end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if not p_force and not (v_last is null or (v_test and v_last = 'out')) then return jsonb_build_object('notified', false, 'reason', 'done', 'site', s.name); end if;
  if not p_force and exists (select 1 from public.att_line_prompt where emp_id = v_emp and site_id = s.id and created_at > now() - interval '6 hours') then
    return jsonb_build_object('notified', false, 'reason', 'dup', 'site', s.name);
  end if;
  insert into public.att_line_prompt (emp_id, site_id, lat, lng, acc) values (v_emp, s.id, p_lat, p_lng, p_acc) returning id into v_id;
  select value into v_url from public.private_config where key = 'line_notify_url';
  select value into v_sec from public.private_config where key = 'line_notify_secret';
  if v_url is null or v_sec is null then return jsonb_build_object('notified', false, 'reason', 'no_url', 'site', s.name); end if;
  begin
    perform net.http_post(url := v_url, headers := jsonb_build_object('Content-Type', 'application/json', 'x-webhook-secret', v_sec),
                          body := jsonb_build_object('kind', 'geo_enter', 'prompt_id', v_id));
  exception when others then
    return jsonb_build_object('notified', false, 'reason', 'http_error', 'site', s.name, 'err', sqlerrm);
  end;
  return jsonb_build_object('notified', true, 'reason', 'sent', 'site', s.name, 'dist', round(s.d));
end $$;
revoke all on function public.att_geo_enter(double precision, double precision, real, boolean) from public, anon;
grant execute on function public.att_geo_enter(double precision, double precision, real, boolean) to authenticated;

-- ===== hub38 =====
-- v179: นำเข้า Budget (บาท) ของโครงการ/สัญญาขายจากไฟล์ IFS (DataIFS_TimeSheet.xlsx) อัตโนมัติ — ใช้กับสคริปต์ ifs_budget_sync.ps1 ที่รันในเครือข่ายบริษัท
-- รันใน Supabase > SQL Editor หนึ่งครั้ง — รันซ้ำได้
-- ฟังก์ชันนี้ "อัปเดตเฉพาะรหัสที่มีอยู่แล้ว" ในตาราง projects / contracts (ไม่สร้างรหัสใหม่) และเรียกได้เฉพาะ service_role
-- p_rows = [{"id":"AS19003-MT","baht":500000}, ...]

create or replace function public.ifs_budget_sync(p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r jsonb; v_id text; v_baht numeric; n_p int := 0; n_c int := 0; v_miss text[] := '{}'; v_cnt int;
begin
  for r in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    v_id := trim(r->>'id'); v_baht := nullif(r->>'baht', '')::numeric;
    continue when v_id is null or v_id = '' or v_baht is null;
    update public.projects set budget_baht = v_baht, updated_by = 'IFS', updated_at = now() where id = v_id and budget_baht is distinct from v_baht;
    get diagnostics v_cnt = row_count; n_p := n_p + v_cnt;
    if v_cnt = 0 and exists (select 1 from public.projects where id = v_id) then continue; end if;   -- มีอยู่แล้วและค่าเท่าเดิม
    if v_cnt = 0 then
      update public.contracts set budget_baht = v_baht, updated_by = 'IFS', updated_at = now() where id = v_id and budget_baht is distinct from v_baht;
      get diagnostics v_cnt = row_count; n_c := n_c + v_cnt;
      if v_cnt = 0 and not exists (select 1 from public.contracts where id = v_id) and array_length(v_miss, 1) is distinct from 40 then v_miss := v_miss || v_id; end if;
    end if;
  end loop;
  return jsonb_build_object('updated_projects', n_p, 'updated_contracts', n_c, 'not_found_sample', to_jsonb(v_miss));
end $$;
revoke all on function public.ifs_budget_sync(jsonb) from public, anon, authenticated;
grant execute on function public.ifs_budget_sync(jsonb) to service_role;

-- ===== hub39 =====
-- v180: ดึงรายการ "สัญญาขาย" (Sale Contract) ทั้งหมดจาก IFS เข้าแอปอัตโนมัติ — สร้างรหัสใหม่ที่ยังไม่มีในตาราง contracts (รหัสที่มีอยู่แล้วไม่แตะ Budget/ชื่อที่ตั้งไว้)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub38.sql) — รันซ้ำได้
-- p_rows = [{"id":"M23030","name":"...","company":"Demco"}, ...] · เรียกได้เฉพาะ service_role · รหัสใหม่ตั้งเป็น active, Budget = 0

create or replace function public.ifs_contract_sync(p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r jsonb; v_id text; v_name text; v_co text; n_new int := 0; n_skip int := 0; v_cnt int;
begin
  for r in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    v_id := trim(r->>'id'); v_name := trim(coalesce(r->>'name', '')); v_co := case when r->>'company' = 'DP' then 'DP' else 'Demco' end;
    continue when v_id is null or v_id = '';
    insert into public.contracts (id, name, company, active, budget_hours, budget_baht, updated_by, updated_at)
    values (v_id, coalesce(nullif(v_name, ''), v_id), v_co, true, 0, 0, 'IFS', now())
    on conflict (id) do nothing;
    get diagnostics v_cnt = row_count;
    if v_cnt > 0 then n_new := n_new + 1; else n_skip := n_skip + 1; end if;
  end loop;
  return jsonb_build_object('inserted', n_new, 'already_exists', n_skip);
end $$;
revoke all on function public.ifs_contract_sync(jsonb) from public, anon, authenticated;
grant execute on function public.ifs_contract_sync(jsonb) to service_role;

-- ===== hub40 =====
-- v181: เพิ่มชื่อ/นามสกุลภาษาอังกฤษในฐานข้อมูลสมาชิก (ดึงจาก Empeo) — ต้องรันก่อนใช้ฟอร์ม/Excel ช่อง Name_EN / Surname_EN
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub39.sql) — รันซ้ำได้

alter table public.employees add column if not exists name_en text not null default '';
alter table public.employees add column if not exists surname_en text not null default '';

-- รับชุดชื่อ EN ที่ดึงจาก Empeo อัปเดตตามรหัสพนักงาน (service_role เท่านั้น) · p_rows = [{"id":"01897","first":"Chirasak","last":"Kraimuenwai"}, ...]
create or replace function public.emp_en_names_sync(p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r jsonb; v_id text; v_f text; v_l text; n_upd int := 0; n_same int := 0; v_cnt int; v_miss text[] := '{}';
begin
  for r in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    v_id := trim(r->>'id'); v_f := trim(coalesce(r->>'first', '')); v_l := trim(coalesce(r->>'last', ''));
    continue when v_id is null or v_id = '';
    update public.employees set name_en = v_f, surname_en = v_l where id = v_id and (name_en is distinct from v_f or surname_en is distinct from v_l);
    get diagnostics v_cnt = row_count;
    if v_cnt > 0 then n_upd := n_upd + v_cnt;
    elsif exists (select 1 from public.employees where id = v_id) then n_same := n_same + 1;
    elsif array_length(v_miss, 1) is distinct from 40 then v_miss := v_miss || v_id; end if;
  end loop;
  return jsonb_build_object('updated', n_upd, 'unchanged', n_same, 'not_in_members_sample', to_jsonb(v_miss));
end $$;
revoke all on function public.emp_en_names_sync(jsonb) from public, anon, authenticated;
grant execute on function public.emp_en_names_sync(jsonb) to service_role;

-- ===== hub41 =====
-- v187: นำเข้าข้อมูลจากไฟล์ IFS (DataIFS_TimeSheet.xlsx) 2 ชีต ทุกคอลัมน์ ที่เมนู "ตั้งค่าข้อมูล" — ชีต "Project Summary" และ "Sale Contract"
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub40.sql) — รันซ้ำได้
-- เก็บข้อมูลดิบทุกคอลัมน์ไว้ดู/ค้นในแอป (เฉพาะ Super Admin เพราะมียอดเงิน) และพร้อมกันนั้น: (1) อัปเดต Budget (บาท) ของโครงการ = ผลรวม BUDGET_COST ต่อรหัส  (2) เพิ่มสัญญาขายใหม่ (รหัสที่มีอยู่แล้วไม่แตะ)

create table if not exists public.ifs_sheets (
  sheet text primary key, cols jsonb not null default '[]'::jsonb, row_count int not null default 0,
  imported_at timestamptz not null default now(), imported_by text not null default ''
);
create table if not exists public.ifs_rows (
  sheet text not null references public.ifs_sheets(sheet) on delete cascade, row_no int not null, data jsonb not null,
  primary key (sheet, row_no)
);
alter table public.ifs_sheets enable row level security;
alter table public.ifs_rows enable row level security;
drop policy if exists ifs_sheets_sel on public.ifs_sheets; create policy ifs_sheets_sel on public.ifs_sheets for select to authenticated using (public.is_super_admin());
drop policy if exists ifs_rows_sel on public.ifs_rows;     create policy ifs_rows_sel   on public.ifs_rows   for select to authenticated using (public.is_super_admin());

create or replace function public.ifs_import(p_sheet text, p_cols jsonb, p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; v_up int := 0; v_new int := 0; v_by text := coalesce(public.my_emp_id(), 'IFS-script');
begin
  if coalesce(auth.role(), '') <> 'service_role' and not public.is_super_admin() then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะ Super Admin'; end if;
  if p_sheet not in ('Project Summary', 'Sale Contract') then raise exception 'BAD_SHEET:รองรับเฉพาะชีต Project Summary และ Sale Contract'; end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลในชีต'; end if;
  insert into public.ifs_sheets (sheet, cols, row_count, imported_at, imported_by) values (p_sheet, coalesce(p_cols, '[]'::jsonb), 0, now(), v_by)
  on conflict (sheet) do update set cols = excluded.cols, imported_at = now(), imported_by = v_by;
  delete from public.ifs_rows where sheet = p_sheet;
  insert into public.ifs_rows (sheet, row_no, data) select p_sheet, (t.ord)::int, t.e from jsonb_array_elements(p_rows) with ordinality as t(e, ord);
  get diagnostics n = row_count;
  update public.ifs_sheets set row_count = n where sheet = p_sheet;
  if p_sheet = 'Project Summary' then
    update public.projects p set budget_baht = s.b, updated_by = 'IFS', updated_at = now()
      from (select trim(data->>'PROJECT_ID/CONTRACT') as id, sum(nullif(trim(data->>'BUDGET_COST'), '')::numeric) as b
              from public.ifs_rows where sheet = 'Project Summary' group by 1) s
     where p.id = s.id and s.b is not null and p.budget_baht is distinct from s.b;
    get diagnostics v_up = row_count;
  else
    insert into public.contracts (id, name, company, active, budget_hours, budget_baht, updated_by, updated_at)
    select x.id, coalesce(nullif(x.nm, ''), x.id), case when x.co = 'DP' then 'DP' else 'Demco' end, true, 0, 0, 'IFS', now()
      from (select distinct on (trim(data->>'PROJECT_ID/CONTRACT')) trim(data->>'PROJECT_ID/CONTRACT') as id,
                   trim(coalesce(nullif(data->>'NAME', ''), data->>'Short Name', '')) as nm, trim(coalesce(data->>'COMPANY', '')) as co
              from public.ifs_rows where sheet = 'Sale Contract' and trim(coalesce(data->>'PROJECT_ID/CONTRACT', '')) <> ''
             order by trim(data->>'PROJECT_ID/CONTRACT'), row_no) x
    on conflict (id) do nothing;
    get diagnostics v_new = row_count;
  end if;
  return jsonb_build_object('rows', n, 'projects_updated', v_up, 'contracts_added', v_new);
end $$;
revoke all on function public.ifs_import(text, jsonb, jsonb) from public, anon;
grant execute on function public.ifs_import(text, jsonb, jsonb) to authenticated, service_role;

-- ===== hub42 =====
-- v188: นำเข้าเฉพาะ 2 ชีตของไฟล์ IFS (DataIFS_TimeSheet.xlsx) ทุกฟิลด์ — "Sale & Project" และ "Project Admin" ที่เมนู "ตั้งค่าข้อมูล"
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub41.sql) — รันซ้ำได้
-- เก็บข้อมูลดิบทุกคอลัมน์ทุกแถวไว้ดู/ค้นในแอป (เฉพาะ Super Admin) · ไม่แตะ Budget/สัญญาขายในตาราง projects / contracts · ลบข้อมูลดิบของชีต Project Summary / Sale Contract ที่เคยนำเข้ารอบก่อนออก

delete from public.ifs_sheets where sheet in ('Project Summary', 'Sale Contract');   -- ifs_rows ถูกลบตามอัตโนมัติ (cascade)

create or replace function public.ifs_import(p_sheet text, p_cols jsonb, p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; v_by text := coalesce(public.my_emp_id(), 'IFS-script');
begin
  if coalesce(auth.role(), '') <> 'service_role' and not public.is_super_admin() then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะ Super Admin'; end if;
  if p_sheet not in ('Sale & Project', 'Project Admin') then raise exception 'BAD_SHEET:รองรับเฉพาะชีต Sale & Project และ Project Admin'; end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลในชีต'; end if;
  insert into public.ifs_sheets (sheet, cols, row_count, imported_at, imported_by) values (p_sheet, coalesce(p_cols, '[]'::jsonb), 0, now(), v_by)
  on conflict (sheet) do update set cols = excluded.cols, imported_at = now(), imported_by = v_by;
  delete from public.ifs_rows where sheet = p_sheet;
  insert into public.ifs_rows (sheet, row_no, data) select p_sheet, (t.ord)::int, t.e from jsonb_array_elements(p_rows) with ordinality as t(e, ord);
  get diagnostics n = row_count;
  update public.ifs_sheets set row_count = n where sheet = p_sheet;
  return jsonb_build_object('rows', n);
end $$;
revoke all on function public.ifs_import(text, jsonb, jsonb) from public, anon;
grant execute on function public.ifs_import(text, jsonb, jsonb) to authenticated, service_role;

-- ===== hub43 =====
-- v189: Auto assign พนักงานจากชีต "Project Admin" (คอลัมน์ Admin = "รหัสพนักงาน ชื่อ") ให้เป็นผู้ได้รับ assign ของโครงการ/สัญญานั้นอัตโนมัติ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub42.sql) — รันซ้ำได้
-- กติกา: เพิ่มเฉพาะคู่ (พนักงาน, รหัส) ที่ยังไม่มี — ไม่ลบ/ไม่แก้ assign เดิม · ข้ามถ้าไม่พบรหัสพนักงานในสมาชิก หรือไม่พบรหัสโครงการ/สัญญาในระบบ
-- ทำงานอัตโนมัติทุกครั้งที่นำเข้าชีต Project Admin และกดทำซ้ำได้ที่ปุ่ม "Assign อัตโนมัติ" ในการ์ดนำเข้า IFS

create or replace function public.ifs_assign_admins() returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record; n_ins int := 0; n_have int := 0; n_nomem int := 0; n_noproj int := 0; v_cnt int;
begin
  if coalesce(auth.role(), '') <> 'service_role' and not public.is_super_admin() then raise exception 'FORBIDDEN:ทำได้เฉพาะ Super Admin'; end if;
  for r in select distinct substring(trim(coalesce(data->>'Admin', '')) from '^(\d+)') as emp, trim(coalesce(data->>'Project ID', '')) as code
             from public.ifs_rows where sheet = 'Project Admin' loop
    continue when r.emp is null or r.code = '';
    if not exists (select 1 from public.employees where id = r.emp) then n_nomem := n_nomem + 1; continue; end if;
    if not exists (select 1 from public.projects where id = r.code) and not exists (select 1 from public.contracts where id = r.code) then n_noproj := n_noproj + 1; continue; end if;
    insert into public.assignments (emp_id, code) values (r.emp, r.code) on conflict do nothing;
    get diagnostics v_cnt = row_count;
    if v_cnt > 0 then n_ins := n_ins + 1; else n_have := n_have + 1; end if;
  end loop;
  return jsonb_build_object('added', n_ins, 'already', n_have, 'no_member', n_nomem, 'no_project', n_noproj);
end $$;
revoke all on function public.ifs_assign_admins() from public, anon;
grant execute on function public.ifs_assign_admins() to authenticated, service_role;

create or replace function public.ifs_import(p_sheet text, p_cols jsonb, p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; v_by text := coalesce(public.my_emp_id(), 'IFS-script'); v_asg jsonb := null;
begin
  if coalesce(auth.role(), '') <> 'service_role' and not public.is_super_admin() then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะ Super Admin'; end if;
  if p_sheet not in ('Sale & Project', 'Project Admin') then raise exception 'BAD_SHEET:รองรับเฉพาะชีต Sale & Project และ Project Admin'; end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลในชีต'; end if;
  insert into public.ifs_sheets (sheet, cols, row_count, imported_at, imported_by) values (p_sheet, coalesce(p_cols, '[]'::jsonb), 0, now(), v_by)
  on conflict (sheet) do update set cols = excluded.cols, imported_at = now(), imported_by = v_by;
  delete from public.ifs_rows where sheet = p_sheet;
  insert into public.ifs_rows (sheet, row_no, data) select p_sheet, (t.ord)::int, t.e from jsonb_array_elements(p_rows) with ordinality as t(e, ord);
  get diagnostics n = row_count;
  update public.ifs_sheets set row_count = n where sheet = p_sheet;
  if p_sheet = 'Project Admin' then v_asg := public.ifs_assign_admins(); end if;   -- auto assign ตามคอลัมน์ Admin
  return jsonb_build_object('rows', n, 'assign', v_asg);
end $$;
revoke all on function public.ifs_import(text, jsonb, jsonb) from public, anon;
grant execute on function public.ifs_import(text, jsonb, jsonb) to authenticated, service_role;

-- ===== hub44 =====
-- v190: เพิ่มฟิลด์ Short Name จากการนำเข้า IFS ไว้กับรหัสโครงการ/สัญญา — มองเห็นได้เฉพาะ "ผู้อนุมัติ" (ตั้งแต่ธุรการขึ้นไป ที่มีขั้นอนุมัติ) และผู้ดูแลระบบ พนักงานทั่วไปมองไม่เห็นและอ่านจากฐานข้อมูลไม่ได้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub43.sql) — รันซ้ำได้
-- ที่มา: ชีต "Sale & Project" (คอลัมน์ Short Name) เป็นหลัก ถ้าไม่มีใช้ชีต "Project Admin" · อัปเดตอัตโนมัติทุกครั้งที่นำเข้า IFS

create table if not exists public.ifs_short_names (
  code text primary key, short_name text not null default '', updated_at timestamptz not null default now()
);
alter table public.ifs_short_names enable row level security;

-- ผู้อนุมัติ = ผู้ดูแลระบบ หรือผู้ที่มีสิทธิ์อนุมัติ (approver_scopes) ใน Role ที่มีขั้นอนุมัติ (approval_perms เป็นเลขขั้น 1-6)
create or replace function public.can_see_short_name() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin() or public.is_super_admin() or exists (
    select 1 from public.approver_scopes s
     where s.emp_id = public.my_emp_id()
       and exists (select 1 from public.approval_perms p where p.role = s.role and p.perm ~ '^[1-6]$'))
$$;
revoke all on function public.can_see_short_name() from public, anon;
grant execute on function public.can_see_short_name() to authenticated;
drop policy if exists ifs_sn_sel on public.ifs_short_names;
create policy ifs_sn_sel on public.ifs_short_names for select to authenticated using (public.can_see_short_name());

-- สร้าง/อัปเดต Short Name จากข้อมูลดิบที่นำเข้า (ใช้ภายใน)
create or replace function public.ifs_apply_short_names_int() returns int
language plpgsql security definer set search_path = public as $$
declare n int := 0;
begin
  insert into public.ifs_short_names (code, short_name, updated_at)
  select code, short_name, now() from (
    select distinct on (code) code, short_name from (
      select trim(coalesce(data->>'PROJECT_ID/CONTRACT', '')) as code, trim(coalesce(data->>'Short Name', '')) as short_name, 1 as pr
        from public.ifs_rows where sheet = 'Sale & Project'
      union all
      select trim(coalesce(data->>'Project ID', '')), trim(coalesce(data->>'Short Name', '')), 2
        from public.ifs_rows where sheet = 'Project Admin') u
     where code <> '' and short_name <> ''
     order by code, pr) x
  on conflict (code) do update set short_name = excluded.short_name, updated_at = now() where public.ifs_short_names.short_name is distinct from excluded.short_name;
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.ifs_apply_short_names_int() from public, anon, authenticated;

-- นำเข้า IFS แล้วอัปเดต Short Name + Auto Assign (ต่อจาก hub43)
create or replace function public.ifs_import(p_sheet text, p_cols jsonb, p_rows jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; v_by text := coalesce(public.my_emp_id(), 'IFS-script'); v_asg jsonb := null; v_sn int := 0;
begin
  if coalesce(auth.role(), '') <> 'service_role' and not public.is_super_admin() then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะ Super Admin'; end if;
  if p_sheet not in ('Sale & Project', 'Project Admin') then raise exception 'BAD_SHEET:รองรับเฉพาะชีต Sale & Project และ Project Admin'; end if;
  if jsonb_typeof(p_rows) <> 'array' or jsonb_array_length(p_rows) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลในชีต'; end if;
  insert into public.ifs_sheets (sheet, cols, row_count, imported_at, imported_by) values (p_sheet, coalesce(p_cols, '[]'::jsonb), 0, now(), v_by)
  on conflict (sheet) do update set cols = excluded.cols, imported_at = now(), imported_by = v_by;
  delete from public.ifs_rows where sheet = p_sheet;
  insert into public.ifs_rows (sheet, row_no, data) select p_sheet, (t.ord)::int, t.e from jsonb_array_elements(p_rows) with ordinality as t(e, ord);
  get diagnostics n = row_count;
  update public.ifs_sheets set row_count = n where sheet = p_sheet;
  v_sn := public.ifs_apply_short_names_int();
  if p_sheet = 'Project Admin' then v_asg := public.ifs_assign_admins(); end if;
  return jsonb_build_object('rows', n, 'assign', v_asg, 'short_names', v_sn);
end $$;
revoke all on function public.ifs_import(text, jsonb, jsonb) from public, anon;
grant execute on function public.ifs_import(text, jsonb, jsonb) to authenticated, service_role;

select public.ifs_apply_short_names_int() as short_names_updated;   -- เติมจากข้อมูลที่นำเข้าไว้แล้วทันที

-- ===== hub45 =====
-- v191: ให้ "ธุรการ" ที่อยู่ในชีต Project Admin (คอลัมน์ Admin) เห็น Short Name ของโครงการได้ด้วย — เดิมเห็นเฉพาะผู้ดูแลระบบและผู้มีสิทธิ์อนุมัติ (approver_scopes) ซึ่งธุรการโครงการไม่อยู่ในกลุ่มนี้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub44.sql) — รันซ้ำได้
-- ผู้เห็น = ผู้ดูแลระบบ · ผู้อนุมัติที่มีขั้นอนุมัติ · ธุรการที่อยู่ในคอลัมน์ Admin ของชีต Project Admin  |  พนักงานทั่วไปยังไม่เห็น

create or replace function public.can_see_short_name() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_admin() or public.is_super_admin()
      or exists (select 1 from public.approver_scopes s
                  where s.emp_id = public.my_emp_id()
                    and exists (select 1 from public.approval_perms p where p.role = s.role and p.perm ~ '^[1-6]$'))
      or exists (select 1 from public.ifs_rows r
                  where r.sheet = 'Project Admin'
                    and substring(trim(coalesce(r.data->>'Admin', '')) from '^(\d+)') = public.my_emp_id())
$$;
revoke all on function public.can_see_short_name() from public, anon;
grant execute on function public.can_see_short_name() to authenticated;

-- v201: เมื่อสมาชิกใหม่ได้รับการอนุมัติ ให้ผูก "รหัสฝ่าย" ของสมาชิกกับตารางชีต Project Admin (นำเข้า IFS)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub45.sql) — รันซ้ำได้
-- กติกา: เมื่อ employees.approved เปลี่ยนเป็น true (หรือเพิ่มสมาชิกที่ approved อยู่แล้ว) ระบบ assign ทุกรหัสโครงการ/สัญญา
--        ในชีต Project Admin ที่คอลัมน์ Department ตรงกับรหัสฝ่ายของสมาชิกให้อัตโนมัติ
--        เพิ่มเฉพาะคู่ (พนักงาน, รหัส) ที่ยังไม่มี · ข้ามรหัสที่ไม่มีในระบบ · ไม่ลบ/ไม่แก้ assign เดิม

create or replace function public.ifs_assign_dept(p_emp text) returns int
language plpgsql security definer set search_path = public as $$
declare v_dept text; v_n int := 0;
begin
  select trim(coalesce(dept, '')) into v_dept from public.employees where id = p_emp;
  if v_dept is null or v_dept = '' then return 0; end if;
  insert into public.assignments (emp_id, code)
  select distinct p_emp, trim(r.data->>'Project ID')
    from public.ifs_rows r
   where r.sheet = 'Project Admin'
     and trim(coalesce(r.data->>'Department', '')) = v_dept
     and trim(coalesce(r.data->>'Project ID', '')) <> ''
     and (exists (select 1 from public.projects p where p.id = trim(r.data->>'Project ID'))
          or exists (select 1 from public.contracts c where c.id = trim(r.data->>'Project ID')))
  on conflict do nothing;
  get diagnostics v_n = row_count;
  return v_n;
end $$;
revoke all on function public.ifs_assign_dept(text) from public, anon;
grant execute on function public.ifs_assign_dept(text) to service_role;

create or replace function public.trg_emp_approved_assign() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.approved is true and (tg_op = 'INSERT' or old.approved is distinct from true) then
    perform public.ifs_assign_dept(new.id);
  end if;
  return new;
end $$;

drop trigger if exists emp_approved_assign on public.employees;
create trigger emp_approved_assign after insert or update of approved on public.employees
  for each row execute function public.trg_emp_approved_assign();

-- v204: โครงการ/สัญญาที่มี Short Name หลายค่า (เช่น CSP2601 มี .80010 / .80020 / .80030) — เก็บทุกค่าไว้ให้ "ธุรการ" เลือกตอนอนุมัติ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub46.sql) — รันซ้ำได้
-- ตารางใหม่ ifs_short_name_opts (code, short_name) มองเห็นเฉพาะผู้อนุมัติ/ผู้ดูแลระบบ เหมือน ifs_short_names · ค่าที่ธุรการเลือกเก็บไว้กับรายการอนุมัติ (ไม่ต้องเพิ่มคอลัมน์)

create table if not exists public.ifs_short_name_opts (
  code text not null, short_name text not null, primary key (code, short_name)
);
alter table public.ifs_short_name_opts enable row level security;
drop policy if exists ifs_sno_sel on public.ifs_short_name_opts;
create policy ifs_sno_sel on public.ifs_short_name_opts for select to authenticated using (public.can_see_short_name());

create or replace function public.ifs_apply_short_name_opts_int() returns int
language plpgsql security definer set search_path = public as $$
declare n int := 0;
begin
  delete from public.ifs_short_name_opts where true;
  insert into public.ifs_short_name_opts (code, short_name)
  select distinct code, short_name from (
    select trim(coalesce(data->>'PROJECT_ID/CONTRACT', '')) as code, trim(coalesce(data->>'Short Name', '')) as short_name
      from public.ifs_rows where sheet = 'Sale & Project'
    union all
    select trim(coalesce(data->>'Project ID', '')), trim(coalesce(data->>'Short Name', ''))
      from public.ifs_rows where sheet = 'Project Admin') u
   where code <> '' and short_name <> '';
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.ifs_apply_short_name_opts_int() from public, anon, authenticated;

-- ทุกครั้งที่นำเข้า IFS ให้อัปเดตตัวเลือก Short Name ด้วย (ต่อจาก ifs_apply_short_names_int ของ hub44)
create or replace function public.ifs_apply_short_names_int() returns int
language plpgsql security definer set search_path = public as $$
declare n int := 0;
begin
  insert into public.ifs_short_names (code, short_name, updated_at)
  select code, short_name, now() from (
    select distinct on (code) code, short_name from (
      select trim(coalesce(data->>'PROJECT_ID/CONTRACT', '')) as code, trim(coalesce(data->>'Short Name', '')) as short_name, 1 as pr
        from public.ifs_rows where sheet = 'Sale & Project'
      union all
      select trim(coalesce(data->>'Project ID', '')), trim(coalesce(data->>'Short Name', '')), 2
        from public.ifs_rows where sheet = 'Project Admin') u
     where code <> '' and short_name <> ''
     order by code, pr, short_name) x
  on conflict (code) do update set short_name = excluded.short_name, updated_at = now() where public.ifs_short_names.short_name is distinct from excluded.short_name;
  get diagnostics n = row_count;
  perform public.ifs_apply_short_name_opts_int();
  return n;
end $$;
revoke all on function public.ifs_apply_short_names_int() from public, anon, authenticated;

select public.ifs_apply_short_name_opts_int() as short_name_options;   -- เติมจากข้อมูลที่นำเข้าไว้แล้วทันที
select count(*) as codes_with_multiple from (select code from public.ifs_short_name_opts group by code having count(*) > 1) q;

-- v206: ตารางกำหนดสิทธิ์การเข้าถึงโมดูล (เช่น Promotion) รายพนักงาน
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub47.sql) — รันซ้ำได้
-- กติกา: Super Admin เข้าได้ทุกโมดูลเสมอ · คนอื่นเข้าได้เมื่อมีแถวในตารางนี้ (perm: view = ดู, manage = จัดการ/เสนอชื่อ)
--        อ่านได้เฉพาะแถวของตัวเอง (Super Admin อ่านได้ทั้งหมด) · เพิ่ม/แก้/ลบ ได้เฉพาะ Super Admin

create table if not exists public.module_access (
  module     text not null,
  emp_id     text not null,
  perm       text not null default 'view' check (perm in ('view', 'manage')),
  granted_by text not null default '',
  granted_at timestamptz not null default now(),
  primary key (module, emp_id)
);
alter table public.module_access enable row level security;

drop policy if exists ma_sel on public.module_access;
create policy ma_sel on public.module_access for select to authenticated
  using (public.is_super_admin() or emp_id = public.my_emp_id());
drop policy if exists ma_ins on public.module_access;
create policy ma_ins on public.module_access for insert to authenticated with check (public.is_super_admin());
drop policy if exists ma_upd on public.module_access;
create policy ma_upd on public.module_access for update to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
drop policy if exists ma_del on public.module_access;
create policy ma_del on public.module_access for delete to authenticated using (public.is_super_admin());
revoke all on public.module_access from anon;
grant select, insert, update, delete on public.module_access to authenticated;

-- v207: ย้ายข้อมูลโมดูล Promotion (เสนอชื่อปรับตำแหน่ง) ขึ้น Supabase พร้อมคุมสิทธิ์ด้วยตาราง module_access
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub48.sql) — รันซ้ำได้
-- สิทธิ์: Super Admin หรือผู้ที่มีแถว module='promo' ใน module_access · view = อ่านอย่างเดียว · manage = นำเข้า/เสนอชื่อ/แก้ไข/ลบ
-- ข้อมูลพนักงาน (เกรด การศึกษา ประวัติ) อยู่ในตาราง promo_employees — คนที่ไม่มีสิทธิ์อ่านไม่ได้ (RLS) แม้จะรู้ที่อยู่ฐานข้อมูล

create or replace function public.can_promo(p_need text default 'view') returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (
    select 1 from public.module_access m
     where m.module = 'promo' and m.emp_id = public.my_emp_id() and (p_need = 'view' or m.perm = 'manage'))
$$;
revoke all on function public.can_promo(text) from public, anon;
grant execute on function public.can_promo(text) to authenticated;

create table if not exists public.promo_employees (
  emp_id text primary key, level int not null default 0, dept text not null default '',
  data jsonb not null, updated_at timestamptz not null default now()
);
create table if not exists public.promo_reqs (
  level int primary key, data jsonb not null, updated_at timestamptz not null default now()
);
create table if not exists public.promo_nominations (
  id text primary key, emp_id text not null, status text not null default 'ร่าง', data jsonb not null,
  created_by text not null default '', created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create unique index if not exists promo_nom_one_active on public.promo_nominations (emp_id) where status not in ('ยกเลิก', 'ไม่ผ่านการพิจารณา');
create table if not exists public.promo_config (
  k text primary key, data jsonb not null, updated_at timestamptz not null default now()
);

do $$ declare t text; begin
  foreach t in array array['promo_employees', 'promo_reqs', 'promo_nominations', 'promo_config'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists %I on public.%I', t || '_sel', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.can_promo(''view''))', t || '_sel', t);
    execute format('drop policy if exists %I on public.%I', t || '_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.can_promo(''manage''))', t || '_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.can_promo(''manage'')) with check (public.can_promo(''manage''))', t || '_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_del', t);
    execute format('create policy %I on public.%I for delete to authenticated using (public.can_promo(''manage''))', t || '_del', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
  end loop;
end $$;

-- นำเข้าจาก Excel ทีเดียว: แทนที่รายชื่อพนักงานทั้งหมด (+ข้อกำหนดตำแหน่งถ้ามี) — รายการเสนอชื่อเดิมไม่ถูกแตะ
create or replace function public.promo_import(p_emps jsonb, p_reqs jsonb default '[]'::jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; m int := 0;
begin
  if not public.can_promo('manage') then raise exception 'FORBIDDEN:ไม่มีสิทธิ์จัดการโมดูล Promotion'; end if;
  if jsonb_typeof(p_emps) <> 'array' or jsonb_array_length(p_emps) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลพนักงาน'; end if;
  delete from public.promo_employees where true;   -- ต้องมี WHERE (Supabase เปิด safe-update)
  insert into public.promo_employees (emp_id, level, dept, data)
  select e->>'id', coalesce((e->>'level')::int, 0), coalesce(e->>'dept', ''), e from jsonb_array_elements(p_emps) e where coalesce(e->>'id', '') <> ''
  on conflict (emp_id) do update set level = excluded.level, dept = excluded.dept, data = excluded.data, updated_at = now();
  get diagnostics n = row_count;
  if jsonb_typeof(p_reqs) = 'array' and jsonb_array_length(p_reqs) > 0 then
    delete from public.promo_reqs where true;
    insert into public.promo_reqs (level, data) select (r->>'level')::int, r from jsonb_array_elements(p_reqs) r
    on conflict (level) do update set data = excluded.data, updated_at = now();
    get diagnostics m = row_count;
  end if;
  return jsonb_build_object('employees', n, 'reqs', m);
end $$;
revoke all on function public.promo_import(jsonb, jsonb) from public, anon;
grant execute on function public.promo_import(jsonb, jsonb) to authenticated;

-- v216: กำหนดขอบเขตการเข้าถึงฐานข้อมูลพนักงานของโมดูล Promotion รายผู้ใช้ (ทั้งหมด / รายกลุ่มงาน / รายสายงาน / รายฝ่าย)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub49.sql + hub49_fix) — รันซ้ำได้
-- กติกา: Super Admin และผู้ที่ขอบเขต = ทั้งหมด เห็น/จัดการได้ทุกคน · ขอบเขตจำกัด = เห็นเฉพาะพนักงานในกลุ่มงาน/สายงาน/ฝ่ายที่กำหนด (รวมรายการเสนอชื่อและประวัติจากประกาศของคนเหล่านั้น)
--        นำเข้า Excel/ประกาศ และแก้เกณฑ์ ทำได้เฉพาะผู้ที่ขอบเขต = ทั้งหมด (สิทธิ์จัดการ)

alter table public.module_access add column if not exists scope jsonb not null default '{"type":"all"}'::jsonb;   -- {"type":"all"} | {"type":"group|line|dept","keys":["60000",...]}
alter table public.promo_employees add column if not exists group_code text not null default '';
alter table public.promo_employees add column if not exists line_code text not null default '';
alter table public.promo_employees add column if not exists dept_code text not null default '';
update public.promo_employees set group_code = coalesce(data->>'groupCode', ''), line_code = coalesce(data->>'lineCode', ''), dept_code = coalesce(data->>'deptCode', '') where true;

create or replace function public.promo_scope_all() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (select 1 from public.module_access m
    where m.module = 'promo' and m.emp_id = public.my_emp_id() and coalesce(m.scope->>'type', 'all') = 'all')
$$;
create or replace function public.promo_in_scope(g text, l text, d text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (select 1 from public.module_access m
    where m.module = 'promo' and m.emp_id = public.my_emp_id() and (
      coalesce(m.scope->>'type', 'all') = 'all'
      or (m.scope->>'type' = 'group' and jsonb_exists(m.scope->'keys', coalesce(g, '')))
      or (m.scope->>'type' = 'line'  and jsonb_exists(m.scope->'keys', coalesce(l, '')))
      or (m.scope->>'type' = 'dept'  and jsonb_exists(m.scope->'keys', coalesce(d, '')))))
$$;
create or replace function public.promo_emp_in_scope(p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.promo_scope_all() or exists (select 1 from public.promo_employees e
    where e.emp_id = p_emp and public.promo_in_scope(e.group_code, e.line_code, e.dept_code))
$$;
revoke all on function public.promo_scope_all() from public, anon;
revoke all on function public.promo_in_scope(text, text, text) from public, anon;
revoke all on function public.promo_emp_in_scope(text) from public, anon;
grant execute on function public.promo_scope_all() to authenticated;
grant execute on function public.promo_in_scope(text, text, text) to authenticated;
grant execute on function public.promo_emp_in_scope(text) to authenticated;

-- นโยบายใหม่ (แทนของ hub49)
drop policy if exists promo_employees_sel on public.promo_employees;
create policy promo_employees_sel on public.promo_employees for select to authenticated
  using (public.can_promo('view') and public.promo_in_scope(group_code, line_code, dept_code));
drop policy if exists promo_nominations_sel on public.promo_nominations;
create policy promo_nominations_sel on public.promo_nominations for select to authenticated
  using (public.can_promo('view') and public.promo_emp_in_scope(emp_id));
drop policy if exists promo_nominations_ins on public.promo_nominations;
create policy promo_nominations_ins on public.promo_nominations for insert to authenticated
  with check (public.can_promo('manage') and public.promo_emp_in_scope(emp_id));
drop policy if exists promo_nominations_upd on public.promo_nominations;
create policy promo_nominations_upd on public.promo_nominations for update to authenticated
  using (public.can_promo('manage') and public.promo_emp_in_scope(emp_id)) with check (public.can_promo('manage') and public.promo_emp_in_scope(emp_id));
drop policy if exists promo_nominations_del on public.promo_nominations;
create policy promo_nominations_del on public.promo_nominations for delete to authenticated
  using (public.can_promo('manage') and public.promo_emp_in_scope(emp_id));
do $$ declare t text; begin
  foreach t in array array['promo_employees', 'promo_reqs', 'promo_config'] loop
    execute format('drop policy if exists %I on public.%I', t || '_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.can_promo(''manage'') and public.promo_scope_all())', t || '_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.can_promo(''manage'') and public.promo_scope_all()) with check (public.can_promo(''manage'') and public.promo_scope_all())', t || '_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_del', t);
    execute format('create policy %I on public.%I for delete to authenticated using (public.can_promo(''manage'') and public.promo_scope_all())', t || '_del', t);
  end loop;
end $$;
drop policy if exists promo_config_sel on public.promo_config;
create policy promo_config_sel on public.promo_config for select to authenticated
  using (public.can_promo('view') and (k not like 'order:%' or public.promo_scope_all()));

-- ประวัติจากประกาศแต่งตั้ง: ส่งเฉพาะรายการของพนักงานที่อยู่ในขอบเขตของผู้เรียก
create or replace function public.promo_orders_for_me() returns jsonb
language sql stable security definer set search_path = public as $$
  select case when not public.can_promo('view') then '[]'::jsonb else coalesce((
    select jsonb_agg(jsonb_build_object('no', c.data->>'no', 'date', c.data->>'date', 'at', c.data->>'at',
      'entries', (select coalesce(jsonb_agg(en), '[]'::jsonb) from jsonb_array_elements(coalesce(c.data->'entries', '[]'::jsonb)) en where public.promo_emp_in_scope(en->>'empId'))))
    from public.promo_config c where c.k like 'order:%'), '[]'::jsonb) end
$$;
revoke all on function public.promo_orders_for_me() from public, anon;
grant execute on function public.promo_orders_for_me() to authenticated;

-- นำเข้าจาก Excel: ผู้ที่ขอบเขต = ทั้งหมดเท่านั้น · บันทึกรหัสกลุ่มงาน/สายงาน/ฝ่ายไว้ใช้กรองสิทธิ์
create or replace function public.promo_import(p_emps jsonb, p_reqs jsonb default '[]'::jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; m int := 0;
begin
  if not (public.can_promo('manage') and public.promo_scope_all()) then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะผู้ที่มีสิทธิ์จัดการและขอบเขตข้อมูลทั้งหมด'; end if;
  if jsonb_typeof(p_emps) <> 'array' or jsonb_array_length(p_emps) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลพนักงาน'; end if;
  delete from public.promo_employees where true;
  insert into public.promo_employees (emp_id, level, dept, group_code, line_code, dept_code, data)
  select e->>'id', coalesce((e->>'level')::int, 0), coalesce(e->>'dept', ''), coalesce(e->>'groupCode', ''), coalesce(e->>'lineCode', ''), coalesce(e->>'deptCode', ''), e
    from jsonb_array_elements(p_emps) e where coalesce(e->>'id', '') <> ''
  on conflict (emp_id) do update set level = excluded.level, dept = excluded.dept, group_code = excluded.group_code, line_code = excluded.line_code, dept_code = excluded.dept_code, data = excluded.data, updated_at = now();
  get diagnostics n = row_count;
  if jsonb_typeof(p_reqs) = 'array' and jsonb_array_length(p_reqs) > 0 then
    delete from public.promo_reqs where true;
    insert into public.promo_reqs (level, data) select (r->>'level')::int, r from jsonb_array_elements(p_reqs) r
    on conflict (level) do update set data = excluded.data, updated_at = now();
    get diagnostics m = row_count;
  end if;
  return jsonb_build_object('employees', n, 'reqs', m);
end $$;
revoke all on function public.promo_import(jsonb, jsonb) from public, anon;
grant execute on function public.promo_import(jsonb, jsonb) to authenticated;

select count(*) filter (where group_code <> '') as with_group, count(*) filter (where dept_code <> '') as with_dept, count(*) as total from public.promo_employees;

-- v217: Flow การอนุมัติการเสนอชื่อปรับตำแหน่ง (Promotion) — ขั้นตามลำดับ + กำหนดผู้อนุมัติแต่ละขั้น (พร้อมขอบเขตกลุ่มงาน/สายงาน/ฝ่าย)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub50.sql) — รันซ้ำได้
-- กติกา: ผู้มีสิทธิ์จัดการ "ส่งขออนุมัติ" รายการสถานะ ร่าง → ผ่านทีละขั้นตามลำดับ (ผู้อนุมัติขั้นนั้นในขอบเขตของพนักงานที่ถูกเสนอ) → ครบทุกขั้น = ผ่านการพิจารณา
--        ไม่อนุมัติ = ไม่ผ่านการพิจารณา (ต้องใส่เหตุผล) · ส่งกลับ = กลับเป็นร่างให้ผู้เสนอแก้ไข (ต้องใส่เหตุผล) · อนุมัติรายการของตัวเองไม่ได้ · Super Admin อนุมัติแทนได้ทุกขั้น
--        เปลี่ยนสถานะ/ขั้นโดยตรงไม่ได้ (มี trigger กัน) ต้องผ่านปุ่มในแอป · ทุกการดำเนินการบันทึกประวัติไว้

alter table public.promo_nominations add column if not exists step int not null default 0;   -- ขั้นที่รออนุมัติอยู่ (0 = ไม่อยู่ระหว่างอนุมัติ)

create table if not exists public.promo_flow_steps (
  step_no int primary key, name text not null, active boolean not null default true
);
insert into public.promo_flow_steps (step_no, name) values (1, 'ผู้บริหารฝ่าย / ผอ.'), (2, 'HR'), (3, 'COO'), (4, 'CEO') on conflict (step_no) do nothing;
create table if not exists public.promo_flow_approvers (
  step_no int not null references public.promo_flow_steps(step_no) on delete cascade, emp_id text not null, name text not null default '',
  scope jsonb not null default '{"type":"all"}'::jsonb, primary key (step_no, emp_id)
);
create table if not exists public.promo_nom_log (
  id bigserial primary key, nom_id text not null, step_no int, step_name text not null default '', action text not null,
  by_emp text not null default '', by_name text not null default '', note text not null default '', at timestamptz not null default now()
);
create index if not exists promo_nom_log_nom on public.promo_nom_log (nom_id, id);

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text) returns boolean
language sql immutable as $$
  select coalesce(s->>'type', 'all') = 'all'
      or (s->>'type' = 'group' and jsonb_exists(s->'keys', coalesce(g, '')))
      or (s->>'type' = 'line'  and jsonb_exists(s->'keys', coalesce(l, '')))
      or (s->>'type' = 'dept'  and jsonb_exists(s->'keys', coalesce(d, '')))
$$;
create or replace function public.promo_nom_visible(p_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.can_promo('view') and exists (select 1 from public.promo_nominations n where n.id = p_id and public.promo_emp_in_scope(n.emp_id))
$$;
revoke all on function public.promo_nom_visible(text) from public, anon;
grant execute on function public.promo_nom_visible(text) to authenticated;

alter table public.promo_flow_steps enable row level security;
alter table public.promo_flow_approvers enable row level security;
alter table public.promo_nom_log enable row level security;
do $$ declare t text; begin
  foreach t in array array['promo_flow_steps', 'promo_flow_approvers'] loop
    execute format('drop policy if exists %I on public.%I', t || '_sel', t);
    execute format('create policy %I on public.%I for select to authenticated using (public.can_promo(''view''))', t || '_sel', t);
    execute format('drop policy if exists %I on public.%I', t || '_ins', t);
    execute format('create policy %I on public.%I for insert to authenticated with check (public.is_super_admin())', t || '_ins', t);
    execute format('drop policy if exists %I on public.%I', t || '_upd', t);
    execute format('create policy %I on public.%I for update to authenticated using (public.is_super_admin()) with check (public.is_super_admin())', t || '_upd', t);
    execute format('drop policy if exists %I on public.%I', t || '_del', t);
    execute format('create policy %I on public.%I for delete to authenticated using (public.is_super_admin())', t || '_del', t);
    execute format('revoke all on public.%I from anon', t);
    execute format('grant select, insert, update, delete on public.%I to authenticated', t);
  end loop;
end $$;
drop policy if exists promo_nom_log_sel on public.promo_nom_log;
create policy promo_nom_log_sel on public.promo_nom_log for select to authenticated using (public.promo_nom_visible(nom_id));
revoke all on public.promo_nom_log from anon;
grant select on public.promo_nom_log to authenticated;

-- กันเปลี่ยนสถานะ/ขั้นโดยตรง (ยกเว้นผ่านฟังก์ชันด้านล่าง หรือ Super Admin) · ยกเลิกได้เมื่อสถานะ ร่าง/เสนอแล้ว · แก้เนื้อหาได้เฉพาะตอน ร่าง
create or replace function public.promo_nom_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(current_setting('promo.rpc', true), '') = '1' or public.is_super_admin() then return new; end if;
  if tg_op = 'INSERT' then new.status := 'ร่าง'; new.step := 0; return new; end if;
  if new.step is distinct from old.step then raise exception 'FORBIDDEN:เปลี่ยนขั้นอนุมัติโดยตรงไม่ได้'; end if;
  if new.status is distinct from old.status and not (new.status = 'ยกเลิก' and old.status in ('ร่าง', 'เสนอแล้ว')) then
    raise exception 'FORBIDDEN:เปลี่ยนสถานะโดยตรงไม่ได้ — ใช้ปุ่ม ส่งขออนุมัติ / อนุมัติ / ส่งกลับ';
  end if;
  if old.status <> 'ร่าง' and new.status = old.status and new.data is distinct from old.data then
    raise exception 'FORBIDDEN:แก้ไขได้เฉพาะรายการสถานะ ร่าง (ส่งกลับเพื่อแก้ไขก่อน)';
  end if;
  return new;
end $$;
drop trigger if exists promo_nom_guard_trg on public.promo_nominations;
create trigger promo_nom_guard_trg before insert or update on public.promo_nominations for each row execute function public.promo_nom_guard();

create or replace function public.promo_nom_log_add(p_id text, p_step int, p_sname text, p_action text, p_note text) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into public.promo_nom_log (nom_id, step_no, step_name, action, by_emp, by_name, note)
  values (p_id, p_step, coalesce(p_sname, ''), p_action, coalesce(public.my_emp_id(), ''), coalesce((select e.name from public.employees e where e.id = public.my_emp_id()), ''), coalesce(p_note, ''));
end $$;
revoke all on function public.promo_nom_log_add(text, int, text, text, text) from public, anon, authenticated;

-- ส่งขออนุมัติ (ร่าง → ขั้นแรก)
create or replace function public.promo_nom_submit(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; s public.promo_flow_steps%rowtype;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if not (public.can_promo('manage') and public.promo_emp_in_scope(n.emp_id)) then raise exception 'FORBIDDEN:ไม่มีสิทธิ์'; end if;
  if n.status <> 'ร่าง' then raise exception 'BAD_STATE:ส่งขออนุมัติได้เฉพาะรายการสถานะ ร่าง'; end if;
  select * into s from public.promo_flow_steps where active order by step_no limit 1;
  if not found then raise exception 'NO_FLOW:ยังไม่ได้กำหนดขั้นตอนอนุมัติ'; end if;
  if not exists (select 1 from public.promo_flow_approvers where step_no = s.step_no) then raise exception 'NO_APPROVER:ขั้นแรก (%) ยังไม่มีผู้อนุมัติ — ให้ Super Admin กำหนดก่อน', s.name; end if;
  perform set_config('promo.rpc', '1', true);
  update public.promo_nominations set status = 'เสนอแล้ว', step = s.step_no, updated_at = now() where id = p_id;
  perform public.promo_nom_log_add(p_id, s.step_no, s.name, 'submit', '');
  return jsonb_build_object('status', 'เสนอแล้ว', 'step', s.step_no);
end $$;
revoke all on function public.promo_nom_submit(text) from public, anon;
grant execute on function public.promo_nom_submit(text) to authenticated;

-- ตัดสินใจ: approve | reject | return
create or replace function public.promo_nom_decide(p_id text, p_action text, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; cur public.promo_flow_steps%rowtype; nx int; v_emp text := public.my_emp_id(); ok boolean;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if n.status <> 'เสนอแล้ว' or n.step <= 0 then raise exception 'BAD_STATE:รายการนี้ไม่ได้อยู่ระหว่างรออนุมัติ'; end if;
  if p_action not in ('approve', 'reject', 'return') then raise exception 'BAD_ACTION'; end if;
  if p_action in ('reject', 'return') and coalesce(trim(p_note), '') = '' then raise exception 'NOTE_REQUIRED:ต้องระบุเหตุผล'; end if;
  if v_emp is not null and v_emp = n.emp_id and not public.is_super_admin() then raise exception 'SELF:อนุมัติรายการของตัวเองไม่ได้'; end if;
  select * into cur from public.promo_flow_steps where step_no = n.step;
  ok := public.is_super_admin() or exists (select 1 from public.promo_flow_approvers a join public.promo_employees e on e.emp_id = n.emp_id
        where a.step_no = n.step and a.emp_id = v_emp and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code));
  if not ok then raise exception 'FORBIDDEN:ไม่ใช่ผู้อนุมัติขั้นนี้ของพนักงานคนนี้'; end if;
  perform set_config('promo.rpc', '1', true);
  if p_action = 'approve' then
    select min(step_no) into nx from public.promo_flow_steps where active and step_no > n.step;
    if nx is null then update public.promo_nominations set status = 'ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
    else update public.promo_nominations set step = nx, updated_at = now() where id = p_id; end if;
  elsif p_action = 'reject' then
    update public.promo_nominations set status = 'ไม่ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
  else
    update public.promo_nominations set status = 'ร่าง', step = 0, updated_at = now() where id = p_id;
  end if;
  perform public.promo_nom_log_add(p_id, n.step, cur.name, p_action, p_note);
  return (select jsonb_build_object('status', status, 'step', step) from public.promo_nominations where id = p_id);
end $$;
revoke all on function public.promo_nom_decide(text, text, text) from public, anon;
grant execute on function public.promo_nom_decide(text, text, text) to authenticated;

-- ขั้นที่ผู้เรียกเป็นผู้อนุมัติ (ไว้แสดงปุ่มอนุมัติในแอป)
create or replace function public.promo_my_approver_rows() returns table (step_no int, scope jsonb)
language sql stable security definer set search_path = public as $$
  select a.step_no, a.scope from public.promo_flow_approvers a where a.emp_id = public.my_emp_id()
$$;
revoke all on function public.promo_my_approver_rows() from public, anon;
grant execute on function public.promo_my_approver_rows() to authenticated;

select (select count(*) from public.promo_flow_steps) as steps, (select count(*) from public.promo_flow_approvers) as approvers;

-- v218: เพิ่มขอบเขต "แผนก" (ตามชื่อแผนก) ให้ขอบเขตข้อมูลและผู้อนุมัติของ Promotion (เดิมมี ทั้งหมด / กลุ่มงาน / สายงาน / ฝ่าย)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub51.sql) — รันซ้ำได้
-- scope = {"type":"all|group|line|dept|section","keys":[...]} · group/line/dept ใช้รหัส · section ใช้ชื่อแผนกตรงตามข้อมูลพนักงาน

alter table public.promo_employees add column if not exists section_name text not null default '';
update public.promo_employees set section_name = coalesce(data->>'section', '') where true;

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text, sec text) returns boolean
language sql immutable as $$
  select coalesce(s->>'type', 'all') = 'all'
      or (s->>'type' = 'group'   and jsonb_exists(s->'keys', coalesce(g, '')))
      or (s->>'type' = 'line'    and jsonb_exists(s->'keys', coalesce(l, '')))
      or (s->>'type' = 'dept'    and jsonb_exists(s->'keys', coalesce(d, '')))
      or (s->>'type' = 'section' and jsonb_exists(s->'keys', coalesce(sec, '')))
$$;
create or replace function public.promo_in_scope(g text, l text, d text, sec text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (select 1 from public.module_access m
    where m.module = 'promo' and m.emp_id = public.my_emp_id() and public.promo_scope_match(m.scope, g, l, d, sec))
$$;
revoke all on function public.promo_in_scope(text, text, text, text) from public, anon;
grant execute on function public.promo_in_scope(text, text, text, text) to authenticated;

create or replace function public.promo_emp_in_scope(p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.promo_scope_all() or exists (select 1 from public.promo_employees e
    where e.emp_id = p_emp and public.promo_in_scope(e.group_code, e.line_code, e.dept_code, e.section_name))
$$;

drop policy if exists promo_employees_sel on public.promo_employees;
create policy promo_employees_sel on public.promo_employees for select to authenticated
  using (public.can_promo('view') and public.promo_in_scope(group_code, line_code, dept_code, section_name));

create or replace function public.promo_nom_decide(p_id text, p_action text, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; cur public.promo_flow_steps%rowtype; nx int; v_emp text := public.my_emp_id(); ok boolean;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if n.status <> 'เสนอแล้ว' or n.step <= 0 then raise exception 'BAD_STATE:รายการนี้ไม่ได้อยู่ระหว่างรออนุมัติ'; end if;
  if p_action not in ('approve', 'reject', 'return') then raise exception 'BAD_ACTION'; end if;
  if p_action in ('reject', 'return') and coalesce(trim(p_note), '') = '' then raise exception 'NOTE_REQUIRED:ต้องระบุเหตุผล'; end if;
  if v_emp is not null and v_emp = n.emp_id and not public.is_super_admin() then raise exception 'SELF:อนุมัติรายการของตัวเองไม่ได้'; end if;
  select * into cur from public.promo_flow_steps where step_no = n.step;
  ok := public.is_super_admin() or exists (select 1 from public.promo_flow_approvers a join public.promo_employees e on e.emp_id = n.emp_id
        where a.step_no = n.step and a.emp_id = v_emp and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code, e.section_name));
  if not ok then raise exception 'FORBIDDEN:ไม่ใช่ผู้อนุมัติขั้นนี้ของพนักงานคนนี้'; end if;
  perform set_config('promo.rpc', '1', true);
  if p_action = 'approve' then
    select min(step_no) into nx from public.promo_flow_steps where active and step_no > n.step;
    if nx is null then update public.promo_nominations set status = 'ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
    else update public.promo_nominations set step = nx, updated_at = now() where id = p_id; end if;
  elsif p_action = 'reject' then
    update public.promo_nominations set status = 'ไม่ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
  else
    update public.promo_nominations set status = 'ร่าง', step = 0, updated_at = now() where id = p_id;
  end if;
  perform public.promo_nom_log_add(p_id, n.step, cur.name, p_action, p_note);
  return (select jsonb_build_object('status', status, 'step', step) from public.promo_nominations where id = p_id);
end $$;
revoke all on function public.promo_nom_decide(text, text, text) from public, anon;
grant execute on function public.promo_nom_decide(text, text, text) to authenticated;

create or replace function public.promo_import(p_emps jsonb, p_reqs jsonb default '[]'::jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n int := 0; m int := 0;
begin
  if not (public.can_promo('manage') and public.promo_scope_all()) then raise exception 'FORBIDDEN:นำเข้าได้เฉพาะผู้ที่มีสิทธิ์จัดการและขอบเขตข้อมูลทั้งหมด'; end if;
  if jsonb_typeof(p_emps) <> 'array' or jsonb_array_length(p_emps) = 0 then raise exception 'EMPTY:ไม่มีข้อมูลพนักงาน'; end if;
  delete from public.promo_employees where true;
  insert into public.promo_employees (emp_id, level, dept, group_code, line_code, dept_code, section_name, data)
  select e->>'id', coalesce((e->>'level')::int, 0), coalesce(e->>'dept', ''), coalesce(e->>'groupCode', ''), coalesce(e->>'lineCode', ''), coalesce(e->>'deptCode', ''), coalesce(e->>'section', ''), e
    from jsonb_array_elements(p_emps) e where coalesce(e->>'id', '') <> ''
  on conflict (emp_id) do update set level = excluded.level, dept = excluded.dept, group_code = excluded.group_code, line_code = excluded.line_code, dept_code = excluded.dept_code, section_name = excluded.section_name, data = excluded.data, updated_at = now();
  get diagnostics n = row_count;
  if jsonb_typeof(p_reqs) = 'array' and jsonb_array_length(p_reqs) > 0 then
    delete from public.promo_reqs where true;
    insert into public.promo_reqs (level, data) select (r->>'level')::int, r from jsonb_array_elements(p_reqs) r
    on conflict (level) do update set data = excluded.data, updated_at = now();
    get diagnostics m = row_count;
  end if;
  return jsonb_build_object('employees', n, 'reqs', m);
end $$;
revoke all on function public.promo_import(jsonb, jsonb) from public, anon;
grant execute on function public.promo_import(jsonb, jsonb) to authenticated;

select count(*) filter (where section_name <> '') as with_section, count(*) as total from public.promo_employees;

-- v219: ขอบเขตแบบ "หน่วยงานตามโครงสร้างองค์กร" (type = unit) — เลือกกลุ่มงาน/สายงาน/ฝ่าย จากโครงสร้างอัตรากำลังของ HR แล้วครอบคลุมทุกหน่วยย่อยภายใต้
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub52.sql) — รันซ้ำได้
-- scope = {"type":"unit","keys":["30000","31000","31001",...],"labels":["กลุ่มงานปฏิบัติการ"]} · พนักงานอยู่ในขอบเขตเมื่อรหัสกลุ่มงาน/สายงาน/ฝ่ายอย่างใดอย่างหนึ่งอยู่ใน keys

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text, sec text) returns boolean
language sql immutable as $$
  select coalesce(s->>'type', 'all') = 'all'
      or (s->>'type' = 'unit'    and (jsonb_exists(s->'keys', coalesce(g, '')) or jsonb_exists(s->'keys', coalesce(l, '')) or jsonb_exists(s->'keys', coalesce(d, ''))))
      or (s->>'type' = 'group'   and jsonb_exists(s->'keys', coalesce(g, '')))
      or (s->>'type' = 'line'    and jsonb_exists(s->'keys', coalesce(l, '')))
      or (s->>'type' = 'dept'    and jsonb_exists(s->'keys', coalesce(d, '')))
      or (s->>'type' = 'section' and jsonb_exists(s->'keys', coalesce(sec, '')))
$$;
select public.promo_scope_match('{"type":"unit","keys":["30000","31001"]}'::jsonb, '30000', '', '', '') as unit_ok_expected_true,
       public.promo_scope_match('{"type":"unit","keys":["30000"]}'::jsonb, '60000', '', '', '') as unit_other_expected_false;

-- v221: ให้ผู้อนุมัติคนเดียวถือได้หลายขอบเขตในขั้นเดียวกัน (เช่น CFO ดูแลหลายกลุ่มงาน) — เพิ่มคอลัมน์ scope_key เข้าคีย์หลักของ promo_flow_approvers
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub53.sql) — รันซ้ำได้

alter table public.promo_flow_approvers add column if not exists scope_key text not null default 'all';
update public.promo_flow_approvers
   set scope_key = case coalesce(scope->>'type', 'all') when 'all' then 'all' else (scope->>'type') || ':' || coalesce(scope->'keys'->>0, '') end
 where true;
alter table public.promo_flow_approvers drop constraint if exists promo_flow_approvers_pkey;
alter table public.promo_flow_approvers add primary key (step_no, emp_id, scope_key);

select count(*) as approvers, count(distinct scope_key) as distinct_scopes from public.promo_flow_approvers;

-- v221: Flow อนุมัติแบบเดียวกับ Role and permission ของระบบบันทึกงาน — แต่ละ Role (ขั้น) กำหนด "ขั้นที่ n / ไม่เกี่ยวข้อง" ได้ในตารางเดียว
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub54.sql) — รันซ้ำได้
-- เพิ่มคอลัมน์ ord (ลำดับอนุมัติ) ให้ promo_flow_steps · active=false = ไม่เกี่ยวข้อง · ถ้าหลาย Role ลำดับเท่ากัน เรียงตามเลข Role

alter table public.promo_flow_steps add column if not exists ord int not null default 0;
update public.promo_flow_steps set ord = step_no where ord = 0;

create or replace function public.promo_nom_submit(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; s public.promo_flow_steps%rowtype;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if not (public.can_promo('manage') and public.promo_emp_in_scope(n.emp_id)) then raise exception 'FORBIDDEN:ไม่มีสิทธิ์'; end if;
  if n.status <> 'ร่าง' then raise exception 'BAD_STATE:ส่งขออนุมัติได้เฉพาะรายการสถานะ ร่าง'; end if;
  select * into s from public.promo_flow_steps where active order by ord, step_no limit 1;
  if not found then raise exception 'NO_FLOW:ยังไม่ได้กำหนดขั้นตอนอนุมัติ'; end if;
  if not exists (select 1 from public.promo_flow_approvers where step_no = s.step_no) then raise exception 'NO_APPROVER:ขั้นแรก (%) ยังไม่มีผู้อนุมัติ — ให้ Super Admin กำหนดก่อน', s.name; end if;
  perform set_config('promo.rpc', '1', true);
  update public.promo_nominations set status = 'เสนอแล้ว', step = s.step_no, updated_at = now() where id = p_id;
  perform public.promo_nom_log_add(p_id, s.step_no, s.name, 'submit', '');
  return jsonb_build_object('status', 'เสนอแล้ว', 'step', s.step_no);
end $$;
revoke all on function public.promo_nom_submit(text) from public, anon;
grant execute on function public.promo_nom_submit(text) to authenticated;

create or replace function public.promo_nom_decide(p_id text, p_action text, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; cur public.promo_flow_steps%rowtype; nx int; v_emp text := public.my_emp_id(); ok boolean;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if n.status <> 'เสนอแล้ว' or n.step <= 0 then raise exception 'BAD_STATE:รายการนี้ไม่ได้อยู่ระหว่างรออนุมัติ'; end if;
  if p_action not in ('approve', 'reject', 'return') then raise exception 'BAD_ACTION'; end if;
  if p_action in ('reject', 'return') and coalesce(trim(p_note), '') = '' then raise exception 'NOTE_REQUIRED:ต้องระบุเหตุผล'; end if;
  if v_emp is not null and v_emp = n.emp_id and not public.is_super_admin() then raise exception 'SELF:อนุมัติรายการของตัวเองไม่ได้'; end if;
  select * into cur from public.promo_flow_steps where step_no = n.step;
  ok := public.is_super_admin() or exists (select 1 from public.promo_flow_approvers a join public.promo_employees e on e.emp_id = n.emp_id
        where a.step_no = n.step and a.emp_id = v_emp and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code, e.section_name));
  if not ok then raise exception 'FORBIDDEN:ไม่ใช่ผู้อนุมัติขั้นนี้ของพนักงานคนนี้'; end if;
  perform set_config('promo.rpc', '1', true);
  if p_action = 'approve' then
    select s.step_no into nx from public.promo_flow_steps s where s.active and (s.ord, s.step_no) > (cur.ord, cur.step_no) order by s.ord, s.step_no limit 1;
    if nx is null then update public.promo_nominations set status = 'ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
    else update public.promo_nominations set step = nx, updated_at = now() where id = p_id; end if;
  elsif p_action = 'reject' then
    update public.promo_nominations set status = 'ไม่ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
  else
    update public.promo_nominations set status = 'ร่าง', step = 0, updated_at = now() where id = p_id;
  end if;
  perform public.promo_nom_log_add(p_id, n.step, cur.name, p_action, p_note);
  return (select jsonb_build_object('status', status, 'step', step) from public.promo_nominations where id = p_id);
end $$;
revoke all on function public.promo_nom_decide(text, text, text) from public, anon;
grant execute on function public.promo_nom_decide(text, text, text) to authenticated;

select step_no, name, ord, active from public.promo_flow_steps order by ord, step_no;

-- v223: ขอบเขตระดับแผนก ใช้ "รหัสฝ่าย|ชื่อแผนก" เพื่อไม่ให้ชื่อแผนกซ้ำข้ามฝ่ายถูกนับรวมกัน (รองรับค่าเดิมที่เป็นชื่อแผนกอย่างเดียว)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub55.sql) — รันซ้ำได้

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text, sec text) returns boolean
language sql immutable as $$
  select coalesce(s->>'type', 'all') = 'all'
      or (s->>'type' = 'unit'    and (jsonb_exists(s->'keys', coalesce(g, '')) or jsonb_exists(s->'keys', coalesce(l, '')) or jsonb_exists(s->'keys', coalesce(d, ''))))
      or (s->>'type' = 'group'   and jsonb_exists(s->'keys', coalesce(g, '')))
      or (s->>'type' = 'line'    and jsonb_exists(s->'keys', coalesce(l, '')))
      or (s->>'type' = 'dept'    and jsonb_exists(s->'keys', coalesce(d, '')))
      or (s->>'type' = 'section' and (jsonb_exists(s->'keys', coalesce(d, '') || '|' || coalesce(sec, '')) or jsonb_exists(s->'keys', coalesce(sec, ''))))
$$;
select public.promo_scope_match('{"type":"section","keys":["20002|กำกับและควบคุม"]}'::jsonb, '', '', '20002', 'กำกับและควบคุม') as same_dept_expected_true,
       public.promo_scope_match('{"type":"section","keys":["20002|กำกับและควบคุม"]}'::jsonb, '', '', '43001', 'กำกับและควบคุม') as other_dept_expected_false;


-- v225: ขอบเขต "ไม่นับรวมแผนก" — ผู้อนุมัติระดับกลุ่มงาน/สายงาน/ฝ่าย ยกเว้นแผนกที่ระบุได้ (scope.exclude = ["รหัสฝ่าย|ชื่อแผนก", ...])
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub56.sql) — รันซ้ำได้

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text, sec text) returns boolean
language sql immutable as $$
  select (   coalesce(s->>'type', 'all') = 'all'
          or (s->>'type' = 'unit'    and (jsonb_exists(s->'keys', coalesce(g, '')) or jsonb_exists(s->'keys', coalesce(l, '')) or jsonb_exists(s->'keys', coalesce(d, ''))))
          or (s->>'type' = 'group'   and jsonb_exists(s->'keys', coalesce(g, '')))
          or (s->>'type' = 'line'    and jsonb_exists(s->'keys', coalesce(l, '')))
          or (s->>'type' = 'dept'    and jsonb_exists(s->'keys', coalesce(d, '')))
          or (s->>'type' = 'section' and (jsonb_exists(s->'keys', coalesce(d, '') || '|' || coalesce(sec, '')) or jsonb_exists(s->'keys', coalesce(sec, '')))))
     and not (jsonb_typeof(s->'exclude') = 'array' and jsonb_exists(s->'exclude', coalesce(d, '') || '|' || coalesce(sec, '')))
$$;
select public.promo_scope_match('{"type":"unit","keys":["43001"],"exclude":["43001|ธุรการโครงการ 2"]}'::jsonb, '30000', '43000', '43001', 'งานอื่น') as other_section_expected_true,
       public.promo_scope_match('{"type":"unit","keys":["43001"],"exclude":["43001|ธุรการโครงการ 2"]}'::jsonb, '30000', '43000', '43001', 'ธุรการโครงการ 2') as excluded_expected_false;

-- v226: หน้า login แยกของ Promotion — เข้าด้วยอีเมลบริษัท: พบอีเมลในสมาชิก → ยืนยันอีเมลผ่านลิงก์ → ตั้งรหัสผ่าน → ใช้งานตามสิทธิ์ใน module_access
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub57.sql) — รันซ้ำได้
-- ความปลอดภัย: โปรเจกต์นี้เปิด "ยืนยันอีเมลอัตโนมัติ" (mailer_autoconfirm) จึงให้ผูกบัญชีได้เฉพาะเมื่อเข้าสู่ระบบด้วยลิงก์ที่ส่งไปที่กล่องอีเมลนั้นจริง (เช็ก amr = otp)
--        บัญชีที่ผูกใหม่จะถูกสุ่มรหัสผ่านเดิมทิ้ง (กันคนที่สมัครดักด้วยอีเมลของผู้อื่น) แล้วให้เจ้าของตั้งรหัสผ่านใหม่

alter table public.employees add column if not exists promo_verified boolean not null default false;   -- ยืนยันอีเมลผ่านหน้า login Promotion แล้ว

-- รหัสพนักงานของผู้ใช้ปัจจุบันสำหรับ Promotion: บัญชีที่ Admin อนุมัติแล้ว หรือยืนยันอีเมลผ่านหน้า login Promotion แล้ว
create or replace function public.promo_emp_id() returns text
language sql stable security definer set search_path = public as $$
  select id from public.employees where user_id = auth.uid() and active and (approved or promo_verified) limit 1
$$;
revoke all on function public.promo_emp_id() from public, anon;
grant execute on function public.promo_emp_id() to authenticated;

-- ฟังก์ชันสิทธิ์ของ Promotion เปลี่ยนมาใช้ promo_emp_id()
create or replace function public.can_promo(p_need text default 'view') returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (
    select 1 from public.module_access m
     where m.module = 'promo' and m.emp_id = public.promo_emp_id() and (p_need = 'view' or m.perm = 'manage'))
$$;
create or replace function public.promo_scope_all() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (select 1 from public.module_access m
    where m.module = 'promo' and m.emp_id = public.promo_emp_id() and coalesce(m.scope->>'type', 'all') = 'all')
$$;
create or replace function public.promo_in_scope(g text, l text, d text, sec text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin() or exists (select 1 from public.module_access m
    where m.module = 'promo' and m.emp_id = public.promo_emp_id() and public.promo_scope_match(m.scope, g, l, d, sec))
$$;
create or replace function public.promo_my_approver_rows() returns table (step_no int, scope jsonb)
language sql stable security definer set search_path = public as $$
  select a.step_no, a.scope from public.promo_flow_approvers a where a.emp_id = public.promo_emp_id()
$$;
create or replace function public.promo_nom_log_add(p_id text, p_step int, p_sname text, p_action text, p_note text) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into public.promo_nom_log (nom_id, step_no, step_name, action, by_emp, by_name, note)
  values (p_id, p_step, coalesce(p_sname, ''), p_action, coalesce(public.promo_emp_id(), ''), coalesce((select e.name from public.employees e where e.id = public.promo_emp_id()), ''), coalesce(p_note, ''));
end $$;
revoke all on function public.promo_nom_log_add(text, int, text, text, text) from public, anon, authenticated;

create or replace function public.promo_nom_decide(p_id text, p_action text, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; cur public.promo_flow_steps%rowtype; nx int; v_emp text := public.promo_emp_id(); ok boolean;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if n.status <> 'เสนอแล้ว' or n.step <= 0 then raise exception 'BAD_STATE:รายการนี้ไม่ได้อยู่ระหว่างรออนุมัติ'; end if;
  if p_action not in ('approve', 'reject', 'return') then raise exception 'BAD_ACTION'; end if;
  if p_action in ('reject', 'return') and coalesce(trim(p_note), '') = '' then raise exception 'NOTE_REQUIRED:ต้องระบุเหตุผล'; end if;
  if v_emp is not null and v_emp = n.emp_id and not public.is_super_admin() then raise exception 'SELF:อนุมัติรายการของตัวเองไม่ได้'; end if;
  select * into cur from public.promo_flow_steps where step_no = n.step;
  ok := public.is_super_admin() or exists (select 1 from public.promo_flow_approvers a join public.promo_employees e on e.emp_id = n.emp_id
        where a.step_no = n.step and a.emp_id = v_emp and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code, e.section_name));
  if not ok then raise exception 'FORBIDDEN:ไม่ใช่ผู้อนุมัติขั้นนี้ของพนักงานคนนี้'; end if;
  perform set_config('promo.rpc', '1', true);
  if p_action = 'approve' then
    select s.step_no into nx from public.promo_flow_steps s where s.active and (s.ord, s.step_no) > (cur.ord, cur.step_no) order by s.ord, s.step_no limit 1;
    if nx is null then update public.promo_nominations set status = 'ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
    else update public.promo_nominations set step = nx, updated_at = now() where id = p_id; end if;
  elsif p_action = 'reject' then
    update public.promo_nominations set status = 'ไม่ผ่านการพิจารณา', step = 0, updated_at = now() where id = p_id;
  else
    update public.promo_nominations set status = 'ร่าง', step = 0, updated_at = now() where id = p_id;
  end if;
  perform public.promo_nom_log_add(p_id, n.step, cur.name, p_action, p_note);
  return (select jsonb_build_object('status', status, 'step', step) from public.promo_nominations where id = p_id);
end $$;
revoke all on function public.promo_nom_decide(text, text, text) from public, anon;
grant execute on function public.promo_nom_decide(text, text, text) to authenticated;

drop policy if exists ma_sel on public.module_access;
create policy ma_sel on public.module_access for select to authenticated
  using (public.is_super_admin() or emp_id = public.my_emp_id() or emp_id = public.promo_emp_id());

-- ตรวจอีเมลก่อนเข้าสู่ระบบ (เรียกได้ก่อน login): NOT_FOUND | NEEDS_PASSWORD (มีในสมาชิก ยังไม่มีบัญชี) | HAS_ACCOUNT
create or replace function public.promo_login_check(p_email text) returns text
language plpgsql stable security definer set search_path = public as $$
declare e public.employees%rowtype;
begin
  select * into e from public.employees where lower(trim(email)) = lower(trim(coalesce(p_email, ''))) and active limit 1;
  if not found then return 'NOT_FOUND'; end if;
  if e.user_id is not null then return 'HAS_ACCOUNT'; end if;
  return 'NEEDS_PASSWORD';
end $$;
revoke all on function public.promo_login_check(text) from public;
grant execute on function public.promo_login_check(text) to anon, authenticated;

-- ผูกบัญชีที่เพิ่งเข้าด้วยลิงก์อีเมลกับสมาชิก (ต้องเข้าด้วยลิงก์/รหัสที่ส่งทางอีเมลเท่านั้น ห้ามใช้ session จากรหัสผ่าน)
create or replace function public.promo_claim_account() returns jsonb
language plpgsql security definer set search_path = public, auth, extensions as $$
declare v_uid uuid := auth.uid(); v_email text := lower(trim(coalesce(auth.jwt()->>'email', ''))); e public.employees%rowtype; via_mail boolean;
begin
  if v_uid is null or v_email = '' then raise exception 'NOT_LOGGED_IN:ยังไม่ได้เข้าสู่ระบบ'; end if;
  select exists (select 1 from jsonb_array_elements(coalesce(auth.jwt()->'amr', '[]'::jsonb)) a where a->>'method' in ('otp', 'magiclink', 'recovery')) into via_mail;
  if not via_mail then raise exception 'NOT_VERIFIED:ต้องยืนยันด้วยลิงก์ที่ส่งไปทางอีเมลก่อน'; end if;
  select * into e from public.employees where lower(trim(email)) = v_email and active limit 1;
  if not found then raise exception 'NOT_FOUND:ไม่พบอีเมลนี้ในสมาชิก'; end if;
  if e.user_id is not null and e.user_id <> v_uid then raise exception 'TAKEN:อีเมลนี้ผูกกับบัญชีอื่นแล้ว — ติดต่อ Super Admin'; end if;
  if e.user_id is null and exists (select 1 from public.employees x where x.user_id = v_uid and x.id <> e.id) then raise exception 'TAKEN:บัญชีนี้ผูกกับสมาชิกอื่นแล้ว'; end if;
  if not e.approved and not e.promo_verified then
    update auth.users set encrypted_password = crypt(gen_random_uuid()::text, gen_salt('bf')), updated_at = now() where id = v_uid;   -- ทิ้งรหัสผ่านที่อาจถูกตั้งดักไว้ก่อน
  end if;
  update public.employees set user_id = v_uid, promo_verified = true where id = e.id;
  return jsonb_build_object('emp_id', e.id, 'name', e.name, 'fresh', not (e.approved or e.promo_verified));
end $$;
revoke all on function public.promo_claim_account() from public, anon;
grant execute on function public.promo_claim_account() to authenticated;

-- ให้สร้างบัญชีล็อกอินได้เมื่ออีเมลอยู่ในสมาชิก (หน้า login Promotion ส่งลิงก์แบบไม่มีรหัสพนักงาน) — ยังไม่ผูกอัตโนมัติ ผูกเมื่อยืนยันลิงก์ด้วย promo_claim_account เท่านั้น
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_emp text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
begin
  if v_emp is null then
    if exists (select 1 from public.employees where lower(trim(coalesce(email, ''))) = lower(trim(new.email)) and active) then return new; end if;
    raise exception 'SIGNUP_MISMATCH: อีเมลนี้ไม่มีในข้อมูลสมาชิก';
  end if;
  update public.employees set user_id = new.id, approved = false
   where lower(trim(id)) = lower(v_emp) and lower(trim(coalesce(email, ''))) = lower(trim(new.email))
     and user_id is null and active;
  if found then return new; end if;
  raise exception 'SIGNUP_MISMATCH: รหัสพนักงานและอีเมลไม่ตรงกับข้อมูลในระบบ';
end $$;

select (select count(*) from public.employees where email is not null) as members_with_email,
       (select count(*) from public.employees where user_id is not null) as with_account;

-- v227: Super Admin จัดการสมาชิก Promotion ในหน้าเดียว — ตั้ง/รีเซ็ตรหัสผ่านให้เอง (ไม่ต้องส่งอีเมล), ยืนยันสมาชิก, ระงับ/เปิดสิทธิ์
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub58.sql) — รันซ้ำได้

alter table public.employees add column if not exists promo_suspended boolean not null default false;   -- ระงับการใช้ Promotion (เก็บสิทธิ์ที่ตั้งไว้ แต่เข้าไม่ได้)

-- บัญชีที่ถูกระงับใช้ Promotion ไม่ได้
create or replace function public.promo_emp_id() returns text
language sql stable security definer set search_path = public as $$
  select id from public.employees where user_id = auth.uid() and active and not promo_suspended and (approved or promo_verified) limit 1
$$;

-- สถานะของผู้ใช้ปัจจุบัน (ไว้แสดงข้อความตอน login): OK | SUSPENDED | UNVERIFIED | NO_MEMBER
create or replace function public.promo_status() returns text
language sql stable security definer set search_path = public as $$
  select coalesce((select case when not e.active then 'NO_MEMBER' when e.promo_suspended then 'SUSPENDED' when e.approved or e.promo_verified then 'OK' else 'UNVERIFIED' end
                     from public.employees e where e.user_id = auth.uid() limit 1), 'NO_MEMBER')
$$;
revoke all on function public.promo_status() from public, anon;
grant execute on function public.promo_status() to authenticated;

-- ตั้ง/รีเซ็ตรหัสผ่านให้สมาชิก (Super Admin) · ถ้ายังไม่มีบัญชีล็อกอิน ตอบ NEEDS_CREATE ให้หน้าเว็บสร้างบัญชีแล้วเรียกซ้ำ
create or replace function public.promo_admin_set_password(p_emp text, p_password text) returns text
language plpgsql security definer set search_path = public, auth, extensions as $$
declare e public.employees%rowtype; v_uid uuid;
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  if coalesce(length(p_password), 0) < 8 or p_password !~ '[A-Za-z]' or p_password !~ '[0-9]' then raise exception 'WEAK_PASSWORD:รหัสผ่านต้องยาวอย่างน้อย 8 ตัว และมีทั้งตัวอักษรและตัวเลข'; end if;
  select * into e from public.employees where id = p_emp;
  if not found then raise exception 'NOT_FOUND:ไม่พบสมาชิก'; end if;
  if coalesce(trim(e.email), '') = '' then raise exception 'NO_EMAIL:สมาชิกยังไม่มีอีเมล'; end if;
  v_uid := e.user_id;
  if v_uid is null then select id into v_uid from auth.users where lower(email) = lower(trim(e.email)) limit 1; end if;
  if v_uid is null then return 'NEEDS_CREATE'; end if;
  if exists (select 1 from public.employees x where x.user_id = v_uid and x.id <> e.id) then raise exception 'TAKEN:บัญชีนี้ผูกกับสมาชิกอื่นอยู่'; end if;
  update auth.users set encrypted_password = crypt(p_password, gen_salt('bf')), email_confirmed_at = coalesce(email_confirmed_at, now()), updated_at = now() where id = v_uid;
  update public.employees set user_id = v_uid, promo_verified = true where id = e.id;
  return 'OK';
end $$;
revoke all on function public.promo_admin_set_password(text, text) from public, anon;
grant execute on function public.promo_admin_set_password(text, text) to authenticated;

-- ยืนยัน / ยกเลิกยืนยันสมาชิก
create or replace function public.promo_admin_verify(p_emp text, p_on boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  update public.employees set promo_verified = p_on where id = p_emp and (user_id is not null or not p_on);
  if not found then raise exception 'NO_ACCOUNT:สมาชิกยังไม่มีบัญชี — ตั้งรหัสผ่านให้ก่อน'; end if;
end $$;
revoke all on function public.promo_admin_verify(text, boolean) from public, anon;
grant execute on function public.promo_admin_verify(text, boolean) to authenticated;

-- ระงับ / เปิดสิทธิ์ใช้ Promotion (ระงับตัวเองไม่ได้)
create or replace function public.promo_admin_suspend(p_emp text, p_on boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN:เฉพาะ Super Admin'; end if;
  if p_on and exists (select 1 from public.employees where id = p_emp and user_id = auth.uid()) then raise exception 'SELF:ระงับสิทธิ์ตัวเองไม่ได้'; end if;
  update public.employees set promo_suspended = p_on where id = p_emp;
end $$;
revoke all on function public.promo_admin_suspend(text, boolean) from public, anon;
grant execute on function public.promo_admin_suspend(text, boolean) to authenticated;

select count(*) filter (where promo_suspended) as suspended, count(*) as members from public.employees;

-- v229: สิทธิ์การเห็นข้อมูลตาม Flow อนุมัติ — ผู้ที่เป็นผู้อนุมัติ (ขั้นที่ใช้งาน) เห็นข้อมูลพนักงานและรายการเสนอชื่อ "เฉพาะในขอบเขตที่ได้รับมอบ" อัตโนมัติ ไม่ต้องตั้งสิทธิ์ซ้ำ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub59.sql) — รันซ้ำได้
-- กติกา: เห็นได้ = Super Admin / มีสิทธิ์ใน module_access ตามขอบเขต / เป็นผู้อนุมัติใน Flow ตามขอบเขตที่กำหนด (ดูอย่างเดียว) · สิทธิ์จัดการ (เสนอชื่อ/นำเข้า) ยังกำหนดที่ module_access

create or replace function public.promo_is_approver() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.promo_flow_approvers a join public.promo_flow_steps s on s.step_no = a.step_no
                  where a.emp_id = public.promo_emp_id() and s.active)
$$;
revoke all on function public.promo_is_approver() from public, anon;
grant execute on function public.promo_is_approver() to authenticated;

create or replace function public.can_promo(p_need text default 'view') returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin()
      or exists (select 1 from public.module_access m
                  where m.module = 'promo' and m.emp_id = public.promo_emp_id() and (p_need = 'view' or m.perm = 'manage'))
      or (p_need = 'view' and public.promo_is_approver())
$$;

create or replace function public.promo_scope_all() returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin()
      or exists (select 1 from public.module_access m where m.module = 'promo' and m.emp_id = public.promo_emp_id() and coalesce(m.scope->>'type', 'all') = 'all')
      or exists (select 1 from public.promo_flow_approvers a join public.promo_flow_steps s on s.step_no = a.step_no
                  where a.emp_id = public.promo_emp_id() and s.active and coalesce(a.scope->>'type', 'all') = 'all')
$$;

create or replace function public.promo_in_scope(g text, l text, d text, sec text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin()
      or exists (select 1 from public.module_access m where m.module = 'promo' and m.emp_id = public.promo_emp_id() and public.promo_scope_match(m.scope, g, l, d, sec))
      or exists (select 1 from public.promo_flow_approvers a join public.promo_flow_steps s on s.step_no = a.step_no
                  where a.emp_id = public.promo_emp_id() and s.active and public.promo_scope_match(a.scope, g, l, d, sec))
$$;

select count(distinct emp_id) as approvers_who_gain_view_access from public.promo_flow_approvers;

-- v230 (แก้บั๊กสำคัญ): promo_scope_match ใน hub57 คืนค่า NULL เมื่อขอบเขตไม่มีคีย์ exclude ทำให้ทุกขอบเขต (ทั้งหมด/หน่วยงาน/แผนก) ถูกมองเป็น "ไม่อยู่ในขอบเขต"
--   ผล: ผู้ใช้ที่ไม่ใช่ Super Admin มองไม่เห็นข้อมูลพนักงาน (หน้า "ยังไม่มีข้อมูลพนักงาน") — แก้ด้วย coalesce
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub60.sql) — รันซ้ำได้

create or replace function public.promo_scope_match(s jsonb, g text, l text, d text, sec text) returns boolean
language sql immutable as $$
  select (   coalesce(s->>'type', 'all') = 'all'
          or (s->>'type' = 'unit'    and (jsonb_exists(s->'keys', coalesce(g, '')) or jsonb_exists(s->'keys', coalesce(l, '')) or jsonb_exists(s->'keys', coalesce(d, ''))))
          or (s->>'type' = 'group'   and jsonb_exists(s->'keys', coalesce(g, '')))
          or (s->>'type' = 'line'    and jsonb_exists(s->'keys', coalesce(l, '')))
          or (s->>'type' = 'dept'    and jsonb_exists(s->'keys', coalesce(d, '')))
          or (s->>'type' = 'section' and (jsonb_exists(s->'keys', coalesce(d, '') || '|' || coalesce(sec, '')) or jsonb_exists(s->'keys', coalesce(sec, '')))))
     and not coalesce(jsonb_typeof(s->'exclude') = 'array' and jsonb_exists(s->'exclude', coalesce(d, '') || '|' || coalesce(sec, '')), false)
$$;
select public.promo_scope_match('{"type":"unit","keys":["31001"]}'::jsonb, '30000', '31000', '31001', '') as unit_no_exclude_expected_true,
       public.promo_scope_match('{"type":"all"}'::jsonb, '', '', '', '') as all_expected_true,
       public.promo_scope_match('{"type":"unit","keys":["31001"]}'::jsonb, '60000', '62000', '62002', '') as other_unit_expected_false,
       public.promo_scope_match('{"type":"unit","keys":["31001"],"exclude":["31001|x"]}'::jsonb, '30000', '31000', '31001', 'x') as excluded_expected_false;

-- v231: ข้อมูลผลประเมิน Competency (Core + Managerial) รายพนักงาน — แยกตารางจากข้อมูลพนักงาน เก็บเป็นรายปี
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub61.sql) — รันซ้ำได้
-- สิทธิ์: อ่านได้เฉพาะพนักงานในขอบเขตของผู้ใช้ (เหมือนข้อมูลพนักงาน) · นำเข้า/แก้ไขได้เฉพาะผู้มีสิทธิ์จัดการและขอบเขตทั้งหมด

create table if not exists public.promo_competency (
  emp_id text not null, year int not null, data jsonb not null, updated_at timestamptz not null default now(),
  primary key (emp_id, year)
);
alter table public.promo_competency enable row level security;
drop policy if exists promo_competency_sel on public.promo_competency;
create policy promo_competency_sel on public.promo_competency for select to authenticated
  using (public.can_promo('view') and public.promo_emp_in_scope(emp_id));
drop policy if exists promo_competency_ins on public.promo_competency;
create policy promo_competency_ins on public.promo_competency for insert to authenticated
  with check (public.can_promo('manage') and public.promo_scope_all());
drop policy if exists promo_competency_upd on public.promo_competency;
create policy promo_competency_upd on public.promo_competency for update to authenticated
  using (public.can_promo('manage') and public.promo_scope_all()) with check (public.can_promo('manage') and public.promo_scope_all());
drop policy if exists promo_competency_del on public.promo_competency;
create policy promo_competency_del on public.promo_competency for delete to authenticated
  using (public.can_promo('manage') and public.promo_scope_all());
revoke all on public.promo_competency from anon;
grant select, insert, update, delete on public.promo_competency to authenticated;

select count(*) as competency_rows from public.promo_competency;

-- v232: แฟ้ม Promotion Portfolio รายการเสนอชื่อ (แบบฟอร์ม + ประเมิน Competency + Checklist หลักฐาน) และที่เก็บไฟล์เอกสารแนบ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub62.sql) — รันซ้ำได้
-- สิทธิ์: ดูได้ตามขอบเขตเหมือนรายการเสนอชื่อ · แก้ไข/อัปโหลดได้เฉพาะผู้มีสิทธิ์ "จัดการ" ที่พนักงานนั้นอยู่ในขอบเขต

create or replace function public.promo_nom_manage(p_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.can_promo('manage') and exists (select 1 from public.promo_nominations n where n.id = p_id and public.promo_emp_in_scope(n.emp_id))
$$;
revoke all on function public.promo_nom_manage(text) from public, anon;
grant execute on function public.promo_nom_manage(text) to authenticated;

create table if not exists public.promo_portfolio (
  nom_id text primary key references public.promo_nominations(id) on delete cascade,
  data jsonb not null default '{}'::jsonb, updated_at timestamptz not null default now(), updated_by text not null default ''
);
alter table public.promo_portfolio enable row level security;
drop policy if exists promo_pf_sel on public.promo_portfolio;
create policy promo_pf_sel on public.promo_portfolio for select to authenticated using (public.promo_nom_visible(nom_id));
drop policy if exists promo_pf_ins on public.promo_portfolio;
create policy promo_pf_ins on public.promo_portfolio for insert to authenticated with check (public.promo_nom_manage(nom_id));
drop policy if exists promo_pf_upd on public.promo_portfolio;
create policy promo_pf_upd on public.promo_portfolio for update to authenticated using (public.promo_nom_manage(nom_id)) with check (public.promo_nom_manage(nom_id));
drop policy if exists promo_pf_del on public.promo_portfolio;
create policy promo_pf_del on public.promo_portfolio for delete to authenticated using (public.promo_nom_manage(nom_id));
revoke all on public.promo_portfolio from anon;
grant select, insert, update, delete on public.promo_portfolio to authenticated;

-- ที่เก็บไฟล์เอกสารแนบ (ส่วนตัว ไม่เปิดสาธารณะ) · พาธไฟล์ = รหัสรายการเสนอชื่อ/ลำดับเอกสาร/ชื่อไฟล์ที่สร้างให้
insert into storage.buckets (id, name, public, file_size_limit)
values ('promo-docs', 'promo-docs', false, 10485760)
on conflict (id) do update set public = false, file_size_limit = 10485760;
drop policy if exists promo_docs_sel on storage.objects;
create policy promo_docs_sel on storage.objects for select to authenticated
  using (bucket_id = 'promo-docs' and public.promo_nom_visible((storage.foldername(name))[1]));
drop policy if exists promo_docs_ins on storage.objects;
create policy promo_docs_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'promo-docs' and public.promo_nom_manage((storage.foldername(name))[1]));
drop policy if exists promo_docs_upd on storage.objects;
create policy promo_docs_upd on storage.objects for update to authenticated
  using (bucket_id = 'promo-docs' and public.promo_nom_manage((storage.foldername(name))[1]));
drop policy if exists promo_docs_del on storage.objects;
create policy promo_docs_del on storage.objects for delete to authenticated
  using (bucket_id = 'promo-docs' and public.promo_nom_manage((storage.foldername(name))[1]));

select (select count(*) from public.promo_portfolio) as portfolios, (select count(*) from storage.buckets where id = 'promo-docs') as bucket_ready;

-- v234: ผู้อนุมัติ "ขั้นแรก" ใน Flow (เช่น ผจก.ฝ่าย / ผู้บังคับบัญชาต้นสังกัด) เสนอชื่อพนักงานในขอบเขตของตนได้ — ตาม template ที่ให้ผู้บังคับบัญชาต้นสังกัดเป็นผู้เสนอ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub63.sql) — รันซ้ำได้
-- สิทธิ์เสนอชื่อ = (สิทธิ์จัดการ + พนักงานอยู่ในขอบเขต) หรือ (ผู้อนุมัติขั้นแรกที่ใช้งานอยู่ และพนักงานอยู่ในขอบเขตของผู้อนุมัติ) · ครอบคลุมรายการเสนอชื่อ แฟ้ม Portfolio และไฟล์แนบ

create or replace function public.promo_first_step() returns int
language sql stable security definer set search_path = public as $$
  select step_no from public.promo_flow_steps where active order by ord, step_no limit 1
$$;
revoke all on function public.promo_first_step() from public, anon;
grant execute on function public.promo_first_step() to authenticated;

create or replace function public.promo_can_nominate(p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin()
      or (public.can_promo('manage') and public.promo_emp_in_scope(p_emp))
      or exists (select 1 from public.promo_flow_approvers a
                   join public.promo_employees e on e.emp_id = p_emp
                  where a.emp_id = public.promo_emp_id() and a.step_no = public.promo_first_step()
                    and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code, e.section_name))
$$;
revoke all on function public.promo_can_nominate(text) from public, anon;
grant execute on function public.promo_can_nominate(text) to authenticated;

-- ผู้ใช้นี้เสนอชื่อได้หรือไม่ (ไว้แสดงปุ่มในแอป)
create or replace function public.promo_is_nominator() returns boolean
language sql stable security definer set search_path = public as $$
  select public.can_promo('manage')
      or exists (select 1 from public.promo_flow_approvers a where a.emp_id = public.promo_emp_id() and a.step_no = public.promo_first_step())
$$;
revoke all on function public.promo_is_nominator() from public, anon;
grant execute on function public.promo_is_nominator() to authenticated;

-- รายการเสนอชื่อ: เพิ่ม/แก้/ลบ ใช้สิทธิ์เสนอชื่อ
drop policy if exists promo_nominations_ins on public.promo_nominations;
create policy promo_nominations_ins on public.promo_nominations for insert to authenticated with check (public.promo_can_nominate(emp_id));
drop policy if exists promo_nominations_upd on public.promo_nominations;
create policy promo_nominations_upd on public.promo_nominations for update to authenticated
  using (public.promo_can_nominate(emp_id)) with check (public.promo_can_nominate(emp_id));
drop policy if exists promo_nominations_del on public.promo_nominations;
create policy promo_nominations_del on public.promo_nominations for delete to authenticated using (public.promo_can_nominate(emp_id));

-- แฟ้ม Portfolio / ไฟล์แนบ
create or replace function public.promo_nom_manage(p_id text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.promo_nominations n where n.id = p_id and public.promo_can_nominate(n.emp_id))
$$;

-- ส่งขออนุมัติ
create or replace function public.promo_nom_submit(p_id text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n public.promo_nominations%rowtype; s public.promo_flow_steps%rowtype;
begin
  select * into n from public.promo_nominations where id = p_id;
  if not found then raise exception 'NOT_FOUND:ไม่พบรายการ'; end if;
  if not public.promo_can_nominate(n.emp_id) then raise exception 'FORBIDDEN:ไม่มีสิทธิ์'; end if;
  if n.status <> 'ร่าง' then raise exception 'BAD_STATE:ส่งขออนุมัติได้เฉพาะรายการสถานะ ร่าง'; end if;
  select * into s from public.promo_flow_steps where active order by ord, step_no limit 1;
  if not found then raise exception 'NO_FLOW:ยังไม่ได้กำหนดขั้นตอนอนุมัติ'; end if;
  if not exists (select 1 from public.promo_flow_approvers where step_no = s.step_no) then raise exception 'NO_APPROVER:ขั้นแรก (%) ยังไม่มีผู้อนุมัติ — ให้ Super Admin กำหนดก่อน', s.name; end if;
  perform set_config('promo.rpc', '1', true);
  update public.promo_nominations set status = 'เสนอแล้ว', step = s.step_no, updated_at = now() where id = p_id;
  perform public.promo_nom_log_add(p_id, s.step_no, s.name, 'submit', '');
  return jsonb_build_object('status', 'เสนอแล้ว', 'step', s.step_no);
end $$;
revoke all on function public.promo_nom_submit(text) from public, anon;
grant execute on function public.promo_nom_submit(text) to authenticated;

select public.promo_first_step() as first_step_no;

-- v236: ผู้อนุมัติ "ทุกขั้น" ที่ใช้งานอยู่ใน Flow เสนอชื่อพนักงานในขอบเขตของตนได้ (เดิม hub64 ให้เฉพาะขั้นแรก)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub64.sql) — รันซ้ำได้

create or replace function public.promo_can_nominate(p_emp text) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_super_admin()
      or (public.can_promo('manage') and public.promo_emp_in_scope(p_emp))
      or exists (select 1 from public.promo_flow_approvers a
                   join public.promo_flow_steps s on s.step_no = a.step_no and s.active
                   join public.promo_employees e on e.emp_id = p_emp
                  where a.emp_id = public.promo_emp_id()
                    and public.promo_scope_match(a.scope, e.group_code, e.line_code, e.dept_code, e.section_name))
$$;
revoke all on function public.promo_can_nominate(text) from public, anon;
grant execute on function public.promo_can_nominate(text) to authenticated;

create or replace function public.promo_is_nominator() returns boolean
language sql stable security definer set search_path = public as $$
  select public.can_promo('manage') or public.promo_is_approver()
$$;
revoke all on function public.promo_is_nominator() from public, anon;
grant execute on function public.promo_is_nominator() to authenticated;

select count(distinct emp_id) as approvers_who_can_nominate from public.promo_flow_approvers;