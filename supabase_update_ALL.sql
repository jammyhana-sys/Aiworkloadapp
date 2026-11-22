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
