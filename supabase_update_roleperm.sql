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
