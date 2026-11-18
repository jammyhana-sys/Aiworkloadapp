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
