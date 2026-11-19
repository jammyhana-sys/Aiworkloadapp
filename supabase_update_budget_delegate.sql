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
