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
