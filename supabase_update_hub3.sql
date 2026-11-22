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
