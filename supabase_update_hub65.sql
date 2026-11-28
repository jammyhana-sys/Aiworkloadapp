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