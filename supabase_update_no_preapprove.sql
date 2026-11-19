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