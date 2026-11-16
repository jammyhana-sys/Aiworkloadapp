-- รันไฟล์นี้ใน Supabase > SQL Editor (ฐานข้อมูลที่สร้างไว้แล้ว) เพื่อเปลี่ยนเงื่อนไขการสมัคร:
-- ต้องกรอก "รหัสพนักงาน" + "อีเมล" ให้ตรงกับรายชื่อที่ Admin เพิ่มไว้ (ไม่ต้องกดลิงก์ยืนยันอีเมล)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_emp text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
begin
  update public.employees set user_id = new.id
   where id = v_emp and lower(email) = lower(new.email) and user_id is null and active;
  if not found then
    raise exception 'EMPLOYEE_NOT_MATCHED';
  end if;
  return new;
end $$;
