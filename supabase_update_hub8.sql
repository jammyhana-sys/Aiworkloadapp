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
