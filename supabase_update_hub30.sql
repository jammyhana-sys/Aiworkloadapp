-- v154: เปิดโหมดทดลอง — บันทึกชั่วโมงงานได้เต็ม 8 ชม. ทันทีหลังลงเวลาเข้างาน ไม่ต้องรอให้เวลาผ่านไปครบ
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub29.sql) — รันซ้ำได้
-- โหมดทดลอง = app_settings 'att_test' {"on": true}  (ยังต้องลงเวลาเข้างานก่อน แต่ชั่วโมงที่บันทึกได้ไม่ผูกกับเวลาที่ผ่านไป)
-- ปิดโหมดทดลองก่อนใช้งานจริง:  update public.app_settings set value = '{"on": false}'::jsonb where key = 'att_test';

insert into public.app_settings (key, value) values ('att_test', '{"on": true}'::jsonb)
on conflict (key) do update set value = '{"on": true}'::jsonb;

create or replace function public.ts_att_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare v_new numeric := 0; v_old numeric := 0; v_allow integer; v_test boolean := false;
begin
  select coalesce((value->>'on')::boolean, false) into v_test from public.app_settings where key = 'att_test';
  select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_new from jsonb_array_elements(coalesce(new.entries, '[]'::jsonb)) e;
  if tg_op = 'UPDATE' then
    select coalesce(sum(coalesce((e->>'hours')::numeric, 0)), 0) into v_old from jsonb_array_elements(coalesce(old.entries, '[]'::jsonb)) e;
  end if;
  if v_new <= v_old then return new; end if;
  if auth.uid() is null or (public.is_super_admin() and new.emp_id is distinct from public.my_emp_id()) then return new; end if;
  if not public.att_required_for(new.emp_id, new.day) then return new; end if;
  v_allow := public.att_hours_for(new.emp_id, new.day);
  if v_allow is null then
    raise exception 'NO_CLOCK_IN:ยังไม่ได้ลงเวลาเข้างานของวันที่ % — ไม่สามารถบันทึกชั่วโมงงานได้ (ลงเวลาที่ระบบลงเวลา หรือผ่าน AI-Beacon ก่อน)', to_char(new.day, 'DD/MM/YYYY');
  end if;
  if coalesce(v_test, false) then v_allow := 8; end if;   -- โหมดทดลอง: ไม่ต้องรอเวลาผ่านไปครบ
  if v_new > v_allow then
    raise exception 'HOURS_EXCEED:ชั่วโมงงานรวม % ชม. เกินชั่วโมงที่ได้จากการลงเวลา % ชม. ของวันที่ %', v_new, v_allow, to_char(new.day, 'DD/MM/YYYY');
  end if;
  return new;
end $$;