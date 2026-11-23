-- v119: ลงเวลาเข้างานได้ "วันละครั้งเดียว" — ออกงานแล้วลงเข้างานซ้ำไม่ได้ (ลืมลงเวลา/แก้ไข ให้ Super Admin ใช้เมนูแก้ไขบันทึกลงเวลา)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub14.sql) — รันซ้ำได้
-- (ลงเวลาด้วย AI-Beacon นับเฉพาะครั้งแรกของวันอยู่แล้ว)

create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int; v_st record;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in' and v_last is not null then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานได้วันละครั้งเท่านั้น (วันนี้ลงเวลาไปแล้ว) — หากต้องแก้ไขให้ติดต่อ Admin'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  -- ลงเวลาออกงานหลังทำงานครบ 8 ชม. ต้องระบุเหตุผล
  if p_kind = 'out' and coalesce(trim(p_note), '') = '' then
    select * into v_st from public.att_net_state(v_emp, v_day);
    if v_st.is_open and v_st.net_secs >= 28800 then
      raise exception 'REASON_REQUIRED:ทำงานครบ 8 ชั่วโมงแล้ว — กรุณาระบุเหตุผลที่ลงเวลาออกงาน (ช่องหมายเหตุ)';
    end if;
  end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active and public.site_applies(v_emp, w.id) order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;
