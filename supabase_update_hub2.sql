-- v71: ลงเวลาเข้า-ออกงานได้เฉพาะ "วันทำงาน" ตามปฏิทินของระบบ DWS (วันหยุดในตาราง holidays · เสาร์-อาทิตย์ · พนักงาน Site ที่ติ๊กทำงานวันเสาร์)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_hub.sql) — รันซ้ำได้

create or replace function public.is_work_day(p_emp text, p_day date) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.holidays h where h.day = p_day)
     and case extract(dow from p_day)::int
           when 0 then false
           when 6 then coalesce((select e.work_sat from public.employees e where e.id = p_emp), false)
           else true end
$$;
revoke all on function public.is_work_day(text, date) from public, anon;
grant execute on function public.is_work_day(text, date) to authenticated, service_role;

-- ลงเวลา: เริ่มวัน (เข้างาน) และออกนอกสถานที่ ทำได้เฉพาะวันทำงาน · ออกงาน/กลับจากนอกสถานที่ปิดรอบที่ค้างอยู่ได้เสมอ
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
  if p_kind in ('in', 'offsite_start') and not public.is_work_day(v_emp, v_day) then
    raise exception 'NOT_WORK_DAY:วันนี้ไม่ใช่วันทำงานตามปฏิทินของระบบ จึงลงเวลาไม่ได้';
  end if;
  select kind into v_last from public.attendance_logs where emp_id = v_emp and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if p_kind = 'in'            and v_last is not null and v_last <> 'out'                      then raise exception 'INVALID_SEQUENCE:ลงเวลาเข้างานไปแล้ว'; end if;
  if p_kind = 'out'           and (v_last is null or v_last = 'out')                          then raise exception 'INVALID_SEQUENCE:ยังไม่ได้ลงเวลาเข้างาน'; end if;
  if p_kind = 'out'           and v_last = 'offsite_start'                                    then raise exception 'INVALID_SEQUENCE:กรุณาบันทึกกลับจากนอกสถานที่ก่อน'; end if;
  if p_kind = 'offsite_start' and (v_last is null or v_last in ('out', 'offsite_start'))      then raise exception 'INVALID_SEQUENCE:ต้องลงเวลาเข้างานก่อน และไม่อยู่ระหว่างออกนอกสถานที่'; end if;
  if p_kind = 'offsite_end'   and (v_last is distinct from 'offsite_start')                   then raise exception 'INVALID_SEQUENCE:ยังไม่ได้บันทึกออกไปทำงานนอกสถานที่'; end if;
  if exists (select 1 from public.attendance_logs where emp_id = v_emp and kind = p_kind and at > now() - interval '30 seconds') then raise exception 'INVALID_SEQUENCE:บันทึกซ้ำเร็วเกินไป'; end if;
  if p_lat is not null and p_lng is not null then
    select w.id, w.name, public.geo_dist_m(p_lat, p_lng, w.lat, w.lng), w.radius_m into v_sid, v_sname, v_d, v_rad
      from public.work_sites w where w.active order by 3 limit 1;
  end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, accuracy_m, site_id, site_name, dist_m, source, note)
  values (v_emp, p_kind, clock_timestamp(), p_lat, p_lng, p_acc,
          case when v_sid is not null and v_d <= v_rad then v_sid end,
          case when v_sid is not null and v_d <= v_rad then v_sname else '' end,
          case when v_sid is not null then round(v_d)::int end, 'app', left(coalesce(p_note, ''), 300))
  returning * into r;
  return to_jsonb(r);
end $$;

-- AI-Beacon: ไม่ลงเวลาให้อัตโนมัติในวันที่ไม่ใช่วันทำงาน
create or replace function public.att_beacon(p_line_user text, p_hwid text, p_event text default 'enter') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; b public.beacons%rowtype; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; w public.work_sites%rowtype; r public.attendance_logs%rowtype;
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้'); end if;
  select * into b from public.beacons where hwid = p_hwid and active;
  if b.hwid is null then return jsonb_build_object('ok', false, 'msg', 'ไม่ใช่ Beacon ที่ลงทะเบียนไว้'); end if;
  if p_event <> 'enter' then return jsonb_build_object('ok', true, 'ignored', true); end if;
  if not public.is_work_day(e.id, v_day) then return jsonb_build_object('ok', true, 'ignored', true, 'nonwork', true, 'name', e.name); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if v_last is not null and v_last <> 'out' then
    return jsonb_build_object('ok', true, 'dup', true, 'name', e.name);
  end if;
  if b.site_id is not null then select * into w from public.work_sites where id = b.site_id; end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, site_id, site_name, source, note, hwid)
  values (e.id, 'in', clock_timestamp(), w.lat, w.lng, w.id, coalesce(w.name, b.name), 'beacon', 'ลงเวลาอัตโนมัติจาก Beacon ' || coalesce(nullif(b.name, ''), b.hwid), p_hwid)
  returning * into r;
  return jsonb_build_object('ok', true, 'kind', 'in', 'at', r.at, 'name', e.name, 'site', r.site_name);
end $$;

revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;
revoke all on function public.att_beacon(text, text, text) from public, anon, authenticated;
grant execute on function public.att_beacon(text, text, text) to service_role;
