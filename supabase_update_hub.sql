-- v70: หน้าหลักแยกระบบย่อย — (1) รหัส PIN เข้าระบบ  (2) ลงเวลาเข้า-ออกงาน/ออกนอกสถานที่ + GPS + AI-Beacon  (3) ระบบลางาน เชื่อมชั่วโมงของ Workload
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (หลัง supabase_update_budget_delegate.sql) — รันซ้ำได้
-- ตัวเลขโควตาวันลาเป็นค่าเริ่มต้นสมมติ ต้องให้ผู้รับผิดชอบ (HR) ตรวจและแก้ให้ตรงนโยบายบริษัทก่อนใช้จริง (ตั้งค่าข้อมูล › ประเภทการลา)

create extension if not exists pgcrypto with schema extensions;

-- ======================================================================
-- 1) PIN 6 หลัก (ตรวจที่ฐานข้อมูล · เก็บแบบแฮช · ผิด 5 ครั้งล็อก 15 นาที)
-- ======================================================================
create table if not exists public.user_pins (
  emp_id       text primary key references public.employees(id) on delete cascade,
  pin_hash     text not null,
  fails        int  not null default 0,
  locked_until timestamptz,
  updated_at   timestamptz not null default now()
);
alter table public.user_pins enable row level security;
revoke all on public.user_pins from anon, authenticated;     -- เข้าถึงผ่านฟังก์ชันด้านล่างเท่านั้น

create or replace function public.pin_status() returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  select * into p from public.user_pins where emp_id = v_emp;
  return jsonb_build_object('ok', true, 'has_pin', p.emp_id is not null,
    'locked_until', case when p.locked_until > now() then p.locked_until end);
end $$;

-- ตรวจ PIN (ผิดติดกัน 5 ครั้ง ล็อก 15 นาที)
create or replace function public.verify_pin(p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  select * into p from public.user_pins where emp_id = v_emp for update;
  if p.emp_id is null then return jsonb_build_object('ok', false, 'error', 'NO_PIN'); end if;
  if p.locked_until is not null and p.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'LOCKED', 'locked_until', p.locked_until);
  end if;
  if p.pin_hash = extensions.crypt(coalesce(p_pin, ''), p.pin_hash) then
    update public.user_pins set fails = 0, locked_until = null where emp_id = v_emp;
    return jsonb_build_object('ok', true);
  end if;
  update public.user_pins
     set fails = case when fails + 1 >= 5 then 0 else fails + 1 end,
         locked_until = case when fails + 1 >= 5 then now() + interval '15 minutes' end
   where emp_id = v_emp;
  select * into p from public.user_pins where emp_id = v_emp;
  return jsonb_build_object('ok', false, 'error', case when p.locked_until > now() then 'LOCKED' else 'WRONG' end,
                            'remaining', 5 - p.fails, 'locked_until', case when p.locked_until > now() then p.locked_until end);
end $$;

-- ตั้ง/เปลี่ยน PIN: (ยังไม่มี PIN) หรือ (ใส่ PIN เดิมถูก) หรือ (เพิ่งล็อกอินด้วยรหัสผ่านภายใน 5 นาที = กรณีลืม PIN)
create or replace function public.set_pin(p_new text, p_old text default null) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_emp text := public.my_emp_id(); p public.user_pins%rowtype; v_auth bigint; v_ok boolean := false;
begin
  if v_emp is null then return jsonb_build_object('ok', false, 'error', 'NO_EMPLOYEE'); end if;
  if p_new is null or p_new !~ '^\d{6}$' then return jsonb_build_object('ok', false, 'error', 'FORMAT'); end if;
  if p_new ~ '^(\d)\1{5}$' or p_new in ('123456', '654321', '012345', '123123') then return jsonb_build_object('ok', false, 'error', 'WEAK'); end if;
  select * into p from public.user_pins where emp_id = v_emp for update;
  if p.emp_id is null then v_ok := true;
  else
    if p.locked_until is not null and p.locked_until > now() then return jsonb_build_object('ok', false, 'error', 'LOCKED', 'locked_until', p.locked_until); end if;
    if p_old is not null and p.pin_hash = extensions.crypt(p_old, p.pin_hash) then v_ok := true; end if;
    if not v_ok then   -- เพิ่งยืนยันตัวตนด้วยรหัสผ่านใน 5 นาทีที่ผ่านมา (JWT amr.timestamp)
      begin v_auth := (auth.jwt() -> 'amr' -> 0 ->> 'timestamp')::bigint; exception when others then v_auth := null; end;
      if v_auth is not null and extract(epoch from now()) - v_auth <= 300 then v_ok := true; end if;
    end if;
  end if;
  if not v_ok then return jsonb_build_object('ok', false, 'error', 'PIN_REQUIRED'); end if;
  insert into public.user_pins (emp_id, pin_hash) values (v_emp, extensions.crypt(p_new, extensions.gen_salt('bf')))
  on conflict (emp_id) do update set pin_hash = excluded.pin_hash, fails = 0, locked_until = null, updated_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- Super Admin รีเซ็ต PIN ให้พนักงาน (พนักงานตั้งใหม่ตอนเข้าระบบครั้งถัดไป)
create or replace function public.admin_reset_pin(p_emp text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  delete from public.user_pins where emp_id = p_emp;
end $$;

revoke all on function public.pin_status(), public.verify_pin(text), public.set_pin(text, text), public.admin_reset_pin(text) from public, anon;
grant execute on function public.pin_status(), public.verify_pin(text), public.set_pin(text, text), public.admin_reset_pin(text) to authenticated;

-- ======================================================================
-- 2) ลงเวลาเข้า-ออกงาน / ออกไปทำงานนอกสถานที่ (GPS + AI-Beacon)
-- ======================================================================
create table if not exists public.work_sites (            -- จุดทำงาน/สำนักงาน พร้อมรัศมีที่ถือว่าอยู่ในพื้นที่
  id       text primary key,
  name     text not null,
  lat      double precision not null,
  lng      double precision not null,
  radius_m int not null default 150 check (radius_m between 20 and 5000),
  active   boolean not null default true
);
create table if not exists public.beacons (                -- อุปกรณ์ Beacon (hwid ตามที่ลงทะเบียนกับ LINE Beacon / AI-Beacon)
  hwid    text primary key,
  name    text not null default '',
  site_id text references public.work_sites(id) on delete set null,
  active  boolean not null default true
);
create table if not exists public.attendance_logs (
  id          uuid primary key default gen_random_uuid(),
  emp_id      text not null references public.employees(id) on delete cascade,
  kind        text not null check (kind in ('in', 'out', 'offsite_start', 'offsite_end')),
  at          timestamptz not null default now(),
  lat         double precision,
  lng         double precision,
  accuracy_m  real,
  site_id     text,
  site_name   text not null default '',
  dist_m      int,
  source      text not null default 'app' check (source in ('app', 'beacon', 'admin')),
  note        text not null default '',
  hwid        text
);
create index if not exists attendance_emp_at on public.attendance_logs (emp_id, at desc);

alter table public.work_sites       enable row level security;
alter table public.beacons          enable row level security;
alter table public.attendance_logs  enable row level security;
revoke all on public.work_sites, public.beacons, public.attendance_logs from anon;

drop policy if exists sites_read on public.work_sites;  create policy sites_read on public.work_sites for select to authenticated using (true);
drop policy if exists sites_super on public.work_sites; create policy sites_super on public.work_sites for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
drop policy if exists beacons_read on public.beacons;   create policy beacons_read on public.beacons for select to authenticated using (public.is_admin());
drop policy if exists beacons_super on public.beacons;  create policy beacons_super on public.beacons for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
-- บันทึกเวลาเขียนผ่านฟังก์ชันเท่านั้น · อ่านได้เฉพาะของตัวเอง และผู้ดูแลระบบ
drop policy if exists att_read on public.attendance_logs;
create policy att_read on public.attendance_logs for select to authenticated using (emp_id = public.my_emp_id() or public.is_admin());

-- ระยะห่าง (เมตร) แบบ haversine
create or replace function public.geo_dist_m(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision) returns double precision
language sql immutable as $$
  select 2 * 6371000 * asin(sqrt(power(sin(radians(lat2 - lat1) / 2), 2) + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)))
$$;

-- ลงเวลา: in / out / offsite_start / offsite_end  (ลำดับ: เริ่ม→เข้า→[ออกนอก→กลับ]→ออก · ตรวจที่ฐานข้อมูล)
create or replace function public.att_punch(p_kind text, p_lat double precision default null, p_lng double precision default null,
                                            p_acc real default null, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); v_last text; v_day date := (now() at time zone 'Asia/Bangkok')::date; r public.attendance_logs%rowtype;
  v_sid text; v_sname text; v_d double precision; v_rad int;
begin
  if v_emp is null then raise exception 'NO_EMPLOYEE'; end if;
  if p_kind not in ('in', 'out', 'offsite_start', 'offsite_end') then raise exception 'BAD_KIND'; end if;
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

-- AI-Beacon / LINE Beacon: เมื่อพนักงานเข้าใกล้ beacon ครั้งแรกของวัน = ลงเวลาเข้างานอัตโนมัติ (เรียกโดย line-webhook ด้วย service_role)
create or replace function public.att_beacon(p_line_user text, p_hwid text, p_event text default 'enter') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; b public.beacons%rowtype; v_day date := (now() at time zone 'Asia/Bangkok')::date; v_last text; w public.work_sites%rowtype; r public.attendance_logs%rowtype;
begin
  select * into e from public.employees where line_user_id = p_line_user and active and approved;
  if e.id is null then return jsonb_build_object('ok', false, 'msg', 'ไม่พบบัญชีที่ผูกกับ LINE นี้'); end if;
  select * into b from public.beacons where hwid = p_hwid and active;
  if b.hwid is null then return jsonb_build_object('ok', false, 'msg', 'ไม่ใช่ Beacon ที่ลงทะเบียนไว้'); end if;
  if p_event <> 'enter' then return jsonb_build_object('ok', true, 'ignored', true); end if;
  select kind into v_last from public.attendance_logs where emp_id = e.id and (at at time zone 'Asia/Bangkok')::date = v_day order by at desc limit 1;
  if v_last is not null and v_last <> 'out' then
    return jsonb_build_object('ok', true, 'dup', true, 'name', e.name);       -- วันนี้ลงเวลาเข้าแล้ว ไม่ซ้ำ
  end if;
  if b.site_id is not null then select * into w from public.work_sites where id = b.site_id; end if;
  insert into public.attendance_logs (emp_id, kind, at, lat, lng, site_id, site_name, source, note, hwid)
  values (e.id, 'in', clock_timestamp(), w.lat, w.lng, w.id, coalesce(w.name, b.name), 'beacon', 'ลงเวลาอัตโนมัติจาก Beacon ' || coalesce(nullif(b.name, ''), b.hwid), p_hwid)
  returning * into r;
  return jsonb_build_object('ok', true, 'kind', 'in', 'at', r.at, 'name', e.name, 'site', r.site_name);
end $$;

revoke all on function public.geo_dist_m(double precision, double precision, double precision, double precision) from public, anon;
grant execute on function public.geo_dist_m(double precision, double precision, double precision, double precision) to authenticated;
revoke all on function public.att_punch(text, double precision, double precision, real, text) from public, anon;
grant execute on function public.att_punch(text, double precision, double precision, real, text) to authenticated;
revoke all on function public.att_beacon(text, text, text) from public, anon, authenticated;
grant execute on function public.att_beacon(text, text, text) to service_role;

-- ======================================================================
-- 3) ระบบลางาน (เชื่อมกับการคำนวณชั่วโมงของ Workload: วันลาที่อนุมัติแล้วไม่ต้องบันทึกงาน / เป้าหมายลดลง)
-- ======================================================================
create table if not exists public.leave_types (
  id         text primary key,
  name       text not null,
  quota_days numeric(5,1),                 -- วันต่อปี (null = ไม่จำกัด)
  paid       boolean not null default true,
  color      text not null default '#4f6df5',
  active     boolean not null default true,
  sort       int not null default 0
);
-- ค่าเริ่มต้น (สมมติ — ให้ HR ตรวจ/แก้ตามนโยบายบริษัทและกฎหมายแรงงาน)
insert into public.leave_types (id, name, quota_days, paid, color, sort) values
  ('sick',     'ลาป่วย',        30,  true,  '#e5484d', 1),
  ('personal', 'ลากิจ',         6,   true,  '#f29b2f', 2),
  ('vacation', 'ลาพักร้อน',     6,   true,  '#14a37f', 3),
  ('maternity','ลาคลอด',        98,  true,  '#a259d9', 4),
  ('ordain',   'ลาอุปสมบท/ประกอบพิธีฮัจย์', 15, true, '#2bb3c0', 5),
  ('unpaid',   'ลาไม่รับค่าจ้าง', null, false, '#6a7a93', 6)
on conflict (id) do nothing;

create table if not exists public.leave_requests (
  id          uuid primary key default gen_random_uuid(),
  emp_id      text not null references public.employees(id) on delete cascade,
  type_id     text not null references public.leave_types(id),
  start_date  date not null,
  end_date    date not null,
  part        text not null default 'full' check (part in ('full', 'am', 'pm')),   -- ครึ่งวันใช้ได้เมื่อลาวันเดียว
  days        numeric(5,1) not null,        -- จำนวนวันทำการ (ไม่นับเสาร์-อาทิตย์/วันหยุด) คำนวณที่ฐานข้อมูล
  reason      text not null default '',
  status      text not null default 'Pending' check (status in ('Pending', 'Approved', 'Rejected', 'Cancelled')),
  decided_by  text,
  decided_at  timestamptz,
  decide_note text not null default '',
  created_at  timestamptz not null default now(),
  check (end_date >= start_date)
);
create index if not exists leave_emp on public.leave_requests (emp_id, start_date);

alter table public.leave_types    enable row level security;
alter table public.leave_requests enable row level security;
revoke all on public.leave_types, public.leave_requests from anon;
drop policy if exists lt_read on public.leave_types;  create policy lt_read on public.leave_types for select to authenticated using (true);
drop policy if exists lt_super on public.leave_types; create policy lt_super on public.leave_types for all to authenticated using (public.is_super_admin()) with check (public.is_super_admin());
-- อ่านได้: ของตัวเอง · ผู้ดูแลระบบ · ผู้อนุมัติ (ใช้คำนวณเป้าหมายชั่วโมงในรายงาน) · เขียนผ่านฟังก์ชันเท่านั้น
drop policy if exists lr_read on public.leave_requests;
create policy lr_read on public.leave_requests for select to authenticated
  using (emp_id = public.my_emp_id() or public.is_admin() or public.is_approver());

create or replace function public.leave_submit(p_type text, p_start date, p_end date, p_part text default 'full', p_reason text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare e public.employees%rowtype; lt public.leave_types%rowtype; d date; v_days numeric := 0; v_used numeric; r public.leave_requests%rowtype; v_part text := coalesce(p_part, 'full');
begin
  select * into e from public.employees where id = public.my_emp_id();
  if e.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into lt from public.leave_types where id = p_type and active;
  if lt.id is null then raise exception 'BAD_TYPE:ไม่พบประเภทการลา'; end if;
  if p_start is null or p_end is null or p_end < p_start then raise exception 'BAD_DATE:ช่วงวันที่ไม่ถูกต้อง'; end if;
  if v_part <> 'full' and p_start <> p_end then raise exception 'BAD_DATE:ลาครึ่งวันเลือกได้เฉพาะลาวันเดียว'; end if;
  for d in select generate_series(p_start::timestamp, p_end::timestamp, interval '1 day')::date loop
    if extract(dow from d) = 0 then continue; end if;
    if extract(dow from d) = 6 and not e.work_sat then continue; end if;
    if exists (select 1 from public.holidays h where h.day = d) then continue; end if;
    v_days := v_days + 1;
  end loop;
  if v_days = 0 then raise exception 'NO_WORKDAY:ช่วงที่เลือกไม่มีวันทำการ (เสาร์-อาทิตย์/วันหยุด)'; end if;
  if v_part <> 'full' then v_days := 0.5; end if;
  if exists (select 1 from public.leave_requests x where x.emp_id = e.id and x.status in ('Pending', 'Approved')
               and x.start_date <= p_end and x.end_date >= p_start
               and not (x.part <> 'full' and v_part <> 'full' and x.part <> v_part)) then
    raise exception 'OVERLAP:มีรายการลาที่ซ้อนกับช่วงวันนี้อยู่แล้ว';
  end if;
  if lt.quota_days is not null then
    select coalesce(sum(days), 0) into v_used from public.leave_requests x
     where x.emp_id = e.id and x.type_id = lt.id and x.status in ('Pending', 'Approved') and extract(year from x.start_date) = extract(year from p_start);
    if v_used + v_days > lt.quota_days then raise exception 'QUOTA:วันลา% เกินสิทธิ์ (ใช้/รออนุมัติ % จาก % วัน)', lt.name, v_used, lt.quota_days; end if;
  end if;
  insert into public.leave_requests (emp_id, type_id, start_date, end_date, part, days, reason)
  values (e.id, lt.id, p_start, p_end, v_part, v_days, left(coalesce(p_reason, ''), 500)) returning * into r;
  return to_jsonb(r);
end $$;

-- อนุมัติ/ไม่อนุมัติ: Super Admin หรือผู้อนุมัติ (Mgr / ผอ. / COO / CEO) ที่มีขอบเขตครอบคลุมพนักงาน (ฝ่าย / รายบุคคล / ทั้งบริษัท) · ห้ามอนุมัติของตัวเอง
create or replace function public.leave_decide(p_id uuid, p_approve boolean, p_note text default '') returns jsonb
language plpgsql security definer set search_path = public as $$
declare me public.employees%rowtype; r public.leave_requests%rowtype; o public.employees%rowtype; v_ok boolean;
begin
  select * into me from public.employees where id = public.my_emp_id() and active and approved;
  if me.id is null then raise exception 'NO_EMPLOYEE'; end if;
  select * into r from public.leave_requests where id = p_id for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status <> 'Pending' then raise exception 'NOT_PENDING:รายการนี้ถูกดำเนินการไปแล้ว'; end if;
  if r.emp_id = me.id and not public.is_super_admin() then raise exception 'FORBIDDEN:อนุมัติการลาของตัวเองไม่ได้'; end if;
  select * into o from public.employees where id = r.emp_id;
  v_ok := public.is_super_admin() or exists (
    select 1 from public.approver_scopes s
     where s.emp_id = me.id and s.role in ('mgr', 'dir', 'coo', 'ceo')
       and (s.scope_type = 'all' or (s.scope_type = 'dept' and s.scope_key = o.dept) or (s.scope_type = 'emp' and s.scope_key = o.id)));
  if not v_ok then raise exception 'FORBIDDEN:ไม่มีสิทธิ์อนุมัติการลาของพนักงานคนนี้'; end if;
  update public.leave_requests
     set status = case when p_approve then 'Approved' else 'Rejected' end, decided_by = me.id, decided_at = now(), decide_note = left(coalesce(p_note, ''), 300)
   where id = p_id returning * into r;
  return to_jsonb(r);
end $$;

create or replace function public.leave_cancel(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v_emp text := public.my_emp_id(); r public.leave_requests%rowtype;
begin
  select * into r from public.leave_requests where id = p_id and emp_id = v_emp for update;
  if r.id is null then raise exception 'NOT_FOUND:ไม่พบรายการลา'; end if;
  if r.status = 'Pending' or (r.status = 'Approved' and r.start_date > (now() at time zone 'Asia/Bangkok')::date) then
    update public.leave_requests set status = 'Cancelled', decided_at = now(), decide_note = 'ยกเลิกโดยผู้ลา' where id = p_id returning * into r;
    return to_jsonb(r);
  end if;
  raise exception 'NOT_ALLOWED:ยกเลิกได้เฉพาะรายการที่รออนุมัติ หรือที่อนุมัติแล้วและยังไม่ถึงวันลา';
end $$;

revoke all on function public.leave_submit(text, date, date, text, text), public.leave_decide(uuid, boolean, text), public.leave_cancel(uuid) from public, anon;
grant execute on function public.leave_submit(text, date, date, text, text), public.leave_decide(uuid, boolean, text), public.leave_cancel(uuid) to authenticated;
