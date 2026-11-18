-- จำกัด 1 บัญชี = 1 อุปกรณ์ที่ใช้งานพร้อมกัน (login ซ้ำจากอีกอุปกรณ์ถูกปฏิเสธ)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอป v58) — รันซ้ำได้
-- หลักการ: เครื่องที่กำลังใช้งานส่งสัญญาณ (heartbeat) ทุก 30 วินาที ถ้าเงียบเกิน 150 วินาที (ปิดเบราว์เซอร์/ไม่ได้ใช้งาน) ถือว่าว่าง อุปกรณ์อื่นเข้าใช้ได้
create table if not exists public.active_sessions (
  emp_id     text primary key references public.employees(id) on delete cascade,
  device_id  text not null,
  user_agent text not null default '',
  started_at timestamptz not null default now(),
  last_seen  timestamptz not null default now()
);
alter table public.active_sessions enable row level security;
revoke all on public.active_sessions from anon, authenticated;          -- เข้าถึงผ่านฟังก์ชันด้านล่างเท่านั้น

-- เริ่มใช้งาน: ถ้ามีอีกอุปกรณ์ใช้อยู่ (last_seen ภายใน 150 วินาที) → SESSION_ACTIVE
create or replace function public.claim_session(p_device text, p_ua text default '') returns void
language plpgsql security definer set search_path = public as $$
declare e text := public.my_emp_id(); r public.active_sessions;
begin
  if e is null then return; end if;
  select * into r from public.active_sessions where emp_id = e for update;
  if found and r.device_id <> p_device and r.last_seen > now() - interval '150 seconds' then
    raise exception 'SESSION_ACTIVE';
  end if;
  insert into public.active_sessions (emp_id, device_id, user_agent, started_at, last_seen)
    values (e, p_device, left(coalesce(p_ua,''), 300), now(), now())
  on conflict (emp_id) do update set
    started_at = case when public.active_sessions.device_id = excluded.device_id then public.active_sessions.started_at else now() end,
    device_id = excluded.device_id, user_agent = excluded.user_agent, last_seen = now();
end $$;

-- สัญญาณต่อเนื่อง: คืน false ถ้ามีอุปกรณ์อื่นยึดบัญชีไปแล้ว (อุปกรณ์นี้ต้องออกจากระบบ)
create or replace function public.heartbeat(p_device text) returns boolean
language plpgsql security definer set search_path = public as $$
declare e text := public.my_emp_id(); r public.active_sessions;
begin
  if e is null then return true; end if;
  select * into r from public.active_sessions where emp_id = e for update;
  if not found then
    insert into public.active_sessions (emp_id, device_id) values (e, p_device);
    return true;
  end if;
  if r.device_id <> p_device then return false; end if;
  update public.active_sessions set last_seen = now() where emp_id = e;
  return true;
end $$;

-- ออกจากระบบ: คืนสิทธิ์ให้อุปกรณ์อื่นเข้าได้ทันที
create or replace function public.release_session(p_device text) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.active_sessions where emp_id = public.my_emp_id() and device_id = p_device;
end $$;

-- Super Admin ปลดล็อกบัญชีของพนักงาน (กรณีอุปกรณ์เดิมค้างหรือเสีย)
create or replace function public.admin_release_session(p_emp text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'FORBIDDEN'; end if;
  delete from public.active_sessions where emp_id = p_emp;
end $$;

revoke all on function public.claim_session(text,text), public.heartbeat(text), public.release_session(text), public.admin_release_session(text) from public, anon;
grant execute on function public.claim_session(text,text), public.heartbeat(text), public.release_session(text), public.admin_release_session(text) to authenticated;
