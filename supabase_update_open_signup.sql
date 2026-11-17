-- เปิดสมัครสมาชิกโดยไม่ตรวจรายชื่อ: ใครก็สมัครได้ แต่ต้องรอ Admin อนุมัติก่อนจึงเข้าถึงข้อมูลได้
-- (รันใน Supabase > SQL Editor หนึ่งครั้ง — ต้องรัน supabase_update_approval.sql มาก่อนแล้ว)

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_emp  text := nullif(trim(new.raw_user_meta_data->>'emp_id'), '');
  v_name text := coalesce(nullif(trim(new.raw_user_meta_data->>'full_name'), ''), split_part(new.email, '@', 1));
  v_id   text;
begin
  -- ถ้า Admin เพิ่มรายชื่อพร้อมอีเมลนี้ไว้แล้ว → ผูกกับแถวเดิม (สถานะอนุมัติตามที่ Admin ตั้งไว้)
  update public.employees set user_id = new.id
   where lower(email) = lower(new.email) and user_id is null and active;
  if found then return new; end if;
  -- ไม่เช่นนั้น สร้างคำขอใหม่ สถานะ "รออนุมัติ"
  v_id := coalesce(v_emp, 'N' || substr(new.id::text, 1, 6));
  if exists (select 1 from public.employees where id = v_id) then
    v_id := v_id || '-' || substr(new.id::text, 1, 4);      -- รหัสซ้ำ: Admin แก้รหัสให้ถูกต้องตอนอนุมัติ
  end if;
  insert into public.employees (id, name, email, role, approved, active, user_id)
  values (v_id, v_name, lower(new.email), 'user', false, true, new.id);
  return new;
end $$;

-- Admin ปฏิเสธคำขอสมัคร (ลบบัญชีผู้สมัครที่ยังไม่อนุมัติ)
create or replace function public.admin_reject(p_id text) returns void
language plpgsql security definer set search_path = public as $$
declare v_uid uuid;
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  select user_id into v_uid from public.employees where id = p_id and approved = false;
  if not found then raise exception 'NOT_PENDING'; end if;
  delete from public.employees where id = p_id and approved = false;
  if v_uid is not null then delete from auth.users where id = v_uid; end if;
end $$;

-- Admin แก้รหัสพนักงานของผู้สมัครที่ยังไม่อนุมัติ
create or replace function public.admin_rename_emp(p_old text, p_new text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  p_new := trim(p_new);
  if p_new = '' then raise exception 'EMPTY_ID'; end if;
  if exists (select 1 from public.employees where id = p_new) then raise exception 'ID_EXISTS'; end if;
  update public.employees set id = p_new where id = p_old and approved = false;
  if not found then raise exception 'NOT_PENDING'; end if;
end $$;

revoke all on function public.admin_reject(text) from public, anon;
revoke all on function public.admin_rename_emp(text, text) from public, anon;
grant execute on function public.admin_reject(text) to authenticated;
grant execute on function public.admin_rename_emp(text, text) to authenticated;