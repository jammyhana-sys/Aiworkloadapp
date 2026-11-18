-- Sales Contract แยกบริษัท DP / Demco (ใช้กำหนดว่าประเภท SG&A ไหนเลือกสัญญาของบริษัทใดได้)
-- รันใน Supabase > SQL Editor หนึ่งครั้ง (ก่อนอัปโหลดแอป v44) — รันซ้ำได้ ไม่เสียหาย
alter table public.contracts add column if not exists company text not null default 'Demco';
do $$
begin
  if not exists (select 1 from pg_constraint where conrelid = 'public.contracts'::regclass and conname = 'contracts_company_check') then
    alter table public.contracts add constraint contracts_company_check check (company in ('DP','Demco'));
  end if;
end $$;
-- สัญญาเดิมทั้งหมดถูกตั้งเป็น Demco โดยอัตโนมัติ ถ้าสัญญาไหนเป็นของ DP ให้แก้ในแอป (ตั้งค่าข้อมูล > Sales Contract) หรือนำเข้า Excel ที่มีคอลัมน์ Company
