-- ============================================================
-- CC Brand Calendar — Brand Brief go-live, column migration
-- Adds one column to the existing brands table. Additive, safe to
-- run twice. Confirmed via a read-only check against production
-- that this column does not exist yet (unlike the old "Client
-- brief" screen, this dashboard was never wired to the database).
-- ============================================================

alter table public.brands
  add column if not exists brief jsonb not null default '{}'::jsonb;

notify pgrst, 'reload schema';

select table_name, column_name, data_type
from   information_schema.columns
where  table_schema = 'public'
  and  table_name   = 'brands'
  and  column_name  = 'brief';
