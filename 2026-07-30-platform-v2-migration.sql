-- ============================================================
-- Platform v2 — per-person "always all brands" + centralised
-- Proposal Bank management.  ADDITIVE and IDEMPOTENT.
-- *** HELD: do not run until Chirag approves the batch deploy ***
-- ============================================================

-- 1) True "always all brands" per person (independent of role).
--    A person with this flag sees every brand — including brands
--    created in the future — without being an Admin.
alter table profiles add column if not exists all_brands boolean not null default false;

-- 2) Brand access now honours: role-level all_brands (Admin),
--    person-level all_brands (new), or an explicit assignment.
create or replace function can_access_brand(b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select all_brands from roles    where key = my_app_role()), false)
      or coalesce((select all_brands from profiles where id  = auth.uid()),   false)
      or exists (select 1 from user_brands where user_id = auth.uid() and brand_id = b)
$$;

-- 3) Let platform user-managers manage the Proposal Bank access
--    list (pb_users) from the People & access screen. Additive
--    policy — PB's own app and rules keep working unchanged.
drop policy if exists pb_users_platform_managers on pb_users;
create policy pb_users_platform_managers on pb_users for all to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));
