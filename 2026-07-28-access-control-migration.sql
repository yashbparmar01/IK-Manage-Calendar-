-- ============================================================
-- Access control & permissions — platform foundation (Stage 1)
-- ------------------------------------------------------------
-- ADDITIVE and IDEMPOTENT. Builds the new-model access engine
-- ALONGSIDE the current one, so the existing calendar keeps
-- working untouched (it still uses profiles.role / is_staff()).
-- Nothing here removes or repurposes the legacy role model.
-- Safe to re-run. Paste into Supabase: SQL Editor -> New query -> Run.
-- ============================================================

-- 1) Permission catalogue -------------------------------------
create table if not exists permissions (
  key         text primary key,
  label       text not null,
  description text default '',
  sort        int  default 0
);

insert into permissions(key,label,description,sort) values
  ('view',             'View posts',           'See posts in assigned brands',         10),
  ('comment',          'Comment / feedback',   'Leave and reply to feedback',          20),
  ('create',           'Create & edit posts',  'Create and edit posts',                30),
  ('upload_media',     'Upload media',         'Attach images, carousels, videos',     40),
  ('submit_review',    'Submit for review',    'Move a post into internal review',     50),
  ('approve_internal', 'Approve (internal)',   'Internally approve a post',            60),
  ('client_signoff',   'Client sign-off',      'Client approval on a post',            70),
  ('publish',          'Publish live',         'Publish to the live account',          80),
  ('manage_users',     'Manage users & roles', 'Manage people, roles and permissions', 90)
on conflict (key) do nothing;

-- 2) Role catalogue -------------------------------------------
create table if not exists roles (
  key        text primary key,
  label      text not null,
  is_client  boolean default false,   -- a client-side role
  all_brands boolean default false,   -- sees every brand (Admin)
  sort       int default 0
);

insert into roles(key,label,is_client,all_brands,sort) values
  ('admin',           'Admin',                   false, true,  10),
  ('account_manager', 'Account manager',         false, false, 20),
  ('creator',         'Creator',                 false, false, 30),
  ('client_reviewer', 'Client reviewer',         true,  false, 40),
  ('client_viewer',   'Client viewer',           true,  false, 50),
  ('pending',         'Pending (no access yet)', false, false, 90)
on conflict (key) do nothing;

-- 3) Editable role -> permission matrix -----------------------
create table if not exists role_permissions (
  role       text not null references roles(key)       on delete cascade,
  permission text not null references permissions(key) on delete cascade,
  allowed    boolean not null default false,
  primary key (role, permission)
);

-- Seed the locked model. "on conflict do nothing" means a re-run
-- never clobbers an Admin's later edits, and it back-fills any new
-- (role, permission) combination that doesn't exist yet.
insert into role_permissions(role, permission, allowed)
select r.key, p.key,
  case
    when r.key = 'admin' then true
    when r.key in ('account_manager','creator')
         and p.key in ('view','comment','create','upload_media','submit_review','approve_internal','publish') then true
    when r.key = 'client_reviewer'
         and p.key in ('view','comment','client_signoff') then true
    when r.key = 'client_viewer'
         and p.key in ('view') then true
    else false
  end
from roles r cross join permissions p
on conflict (role, permission) do nothing;

-- 4) New-model role on each profile (separate from legacy 'role')
alter table profiles add column if not exists app_role text default 'pending' references roles(key);

-- 5) Brand assignments (a person can be assigned to many brands)
create table if not exists user_brands (
  user_id  uuid not null references auth.users(id) on delete cascade,
  brand_id uuid not null references brands(id)      on delete cascade,
  primary key (user_id, brand_id)
);

-- 6) Per-brand "requires client sign-off?" switch --------------
alter table brands add column if not exists requires_client_signoff boolean not null default false;

-- 7) Helper functions (new model) -----------------------------
create or replace function my_app_role() returns text
language sql stable security definer set search_path = public as $$
  select coalesce((select app_role from profiles where id = auth.uid()), 'pending')
$$;

create or replace function has_perm(perm text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select allowed from role_permissions
                   where role = my_app_role() and permission = perm), false)
$$;

create or replace function can_access_brand(b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select all_brands from roles where key = my_app_role()), false)
      or exists (select 1 from user_brands where user_id = auth.uid() and brand_id = b)
$$;

-- 8) Security on the new tables -------------------------------
alter table permissions      enable row level security;
alter table roles            enable row level security;
alter table role_permissions enable row level security;
alter table user_brands      enable row level security;

-- catalogues: any signed-in user may read; only user-managers may change
drop policy if exists permissions_read on permissions;
create policy permissions_read  on permissions      for select to authenticated using (true);
drop policy if exists permissions_write on permissions;
create policy permissions_write on permissions      for all    to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));

drop policy if exists roles_read on roles;
create policy roles_read  on roles for select to authenticated using (true);
drop policy if exists roles_write on roles;
create policy roles_write on roles for all    to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));

drop policy if exists role_perms_read on role_permissions;
create policy role_perms_read  on role_permissions for select to authenticated using (true);
drop policy if exists role_perms_write on role_permissions;
create policy role_perms_write on role_permissions for all    to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));

-- assignments: you can see your own; user-managers see & manage all
drop policy if exists user_brands_read on user_brands;
create policy user_brands_read  on user_brands for select to authenticated
  using (user_id = auth.uid() or has_perm('manage_users'));
drop policy if exists user_brands_write on user_brands;
create policy user_brands_write on user_brands for all    to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));

-- 9) Let user-managers read/update every profile (for the People screen).
--    These are ADDED alongside the existing profile policies (Postgres
--    ORs permissive policies together), so legacy admin access still works.
drop policy if exists profiles_read_managers on profiles;
create policy profiles_read_managers  on profiles for select to authenticated
  using (id = auth.uid() or has_perm('manage_users'));
drop policy if exists profiles_update_managers on profiles;
create policy profiles_update_managers on profiles for update to authenticated
  using (has_perm('manage_users')) with check (has_perm('manage_users'));

-- ============================================================
-- AFTER RUNNING — make yourself Admin in the new model:
--   update profiles set app_role='admin'
--   where email='chirag@communicationcrafts.com';
-- (Your legacy access is unchanged; this only sets the new app_role.)
-- ============================================================
