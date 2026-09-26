-- ============================================================
-- InfiniKraft Brand Calendar: Security, Auth, OTP & Approval Migration
-- Target: Supabase Postgres
-- Admin: Exactly ONE authorized Google account (ninjafuryofficial@gmail.com)
-- ============================================================

-- 1. SERVER-SIDE GMAIL-ONLY ENFORCEMENT ON AUTH.USERS
-- ------------------------------------------------------------
-- Ensures that ANY attempt to sign up or authenticate with a non-Gmail
-- address via Supabase Auth is rejected at the database level.
create or replace function public.check_user_email_domain()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  user_email text;
begin
  user_email := lower(coalesce(new.email, ''));
  if user_email = '' or not (user_email like '%@gmail.com') then
    raise exception 'Access restricted: Only @gmail.com email addresses are permitted.';
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_domain_check on auth.users;
create trigger on_auth_user_created_domain_check
  before insert or update on auth.users
  for each row execute function public.check_user_email_domain();

-- 2. EXTEND PROFILES WITH STATUS & APPROVAL METADATA
-- ------------------------------------------------------------
-- Reuses existing profiles table. Valid statuses: PENDING, APPROVED, REJECTED, DISABLED
alter table public.profiles
  add column if not exists status text not null default 'PENDING' check (status in ('PENDING', 'APPROVED', 'REJECTED', 'DISABLED')),
  add column if not exists approved_at timestamptz,
  add column if not exists approved_by text,
  add column if not exists otp_verified boolean not null default false,
  add column if not exists all_brands boolean not null default false,
  add column if not exists display_name text default '',
  add column if not exists avatar_url text default '';

create index if not exists idx_profiles_status on public.profiles(status);

-- 3. EMAIL OTP STORAGE TABLE (SECURE HASHED OTP FOR NORMAL USERS)
-- ------------------------------------------------------------
create table if not exists public.email_otps (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  otp_hash text not null,
  expires_at timestamptz not null,
  attempts int not null default 0,
  max_attempts int not null default 5,
  verified boolean not null default false,
  verified_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_email_otps_user on public.email_otps(user_id);
create index if not exists idx_email_otps_email on public.email_otps(email);

alter table public.email_otps enable row level security;

-- Only service role (Edge Function) or admin can inspect/manage OTPs
drop policy if exists email_otps_service on public.email_otps;
create policy email_otps_service on public.email_otps
  for all to service_role
  using (true)
  with check (true);

-- 4. PROFILE AUTOMATIC CREATION & SYNC TRIGGER (GOOGLE OAUTH)
-- ------------------------------------------------------------
-- When a user authenticates via Google:
-- If email is ninjafuryofficial@gmail.com -> automatically APPROVED Admin with all brands
-- All other users -> PENDING with pending role and unverified OTP
create or replace function public.handle_new_infinikraft_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  user_name text;
  user_avatar text;
  user_email text;
begin
  user_email := lower(coalesce(new.email, ''));
  user_name := coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1));
  user_avatar := coalesce(new.raw_user_meta_data->>'avatar_url', new.raw_user_meta_data->>'picture', '');

  -- EXACT ONE ADMIN ACCOUNT: ninjafuryofficial@gmail.com
  if user_email = 'ninjafuryofficial@gmail.com' then
    insert into public.profiles (
      id, email, display_name, avatar_url, role, app_role, status, all_brands, otp_verified, approved_at, approved_by
    ) values (
      new.id,
      user_email,
      coalesce(nullif(user_name, ''), 'InfiniKraft Admin'),
      user_avatar,
      'admin',
      'admin',
      'APPROVED',
      true,
      true,
      now(),
      'system_provision'
    )
    on conflict (id) do update set
      email = excluded.email,
      role = 'admin',
      app_role = 'admin',
      status = 'APPROVED',
      all_brands = true,
      otp_verified = true,
      approved_at = coalesce(public.profiles.approved_at, now()),
      approved_by = 'system_provision';
  else
    -- ALL OTHER USERS: Default to pending, pending, unapproved, unverified OTP
    insert into public.profiles (
      id, email, display_name, avatar_url, role, app_role, status, otp_verified, all_brands
    ) values (
      new.id,
      user_email,
      user_name,
      user_avatar,
      'pending',
      'pending',
      'PENDING',
      false,
      false
    )
    on conflict (id) do update set
      email = excluded.email,
      display_name = coalesce(nullif(excluded.display_name, ''), public.profiles.display_name),
      avatar_url = coalesce(nullif(excluded.avatar_url, ''), public.profiles.avatar_url);
  end if;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.handle_new_infinikraft_user();

-- 5. ACCESS CHECK HELPER FUNCTIONS (REUSING EXISTING ROLES & PERMISSIONS)
-- ------------------------------------------------------------
-- Retrieve caller's app_role from profiles
create or replace function public.my_app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((select app_role from public.profiles where id = auth.uid()), 'pending');
$$;

-- Check if current authenticated user is the authorized InfiniKraft Admin
-- Strictest check: must match id, email = ninjafuryofficial@gmail.com, status = APPROVED, and admin role
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    join auth.users u on u.id = p.id
    where p.id = auth.uid()
      and lower(u.email) = 'ninjafuryofficial@gmail.com'
      and p.status = 'APPROVED'
      and (p.role = 'admin' or p.app_role = 'admin')
  );
$$;

-- Check if current authenticated user is approved for general application access
create or replace function public.is_approved()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and status = 'APPROVED'
  );
$$;

-- Check granular capability using the existing role_permissions matrix
create or replace function public.has_perm(perm text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce((
    select allowed from public.role_permissions
    where role = public.my_app_role() and permission = perm
  ), false);
$$;

-- Determine brand access using only profiles and roles (no external tables required)
create or replace function public.can_access_brand(b uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    -- 1. Admin or role with all_brands flag (roles.all_brands)
    coalesce((select all_brands from public.roles where key = public.my_app_role()), false)
    -- 2. Profile-level all_brands flag (e.g. approved staff)
    or coalesce((select all_brands from public.profiles where id = auth.uid()), false)
    -- 3. Explicit primary brand assignment on the profile
    or coalesce((select brand_id = b from public.profiles where id = auth.uid()), false);
$$;

-- 6. STRICT ROW LEVEL SECURITY (RLS) FOR PROFILES
-- ------------------------------------------------------------
alter table public.profiles enable row level security;

-- Reading profiles: Users can read their own profile, or approved admin can read all profiles
drop policy if exists profiles_read_self_or_admin on public.profiles;
create policy profiles_read_self_or_admin on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

-- Updating profiles: Only Admin can modify user status, roles, or brand assignments
drop policy if exists profiles_update_admin on public.profiles;
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- Users can only update their own non-privileged preferences (e.g. emoji, display_name)
drop policy if exists profiles_update_self_prefs on public.profiles;
create policy profiles_update_self_prefs on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (
    id = auth.uid()
    -- Prevent self privilege escalation: status, role, and brand cannot be changed by non-admins
    and status = (select p.status from public.profiles p where p.id = auth.uid())
    and role = (select p.role from public.profiles p where p.id = auth.uid())
    and coalesce(app_role, '') = coalesce((select p.app_role from public.profiles p where p.id = auth.uid()), '')
    and coalesce(all_brands, false) = coalesce((select p.all_brands from public.profiles p where p.id = auth.uid()), false)
  );

-- 7. REINFORCE CALENDAR & BRAND DATA POLICIES WITH APPROVAL CHECK
-- ------------------------------------------------------------
-- Ensure that pending, rejected, or disabled users CANNOT read or write
-- calendar posts, events, brands, or month plans even with a valid session token.

-- Brands
alter table public.brands enable row level security;
drop policy if exists brands_approved_read on public.brands;
create policy brands_approved_read on public.brands
  for select to authenticated
  using (public.is_approved() and (public.is_admin() or public.can_access_brand(id)));

drop policy if exists brands_admin_write on public.brands;
create policy brands_admin_write on public.brands
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- Social posts
alter table public.social_posts enable row level security;
drop policy if exists social_posts_approved_read on public.social_posts;
create policy social_posts_approved_read on public.social_posts
  for select to authenticated
  using (public.is_approved() and (public.is_admin() or public.can_access_brand(brand_id)));

drop policy if exists social_posts_approved_write on public.social_posts;
create policy social_posts_approved_write on public.social_posts
  for all to authenticated
  using (public.is_approved() and (public.is_admin() or (public.can_access_brand(brand_id) and public.has_perm('create'))))
  with check (public.is_approved() and (public.is_admin() or (public.can_access_brand(brand_id) and public.has_perm('create'))));

-- 8. STRICT ENFORCEMENT: ONLY ninjafuryofficial@gmail.com CAN HOLD ADMIN ROLE
-- ------------------------------------------------------------
create or replace function public.check_single_admin()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  target_email text;
begin
  if (new.role = 'admin' or new.app_role = 'admin') then
    target_email := lower(coalesce(new.email, ''));
    if target_email != 'ninjafuryofficial@gmail.com' then
      raise exception 'Security violation: Only ninjafuryofficial@gmail.com is authorized to hold the Admin role.';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_ensure_single_admin on public.profiles;
create trigger trg_ensure_single_admin
  before insert or update on public.profiles
  for each row execute function public.check_single_admin();

-- 9. ADMIN PROVISIONING PROCEDURE (GOOGLE OAUTH ACCOUNT ONLY - NO PASSWORDS)
-- ------------------------------------------------------------
-- Run once in Supabase SQL editor to ensure ninjafuryofficial@gmail.com is Admin:
--
-- select public.provision_infinikraft_admin('ninjafuryofficial@gmail.com');
--
create or replace function public.provision_infinikraft_admin(target_email text default 'ninjafuryofficial@gmail.com')
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  target_id uuid;
begin
  target_email := lower(trim(target_email));
  if target_email != 'ninjafuryofficial@gmail.com' then
    raise exception 'Security violation: Only ninjafuryofficial@gmail.com is authorized as the InfiniKraft Admin.';
  end if;

  -- Demote any other profile that might have admin role
  update public.profiles
  set role = 'team',
      app_role = 'creator',
      all_brands = false
  where (role = 'admin' or app_role = 'admin')
    and lower(email) != target_email;

  -- Look up the Google OAuth user in auth.users
  select id into target_id from auth.users where lower(email) = target_email;
  if target_id is null then
    return 'Note: Google account ' || target_email || ' has not signed in yet. Once ninjafuryofficial@gmail.com clicks Continue with Google, they will be automatically provisioned as Admin.';
  end if;

  -- Configure profile as the approved Admin with all brands
  update public.profiles
  set role = 'admin',
      app_role = 'admin',
      status = 'APPROVED',
      all_brands = true,
      otp_verified = true,
      approved_at = coalesce(approved_at, now()),
      approved_by = 'system_provision'
  where id = target_id;

  return 'User ' || target_email || ' successfully provisioned as the InfiniKraft Admin.';
end;
$$;
