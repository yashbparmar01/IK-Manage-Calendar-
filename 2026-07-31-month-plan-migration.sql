-- ============================================================
-- CC Brand Calendar — Month plan: Key Theme, Goals, Influencer
-- Marketing, Production. Additive, idempotent. Mirrors the exact
-- RLS pattern already used by social_posts (is_staff()/my_brand()),
-- NOT the new platform access model — the calendar hasn't been
-- ported to that yet.
-- ============================================================

create table if not exists social_month_plan (
  id          text primary key,
  brand_id    uuid not null references brands(id) on delete cascade,
  year        int  not null default 2026,
  month       int  not null check (month between 1 and 12),
  key_theme   text not null default '',
  updated_at  timestamptz not null default now(),
  unique(brand_id, year, month)
);

create table if not exists social_month_items (
  id          text primary key,
  brand_id    uuid not null references brands(id) on delete cascade,
  year        int  not null default 2026,
  month       int  not null check (month between 1 and 12),
  category    text not null check (category in ('goal','influencer','production')),
  label       text not null default '',
  status      text not null default 'pending',
  sort_order  int  not null default 0,
  updated_at  timestamptz not null default now(),
  constraint social_month_items_status_ck check (
    (category = 'goal'        and status in ('open','done')) or
    (category = 'influencer'  and status in ('pending','approved','briefed','content_approved','published')) or
    (category = 'production'  and status in ('pending','moodboard_shared','complete'))
  )
);

create index if not exists social_month_plan_brand_idx  on social_month_plan(brand_id);
create index if not exists social_month_plan_year_idx   on social_month_plan(year);
create index if not exists social_month_items_brand_idx on social_month_items(brand_id);
create index if not exists social_month_items_year_idx  on social_month_items(year);
create index if not exists social_month_items_cat_idx   on social_month_items(category);

alter table social_month_plan  enable row level security;
alter table social_month_items enable row level security;

drop policy if exists social_month_plan_read on social_month_plan;
create policy social_month_plan_read on social_month_plan for select to authenticated
  using (is_staff() or brand_id = my_brand());
drop policy if exists social_month_plan_write on social_month_plan;
create policy social_month_plan_write on social_month_plan for all to authenticated
  using (is_staff()) with check (is_staff());

drop policy if exists social_month_items_read on social_month_items;
create policy social_month_items_read on social_month_items for select to authenticated
  using (is_staff() or brand_id = my_brand());
drop policy if exists social_month_items_write on social_month_items;
create policy social_month_items_write on social_month_items for all to authenticated
  using (is_staff()) with check (is_staff());

select 'social_month_plan + social_month_items ready' as status;
