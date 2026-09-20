create table if not exists public.chrollo_scans (
  id text primary key,
  created_at timestamptz not null default now(),
  repository_url text not null,
  payload jsonb not null
);

create index if not exists chrollo_scans_created_at_idx
  on public.chrollo_scans (created_at desc);

alter table public.chrollo_scans enable row level security;

-- Chrollo's server uses the service-role key. Do not expose that key to the browser.
