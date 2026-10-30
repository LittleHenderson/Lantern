create table public.todos (id bigint primary key, title text, user_id uuid);
create table public.profiles (id uuid primary key, name text);
alter table public.profiles enable row level security;
