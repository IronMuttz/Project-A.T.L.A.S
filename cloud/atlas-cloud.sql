-- ═══════════════════════════════════════════════════════════════════════════
--  A.T.L.A.S cloud accounts + cloud saves (Supabase)
--  Paste this whole file into Supabase → SQL Editor → New query → Run.
--  Safe to run again: it only creates what is missing and replaces the functions.
--
--  Players sign up with a username and password (no email). Passwords are stored
--  as bcrypt hashes. The game never touches the tables directly: it can only call
--  the atlas_* functions below, and every function checks the player's session.
-- ═══════════════════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.atlas_players (
  id           uuid primary key default gen_random_uuid(),
  username     text not null,
  pass_hash    text not null,
  created_at   timestamptz not null default now(),
  last_login   timestamptz,
  failed       int not null default 0,          -- wrong passwords in a row
  locked_until timestamptz                      -- brief lock after too many wrong passwords
);
create unique index if not exists atlas_players_username on public.atlas_players (lower(username));

create table if not exists public.atlas_sessions (
  token_hash text primary key,                  -- sha-256 of the token; the token itself only lives on the device
  player_id  uuid not null references public.atlas_players(id) on delete cascade,
  device     text,
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);
create index if not exists atlas_sessions_player on public.atlas_sessions (player_id);

create table if not exists public.atlas_saves (
  player_id  uuid not null references public.atlas_players(id) on delete cascade,
  slot       text not null,
  meta       jsonb not null default '{}'::jsonb,
  data       text not null,
  updated_at timestamptz not null default now(),
  primary key (player_id, slot)
);

-- Lock the tables: no direct access from the app, only through the functions
alter table public.atlas_players  enable row level security;
alter table public.atlas_sessions enable row level security;
alter table public.atlas_saves    enable row level security;
revoke all on public.atlas_players, public.atlas_sessions, public.atlas_saves from anon, authenticated;

-- ── helpers ───────────────────────────────────────────────────────────────
create or replace function public.atlas_session_player(p_token text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid;
begin
  if p_token is null or length(p_token) < 32 then raise exception 'session'; end if;
  update atlas_sessions set last_used = now()
   where token_hash = encode(digest(p_token, 'sha256'), 'hex')
     and last_used > now() - interval '180 days'
  returning player_id into pid;
  if pid is null then raise exception 'session'; end if;
  return pid;
end $$;

create or replace function public.atlas_new_session(p_player uuid, p_device text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare tok text := encode(gen_random_bytes(32), 'hex');
begin
  insert into atlas_sessions(token_hash, player_id, device) values (encode(digest(tok, 'sha256'), 'hex'), p_player, left(p_device, 60));
  delete from atlas_sessions where player_id = p_player and last_used < now() - interval '180 days';
  return tok;
end $$;

-- ── accounts ──────────────────────────────────────────────────────────────
create or replace function public.atlas_signup(p_username text, p_password text, p_device text default null)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid;
begin
  p_username := btrim(coalesce(p_username, ''));
  if p_username !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  if length(coalesce(p_password, '')) < 6 or length(p_password) > 72 then raise exception 'bad_password'; end if;
  if exists (select 1 from atlas_players where lower(username) = lower(p_username)) then raise exception 'taken'; end if;
  -- simple brake on mass sign-ups
  if (select count(*) from atlas_players where created_at > now() - interval '1 hour') >= 200 then raise exception 'busy'; end if;
  insert into atlas_players(username, pass_hash, last_login) values (p_username, crypt(p_password, gen_salt('bf', 10)), now())
  returning id into pid;
  return json_build_object('username', p_username, 'token', atlas_new_session(pid, p_device));
exception when unique_violation then raise exception 'taken';
end $$;

create or replace function public.atlas_login(p_username text, p_password text, p_device text default null)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pl atlas_players%rowtype;
begin
  -- Wrong password / locked are returned (not raised) so the failed-attempt counter is kept
  select * into pl from atlas_players where lower(username) = lower(btrim(coalesce(p_username, '')));
  if not found then return json_build_object('error', 'bad_login'); end if;
  if pl.locked_until is not null and pl.locked_until > now() then return json_build_object('error', 'locked'); end if;
  if pl.pass_hash <> crypt(coalesce(p_password, ''), pl.pass_hash) then
    update atlas_players set failed = failed + 1,
      locked_until = case when failed + 1 >= 8 then now() + interval '10 minutes' else null end
     where id = pl.id;
    return json_build_object('error', 'bad_login');
  end if;
  update atlas_players set failed = 0, locked_until = null, last_login = now() where id = pl.id;
  return json_build_object('username', pl.username, 'token', atlas_new_session(pl.id, p_device));
end $$;

create or replace function public.atlas_whoami(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token);
begin
  return (select json_build_object('username', username, 'since', created_at) from atlas_players where id = pid);
end $$;

create or replace function public.atlas_logout(p_token text)
returns void language sql security definer set search_path = public, extensions as $$
  delete from atlas_sessions where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
$$;

create or replace function public.atlas_change_password(p_token text, p_old text, p_new text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token); h text;
begin
  select pass_hash into h from atlas_players where id = pid;
  if h <> crypt(coalesce(p_old, ''), h) then raise exception 'bad_login'; end if;
  if length(coalesce(p_new, '')) < 6 or length(p_new) > 72 then raise exception 'bad_password'; end if;
  update atlas_players set pass_hash = crypt(p_new, gen_salt('bf', 10)) where id = pid;
  -- sign out every other device
  delete from atlas_sessions where player_id = pid and token_hash <> encode(digest(p_token, 'sha256'), 'hex');
end $$;

create or replace function public.atlas_delete_account(p_token text, p_password text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token); h text;
begin
  select pass_hash into h from atlas_players where id = pid;
  if h <> crypt(coalesce(p_password, ''), h) then raise exception 'bad_login'; end if;
  delete from atlas_players where id = pid;            -- sessions and saves go with it
end $$;

-- ── saves ─────────────────────────────────────────────────────────────────
create or replace function public.atlas_put_save(p_token text, p_slot text, p_meta jsonb, p_data text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token);
begin
  if p_slot !~ '^[a-z0-9_]{1,20}$' then raise exception 'bad_slot'; end if;
  if length(coalesce(p_data, '')) < 10 or length(p_data) > 8000000 then raise exception 'too_big'; end if;
  if (select count(*) from atlas_saves where player_id = pid and slot <> p_slot) >= 12 then raise exception 'too_many'; end if;
  insert into atlas_saves(player_id, slot, meta, data, updated_at) values (pid, p_slot, coalesce(p_meta, '{}'::jsonb), p_data, now())
  on conflict (player_id, slot) do update set meta = excluded.meta, data = excluded.data, updated_at = now();
  return json_build_object('ok', true, 'updated_at', now());
end $$;

create or replace function public.atlas_list_saves(p_token text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token);
begin
  return coalesce((select json_agg(json_build_object('slot', slot, 'meta', meta, 'updated_at', updated_at) order by updated_at desc)
                     from atlas_saves where player_id = pid), '[]'::json);
end $$;

create or replace function public.atlas_get_save(p_token text, p_slot text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token);
begin
  return (select json_build_object('slot', slot, 'meta', meta, 'data', data, 'updated_at', updated_at)
            from atlas_saves where player_id = pid and slot = p_slot);
end $$;

create or replace function public.atlas_delete_save(p_token text, p_slot text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid := atlas_session_player(p_token);
begin
  delete from atlas_saves where player_id = pid and slot = p_slot;
end $$;

-- Only the entry points are callable from the game; the helpers are not
revoke all on function public.atlas_session_player(text), public.atlas_new_session(uuid, text) from public, anon, authenticated;
grant execute on function
  public.atlas_signup(text, text, text), public.atlas_login(text, text, text), public.atlas_whoami(text),
  public.atlas_logout(text), public.atlas_change_password(text, text, text), public.atlas_delete_account(text, text),
  public.atlas_put_save(text, text, jsonb, text), public.atlas_list_saves(text), public.atlas_get_save(text, text),
  public.atlas_delete_save(text, text)
to anon, authenticated;
