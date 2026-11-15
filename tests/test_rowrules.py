"""The row rules a project's SQL files write down (lantern/rowrules.py): each thing that leaves a table open beside
twins that look like it and do not."""
from lantern import rowrules


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _read(tmp_path, files):
    _write(tmp_path, files)
    return rowrules.read(tmp_path)


def test_a_table_is_open_until_a_file_switches_row_level_security_on(tmp_path):
    st = _read(tmp_path, {"supabase/migrations/001_init.sql": """
        create table public.todos (id bigint primary key, title text);
        create table notes (id bigint primary key);
        CREATE TABLE IF NOT EXISTS "public"."Profiles" (id uuid primary key);
        alter table notes enable row level security;
        ALTER TABLE ONLY "public"."Profiles" ENABLE ROW LEVEL SECURITY;
    """})
    todos, notes, profiles = st.table("todos"), st.table("notes"), st.table("Profiles")
    assert (todos.rls, todos.file, todos.line) == (False, "supabase/migrations/001_init.sql", 2)
    assert st.off(todos)
    assert notes.rls is True and notes.rls_at == ("supabase/migrations/001_init.sql", 5) and not st.off(notes)
    assert profiles.rls is True and st.table("profiles") is None      # a quoted name keeps its capital letter


def test_the_files_are_applied_in_their_order(tmp_path):
    st = _read(tmp_path, {
        "supabase/migrations/20260101000000_a.sql": "create table todos (id int); alter table todos enable row level security;",
        "supabase/migrations/20260201000000_b.sql": "alter table todos disable row level security;",
        "supabase/migrations/20260301000000_c.sql": "create table gone (id int); create table kept (id int);",
        "supabase/migrations/20260401000000_d.sql": "drop table if exists gone cascade; alter table kept rename to held;",
        "supabase/seed.sql": "insert into todos values (1);",
    })
    assert st.files[0].endswith("_a.sql") and st.files[-1] == "supabase/seed.sql"
    assert st.table("todos").rls is False and st.off(st.table("todos"))
    assert st.table("gone") is None and st.table("kept") is None and st.table("held") is not None


def test_the_twin_switched_on_in_a_later_file(tmp_path):
    st = _read(tmp_path, {
        "prisma/migrations/20260101_init/migration.sql": 'CREATE TABLE "Todo" ("id" SERIAL NOT NULL);',
        "prisma/migrations/20260102_rls/migration.sql": 'ALTER TABLE "Todo" ENABLE ROW LEVEL SECURITY;',
    })
    assert st.table("Todo").rls is True and not st.off(st.table("Todo"))


def test_what_is_written_in_a_comment_or_a_text_switches_nothing_on(tmp_path):
    st = _read(tmp_path, {"db/schema.sql": """
        create table todos (id int, note text default 'alter table todos enable row level security;');
        -- alter table todos enable row level security;
        /* alter table todos enable row level security; /* nested */ still a comment */
        create table "odd;name" (id int);
        comment on table todos is E'it\\'s; alter table todos enable row level security';
    """})
    assert st.table("todos").rls is False
    assert st.table("odd;name") is not None
    # the text names row-level security, so what runs in the database may switch it on: "off" is not said
    assert st.in_database and not st.off(st.table("todos"))


def test_row_level_security_switched_on_by_code_in_the_database_is_not_known_and_not_off(tmp_path):
    st = _read(tmp_path, {"supabase/migrations/001.sql": """
        create table a (id int);
        create table b (id int);
        alter table b enable row level security;
        do $$ declare r record; begin
          for r in select tablename from pg_tables where schemaname = 'public' loop
            execute format('alter table %I enable row level security', r.tablename);
          end loop;
        end $$;
    """})
    assert st.in_database == [("supabase/migrations/001.sql", 5)]
    assert st.table("a").rls is False and not st.off(st.table("a"))
    assert st.table("b").rls is True
    # the twin: a function's body that has nothing to do with it leaves "off" said
    st = _read(tmp_path / "twin", {"001.sql": """
        create table a (id int);
        create function touch() returns trigger language plpgsql as $fn$ begin new.at = now(); return new; end $fn$;
    """})
    assert not st.in_database and st.off(st.table("a"))


def test_a_policy_is_read_with_its_command_its_roles_and_its_two_expressions(tmp_path):
    st = _read(tmp_path, {"supabase/migrations/001.sql": """
        create table todos (id int, user_id uuid);
        alter table todos enable row level security;
        create policy "own rows" on public.todos
          for select to authenticated
          using ((select auth.uid()) = user_id);
        create policy add_own on todos as permissive for insert to authenticated, anon
          with check ( auth.uid() = user_id );
        CREATE POLICY "change own" ON "todos" FOR UPDATE
          USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
        create policy narrow on todos as restrictive for delete using (auth.uid() = user_id);
    """})
    own, add, change, narrow = st.table("todos").policies
    assert (own.name, own.command, own.roles, own.restrictive) == ("own rows", "select", ("authenticated",), False)
    assert own.using == "(select auth.uid()) = user_id" and own.check is None and own.line == 4
    assert (add.command, add.roles, add.check) == ("insert", ("authenticated", "anon"), "auth.uid() = user_id")
    assert (change.command, change.roles) == ("update", ("public",))
    assert change.using == "auth.uid() = user_id" and change.check == "auth.uid() = user_id"
    assert narrow.restrictive and narrow.command == "delete"
    assert not any(p.using_always or p.check_always for p in st.table("todos").policies)
    assert st.table("todos").open_writes() == [] and st.table("todos").open_reads() == []


def test_a_policy_that_lets_everyone_write_and_its_twins(tmp_path):
    st = _read(tmp_path, {"supabase/migrations/001.sql": """
        create table a (id int); alter table a enable row level security;
        create policy "anyone adds" on a for insert with check (true);
        create table b (id int); alter table b enable row level security;
        create policy "all of it" on b for all to authenticated using ( TRUE );
        create table c (id int); alter table c enable row level security;
        create policy "anyone changes" on c for update using (1 = 1) with check (auth.uid() = owner);
        create policy "anyone removes" on c for delete to anon using ((true));
        create table d (id int); alter table d enable row level security;
        create policy "read all" on d for select using (true);
        create policy "own" on d for update using (auth.uid() = owner) with check (true);
        create policy "word" on d for delete using (kind = 'true');
        create policy "and" on d for insert with check (true and auth.uid() = owner);
        create table e (id int); alter table e enable row level security;
        create policy "server" on e for all to service_role using (true);
        create table f (id int); alter table f enable row level security;
        create policy "open" on f for delete using (true);
        create policy "narrow" on f as restrictive for delete using (auth.uid() = owner);
    """})
    ways = lambda name: [(p.name, w, who) for p, w, who in st.table(name).open_writes()]     # noqa: E731
    assert ways("a") == [("anyone adds", ("insert",), "everyone")]
    assert ways("b") == [("all of it", ("insert", "update", "delete"), "signed-in")]
    assert ways("c") == [("anyone changes", ("update",), "everyone"), ("anyone removes", ("delete",), "everyone")]
    # the twins: a read for everyone is no write; an owner's own row; a word in a text; a condition with more to it;
    # a policy for the server's own role; a restrictive policy beside the open one
    assert ways("d") == [] and [p.name for p, _ in st.table("d").open_reads()] == ["read all"]
    assert ways("e") == [] and ways("f") == []


def test_a_policy_changed_renamed_or_dropped_later(tmp_path):
    st = _read(tmp_path, {
        "supabase/migrations/001.sql": """
            create table a (id int); alter table a enable row level security;
            create policy p1 on a for insert with check (true);
            create policy p2 on a for delete using (true);
            create policy p3 on a for update using (auth.uid() = owner);
        """,
        "supabase/migrations/002.sql": """
            drop policy if exists p1 on a;
            alter policy p2 on a using (auth.uid() = owner);
            alter policy p3 on a rename to p4;
            alter policy p4 on a to authenticated using (true);
        """})
    t = st.table("a")
    assert [p.name for p in t.policies] == ["p2", "p4"]
    assert [(p.name, w, who) for p, w, who in t.open_writes()] == [("p4", ("update",), "signed-in")]


def test_a_table_of_another_schema_and_a_table_the_files_do_not_create(tmp_path):
    st = _read(tmp_path, {"supabase/migrations/001.sql": """
        create schema private;
        create table private.audit (id int);
        create temp table scratch (id int);
        create policy "seen" on made_in_dashboard for insert with check (true);
        alter table also_dashboard enable row level security;
    """})
    assert st.table("audit") is None and st.table("audit", "private").rls is False
    assert st.table("scratch") is None
    t = st.table("made_in_dashboard")
    assert t.file is None and t.rls is None and not st.off(t)                 # not known is not off
    assert [(p.name, w) for p, w, _ in t.open_writes()] == [("seen", ("insert",))]
    assert st.table("also_dashboard").rls is True


def test_a_file_too_large_is_named_and_a_project_without_sql_reads_as_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(rowrules, "MAX_SQL", 50)
    st = _read(tmp_path, {"big.sql": "create table a (id int);" + " " * 60, "small.sql": "create table b (id int);"})
    assert st.left_out == ["big.sql"] and st.files == ["small.sql"]
    assert st.table("a") is None and st.table("b") is not None
    assert rowrules.read(tmp_path / "nothing-here").tables == {}
