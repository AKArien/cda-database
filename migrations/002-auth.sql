begin;
select _v.register_patch('002-auth', ARRAY['001-base-schema'], NULL);

-- accesses (what one might call a user) are created by the organisation (well, an admin) for people who should be allowed to consult the data. They provide them with a name and a temporary password

create role authenticator login noinherit nocreatedb nocreaterole nosuperuser;
create role anon nologin;
create role web nologin;

create schema auth;

create table auth.accesses (
	id serial primary key,
	name text unique,
	admin_notes text not null, -- text specifying, for human bookeeping, the identity of the accessor (though this should be reflected in the name), contact information, the reason of granting which access, their affiliation with the organisation, or any other information that might be administratively relevant
	pass text not null check (length(pass) < 512),
	expires timestamp, -- time at which all access is revoked and the access is locked
	role name not null check (length(role) < 512),
	max_session_time int,
	force_change_password bool
);

-- tables for fine-grained permission controls
create table auth.sites_permissions (
	site int references sites(id),
	access int references auth.accesses(id),
	primary key (site, access)
);

create table auth.gateways_permissions (
	gateway int references gateways(id),
	access int references auth.accesses(id),
	primary key (gateway, access)
);

create table auth.watchers_permissions (
	watcher int references watchers(id),
	access int references auth.accesses(id),
	primary key (watcher, access)
);

-- session implementation : unlogged table of valid sessions
create unlogged table auth.sessions (
	verification uuid primary key,
	access int references auth.accesses(id),
	expiration timestamp not null
);

create function	auth.check_role_exists() returns trigger as $$
begin
	if not exists (select 1 from pg_roles as r where r.rolname = new.role) then
		raise foreign_key_violation using message =
    		'unknown database role: ' || new.role;
		return null;
	end if;
	return new;
end
$$ language plpgsql;

create constraint trigger ensure_access_role_exists
	after insert or update on auth.accesses
	for each row
	execute procedure auth.check_role_exists();


create function auth.encrypt_pass() returns trigger as $$
begin
	if tg_op = 'INSERT' or new.pass <> old.pass then
		new.pass = crypt(new.pass, gen_salt('bf'));
	end if;
	return new;
end
$$ language plpgsql;

create trigger encrypt_pass
	before insert or update on auth.accesses
	for each row
	execute procedure auth.encrypt_pass();

create function auth.access_role(email text, pass text) returns name
	language plpgsql
	as $$
begin
	return (
		select role from auth.accesses
		where accesses.email = access_role.email
		and accesses.pass = crypt(access_role.pass, accesses.pass)
	);
end;
$$;

-- set as db-pre-request in postgREST config. Implements session management.
create function auth.error_on_no_session() returns void
language plpgsql as $$
begin
	if not exists (
		select verification from auth.sessions
		where
			access = current_setting('request.jwt.claims', true)::json->>'id'
			and verification = current_setting('request.jwt.claims', true)::json->>'verification'
			and expiration > now()
	) then
		raise 'No session, try logging in first';
	end if;
end
$$;

create function login(name text, pass text, requested_session_time int default 3600, OUT token text) as $$
declare
	_role name;
	session_time integer;
	verification uuid;
	expiration timestamp;
begin
	-- identity check
	select auth.access(name, pass) into _role;
	if _role is null then
		raise invalid_password using message = 'invalid access or password';
	end if;

	if access.expires is not null then
		if now() > expires then
			raise 'Account has expired, contact your organisation if you need access';
		end if;
	end if;

	-- constrain variables
	session_time := min(requested_session_time, access.max_session_time);
	
	-- definitive values
	verification := gen_random_uuid();
	expiration := extract(epoch from now())::int + session_time;

	-- create a session
	insert into auth.sessions values (
		verification,
		access.id,
		expiration
	);

	-- finally, generate and grant the token
	select sign(
		row_to_json(r), current_setting('app.jwt_secret')
	) as token
	from (
		select _role as role, access.id as id, verification,
		expiration as exp
	) r
	into token;
end;
$$ language plpgsql security definer;

grant execute on function login(text,text,int) to anon;

commit;
