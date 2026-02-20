begin;
select _v.register_patch('002-auth', ARRAY['001-base-schema'], NULL);

create role authenticator login noinherit nocreatedb nocreaterole nosuperuser;
create role anon nologin;
create role web nologin;
create role account_0 nologin; -- this role serves as an omnipotent admin. scary, be careful !

grant anon to authenticator;

create schema auth;

-- accesses (what one might call a user) are created by the organisation (well, an admin) for people who should be allowed to consult the data. They provide them with a name and a temporary password
create table auth.accesses (
	id serial primary key,
	name text unique,
	admin_notes text, -- text specifying, for human bookeeping, the identity of the accessor (though this should be reflected in the name), contact information, the reason of granting which access, their affiliation with the organisation, or any other information that might be administratively relevant
	pass text not null check (length(pass) < 512),
	expires timestamp, -- time at which all access is revoked and the access is locked
	role name not null check (length(role) < 512),
	max_session_time int,
	force_change_pass bool
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
	execute procedure auth.encrypt_pass()
;

create function auth.access_get(access text, pass text) returns auth.accesses
language plpgsql as $$
declare
	result auth.accesses%rowtype;
begin
	select * into result
	from auth.accesses
		where accesses.name = access_get.access
		and accesses.pass = crypt(access_get.pass, accesses.pass)
	;

	return result;
end;
$$;

-- set as db-pre-request in postgREST config. Implements session management.
create function error_on_no_session() returns void as $$
begin
	if current_user = 'web' then
		-- verify session
		if not exists (
			select verification from auth.sessions
			where
				access = (current_setting('request.jwt.claims', true)::json->>'id')::int
				and verification = (current_setting('request.jwt.claims', true)::json->>'verification')::uuid
				and expiration > now()
		) then
			raise 'Session invalid or inexistant';
		-- verify if password has to change
		end if;
	end if;
end
$$ language plpgsql security definer;

create function login(access text, pass text, requested_session_time int default 3600, OUT token text) as $$
declare
	_access auth.accesses%rowtype;
	session_time integer;
	verification uuid;
	expiration timestamp;
begin
	-- identity check
	select * into _access from auth.access_get(access, pass);
	if _access is null then
		raise invalid_password using message = 'invalid access or password';
	end if;

	if _access.expires is not null then
		if now() > _access.expires then
			raise 'Access has expired, contact your organisation';
		end if;
	end if;

	-- constrain variables
	session_time := least(requested_session_time, _access.max_session_time);
	
	-- definitive values
	verification := gen_random_uuid();
	expiration := now() + session_time * interval'1 second';

	-- create a session
	insert into auth.sessions values (
		verification,
		_access.id,
		expiration
	);

	-- finally, generate and grant the token
	select sign(
		row_to_json(r), current_setting('app.jwt_secret')
	) as token
	from (
		select _access.role as role,
		_access.id as id,
		verification,
		(extract(epoch from expiration)::bigint) as exp
	) r
	into token;
end;
$$ language plpgsql security definer;

grant execute on function login(text,text,int) to anon;

commit;
