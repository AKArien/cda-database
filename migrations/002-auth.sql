begin;
select _v.register_patch('002-auth', ARRAY['001-base-schema'], NULL);

-- users are created by the organisation (well, an admin) for people who should be allowed to consult the data. They provide them with a name and a temporary password

CREATE ROLE authenticator LOGIN NOINHERIT NOCREATEDB NOCREATEROLE NOSUPERUSER;
CREATE ROLE anonymous NOLOGIN;
CREATE ROLE webuser NOLOGIN;

create table auth.users (
	id serial primary key,
	name text unique,
	admin_notes not null text, -- text specifying, for human bookeeping, the identity of the user (though this should be reflected in the name), contact information, the reason of granting which access, their affiliation with the organisation, or any other information that might be administratively relevant
	pass text not null check (length(pass) < 512),
	expires datetime, -- time at which all access is revoked and the user is locked
	role name not null check (length(role) <512),
	max_session_time int,
	force_change_password bool
);

-- tables for fine-grained permission controls
create table auth.sites_permissions (
	site int foreign key references job.sites.id,
	user int foreign key references auth.users,
	primary key (site, user)
);

create table auth.gateways_permissions (
	gateway int foreign key references job.gateways.id,
	user int foreign key references auth.users,
	primary key (gateway, user)
);

create table auth.watchers_permissions (
	watcher int foreign key references job.watchers.id,
	user int foreign key references auth.users,
	primary key (watcher, user)
);

-- session implementation : unlogged table of valid sessions
create unlogged table auth.sessions (
	verification uuid primary key,
	user int foreign key references auth.users.id,
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

create constraint trigger ensure_user_role_exists
	after insert or update on basic_auth.users
	for each row
	execute procedure basic_auth.check_role_exists();


create function auth.encrypt_pass() returns trigger as $$
begin
	if tg_op = 'INSERT' or new.pass <> old.pass then
		new.pass = crypt(new.pass, gen_salt('bf'));
	end if;
	return new;
end
$$ language plpgsql;

create trigger encrypt_pass
	before insert or update on basic_auth.users
	for each row
	execute procedure basic_auth.encrypt_pass();

create function auth.user_role(email text, pass text) returns name
	language plpgsql
	as $$
begin
	return (
		select role from basic_auth.users
		where users.email = user_role.email
		and users.pass = crypt(user_role.pass, users.pass)
	);
end;
$$;

create role anon noinherit;
create role authenticator noinherit;
grant anon to authenticator;

-- set as db-pre-request in postgREST config. Implements session management.
create function auth.error_on_no_session() returns void
language plpgsql as $$
begin
	if not exists (
		select verification from auth.sessions
		where
			user = current_setting('request.jwt.claims', true)::json->>'id'
			and verification = current_setting('request.jwt.claims', true)::json->>'verification'
			and expiration > now()
	) then
		raise no_session using hint = 'No session. Try logging in first.';
	end if;
end
$$;

create function login(name text, pass text, requested_session_time integer default 3600, OUT token text) as $$
declare
	_role name;
	session_time integer;
	verification uuid;
begin
	-- identity check
	select auth.user(name, pass) into _role;
	if _role is null then
		raise invalid_password using message = 'invalid user or password';
	end if;

	if user.expires is not null then
		if now() > expires then
			raise invalid_x using message 'account has expired, contact your organisation if you need access';
		end if;
	end if;

	-- constrain variables
	session_time := min(requested_session_time, user.max_session_time);
	
	-- definitive values
	verification := gen_random_uuid();
	expiration := extract(epoch from now())::int + session_time;

	-- create a session
	insert into auth.sessions (
		verification,
		user.id,
		expiration
	);

	-- finally, generate and grant the token
	select sign(
		row_to_json(r), current_setting('app.jwt_secret')
	) as token
	from (
		select _role as role, user.id as id, verification,
		expiration as exp
	) r
	into token;
end;
$$ language plpgsql security definer;

grant execute on function login(text,text) to anon;

commit;
