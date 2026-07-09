begin;
select _v.register_patch('008-management-writes', ARRAY['007-entities-creation'], NULL);

-- accesses writable view (no pass/role/name changes here)
create view api.accesses_rw as
select
	a.id,
	a.name,
	a.admin_notes,
	a.expires,
	a.role,
	a.max_session_time,
	a.force_change_pass
from auth.accesses a;

grant select, update on api.accesses_rw to web;

create function api.accesses_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m bigint;
begin
	if NEW.id is distinct from OLD.id then
		raise insufficient_privilege using message = 'id is immutable';
	end if;
	if NEW.name is distinct from OLD.name then
		raise insufficient_privilege using message = 'name is immutable';
	end if;
	if NEW.role is distinct from OLD.role then
		raise insufficient_privilege using message = 'role is immutable';
	end if;

	m := auth.permission_mask('write', 'access', OLD.id);

	if NEW.admin_notes is distinct from OLD.admin_notes then
		if (m & auth.member_bit('non_sensitive')) = 0 then
			raise insufficient_privilege using message = 'missing write(non_sensitive) on access';
		end if;
	end if;

	if NEW.expires is distinct from OLD.expires then
		if (m & auth.member_bit('lifetime')) = 0 then
			raise insufficient_privilege using message = 'missing write(lifetime) on access';
		end if;
	end if;

	if NEW.max_session_time is distinct from OLD.max_session_time then
		if (m & auth.member_bit('session_time')) = 0 then
			raise insufficient_privilege using message = 'missing write(session_time) on access';
		end if;
	end if;

	if NEW.force_change_pass is distinct from OLD.force_change_pass then
		if (m & auth.member_bit('change_pass')) = 0 then
			raise insufficient_privilege using message = 'missing write(change_pass) on access';
		end if;
	end if;

	update auth.accesses
	set
		admin_notes = NEW.admin_notes,
		expires = NEW.expires,
		max_session_time = NEW.max_session_time,
		force_change_pass = NEW.force_change_pass
	where id = OLD.id
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_accesses_rw_update
instead of update on api.accesses_rw
for each row
execute function api.accesses_rw_update();


-- sites writable view (only info/perimeter mutable)
create view api.sites_rw as
select
	s.id,
	s.name,
	s.info,
	s.perimeter
from sites s;

grant select, update on api.sites_rw to web;

create function api.sites_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m bigint;
begin
	if NEW.id is distinct from OLD.id then
		raise insufficient_privilege using message = 'id is immutable';
	end if;
	if NEW.name is distinct from OLD.name then
		raise insufficient_privilege using message = 'name is immutable';
	end if;

	m := auth.permission_mask('write', 'site', OLD.id);

	if NEW.info is distinct from OLD.info then
		if (m & auth.member_bit('info')) = 0 then
			raise insufficient_privilege using message = 'missing write(info) on site';
		end if;
	end if;

	if NEW.perimeter is distinct from OLD.perimeter then
		if (m & auth.member_bit('location')) = 0 then
			raise insufficient_privilege using message = 'missing write(location) on site';
		end if;
	end if;

	update sites
	set
		info = NEW.info,
		perimeter = NEW.perimeter
	where id = OLD.id
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_sites_rw_update
instead of update on api.sites_rw
for each row
execute function api.sites_rw_update();


-- gateways writable view (only info/location mutable)
create view api.gateways_rw as
select
	g.id,
	g.site,
	g.cn,
	g.name,
	g.info,
	g.location
from gateways g;

grant select, update on api.gateways_rw to web;

create function api.gateways_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m bigint;
begin
	if NEW.id is distinct from OLD.id then
		raise insufficient_privilege using message = 'id is immutable';
	end if;
	if NEW.site is distinct from OLD.site then
		raise insufficient_privilege using message = 'site is immutable';
	end if;
	if NEW.cn is distinct from OLD.cn then
		raise insufficient_privilege using message = 'cn is immutable';
	end if;
	if NEW.name is distinct from OLD.name then
		raise insufficient_privilege using message = 'name is immutable';
	end if;

	m := auth.permission_mask('write', 'gateway', OLD.id);

	if NEW.info is distinct from OLD.info then
		if (m & auth.member_bit('info')) = 0 then
			raise insufficient_privilege using message = 'missing write(info) on gateway';
		end if;
	end if;

	if NEW.location is distinct from OLD.location then
		if (m & auth.member_bit('location')) = 0 then
			raise insufficient_privilege using message = 'missing write(location) on gateway';
		end if;
	end if;

	update gateways
	set
		info = NEW.info,
		location = NEW.location
	where id = OLD.id
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_gateways_rw_update
instead of update on api.gateways_rw
for each row
execute function api.gateways_rw_update();

-- watchers writable view (only info/location mutable)
create view api.watchers_rw as
select
	w.id,
	w.gateway,
	w.cn,
	w.name,
	w.info,
	w.location
from watchers w;

grant select, update on api.watchers_rw to web;

create function api.watchers_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m bigint;
begin
	if NEW.id is distinct from OLD.id then
		raise insufficient_privilege using message = 'id is immutable';
	end if;
	if NEW.gateway is distinct from OLD.gateway then
		raise insufficient_privilege using message = 'gateway is immutable';
	end if;
	if NEW.cn is distinct from OLD.cn then
		raise insufficient_privilege using message = 'cn is immutable';
	end if;
	if NEW.name is distinct from OLD.name then
		raise insufficient_privilege using message = 'name is immutable';
	end if;

	m := auth.permission_mask('write', 'watcher', OLD.id);

	if NEW.info is distinct from OLD.info then
		if (m & auth.member_bit('info')) = 0 then
			raise insufficient_privilege using message = 'missing write(info) on watcher';
		end if;
	end if;

	if NEW.location is distinct from OLD.location then
		if (m & auth.member_bit('location')) = 0 then
			raise insufficient_privilege using message = 'missing write(location) on watcher';
		end if;
	end if;

	update watchers
	set
		info = NEW.info,
		location = NEW.location
	where id = OLD.id
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_watchers_rw_update
instead of update on api.watchers_rw
for each row
execute function api.watchers_rw_update();


create view api.accesses_group_rw as
select
	g.id,
	g.name,
	g.description
from accesses_group g;

grant select, update on api.accesses_group_rw to web;

create function api.accesses_group_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m bigint;
begin
	if NEW.id is distinct from OLD.id then
		raise insufficient_privilege using message = 'id is immutable';
	end if;
	if NEW.name is distinct from OLD.name then
		raise insufficient_privilege using message = 'name is immutable';
	end if;

	-- reuse read/write mask model on a_group target
	m := auth.permission_mask('write', 'a_group', OLD.id);

	if NEW.description is distinct from OLD.description then
		if (m & auth.member_bit('non_sensitive')) = 0 then
			raise insufficient_privilege using message = 'missing write(non_sensitive) on a_group';
		end if;
	end if;

	update accesses_group
	set description = NEW.description
	where id = OLD.id
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_accesses_group_rw_update
instead of update on api.accesses_group_rw
for each row
execute function api.accesses_group_rw_update();

-- ---------------------------------------------------------------------------
-- access_in_group writable view
-- Mutable: a_group only (reassignment), access immutable in this model
-- ---------------------------------------------------------------------------

create view api.access_in_group_rw as
select
	aig.access,
	aig.a_group
from access_in_group aig;

grant select, update on api.access_in_group_rw to web;

create function api.access_in_group_rw_update()
returns trigger
language plpgsql
security definer
as $$
declare
	m_old bigint;
	m_new bigint;
begin
	if NEW.access is distinct from OLD.access then
		raise insufficient_privilege using message = 'access is immutable';
	end if;

	if NEW.a_group is distinct from OLD.a_group then
		m_old := auth.permission_mask('write', 'a_group', OLD.a_group);
		m_new := auth.permission_mask('write', 'a_group', NEW.a_group);

		if (m_old & auth.member_bit('non_sensitive')) = 0 then
			raise insufficient_privilege using message = 'missing write(non_sensitive) on source a_group';
		end if;
		if (m_new & auth.member_bit('non_sensitive')) = 0 then
			raise insufficient_privilege using message = 'missing write(non_sensitive) on target a_group';
		end if;
	end if;

	update access_in_group
	set a_group = NEW.a_group
	where access = OLD.access
	  and a_group = OLD.a_group
	returning * into NEW;

	return NEW;
end;
$$;

create trigger trg_access_in_group_rw_update
instead of update on api.access_in_group_rw
for each row
execute function api.access_in_group_rw_update();

-- keep rw views as invoker
alter view api.accesses_rw set (security_invoker = true);
alter view api.sites_rw set (security_invoker = true);
alter view api.gateways_rw set (security_invoker = true);
alter view api.watchers_rw set (security_invoker = true);

commit;
