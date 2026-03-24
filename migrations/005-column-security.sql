begin;
select _v.register_patch('005-column-security', ARRAY['004-rls-rules'], NULL);

create function auth.jwt_access_id() returns int
language sql stable
as $$
	select (current_setting('request.jwt.claims', true)::json->>'id')::int;
$$;

revoke all on function auth.jwt_access_id() from public;
grant execute on function auth.jwt_access_id() to web;

create function auth.is_permission_receiver(p_receiver_type permissions_owner, p_receiver int)
returns boolean
language sql stable
as $$
	select
		(p_receiver_type = 'access' and p_receiver = auth.jwt_access_id())
		or
		(
			p_receiver_type = 'a_group'
			and exists (
				select 1
				from access_in_group aig
				where aig.access = auth.jwt_access_id()
				  and aig.a_group = p_receiver
			)
		);
$$;

grant execute on function auth.is_permission_receiver(permissions_owner,int) to web;

-- Column permission check with inheritance for on-site entities
create function auth.can_read_on_site(
	p_member permissions_member,
	p_target_type permissions_target,
	p_target int
) returns boolean
language sql
stable
as $$
	-- direct permission on the target
	select exists (
		select 1
		from permissions p
		where
			p.action = 'read'
			and p.member = p_member
			and auth.is_permission_receiver(p.receiver_type, p.receiver)
			and (
				(p.target_type = p_target_type and p.target = p_target)
				or (
					-- inheritance to gateway from site
					p_target_type = 'gateway'
					and p.target_type = 'site'
					and p.target = (select g.site from gateways g where g.id = p_target)
				)
				or (
					-- inheritance to watcher from gateway or site
					p_target_type = 'watcher'
					and (
						(p.target_type = 'gateway' and p.target = (select w.gateway from watchers w where w.id = p_target))
						or
						(p.target_type = 'site' and p.target = (
							select g.site
							from watchers w
							join gateways g on g.id = w.gateway
							where w.id = p_target
						))
					)
				)
			)
	);
$$;

grant execute on function auth.can_read_on_site(permissions_member,permissions_target,int) to web;



commit;