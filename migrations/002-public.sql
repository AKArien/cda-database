begin;
select _v.register_patch('002-public', ARRAY['001-auth'], NULL);

-- views and functions in public schema for postgREST

create view public.sites as
	select * from private.sites
	join auth.sites_permissions
		on private.sites.id = auth.sites_permissions.site
	where auth.sites_permissions.user = (
		select user from auth.sessions
		where
			verification = current_setting('jwt.claims.verification', true)::uuid
			and
			expiration > now()
	)
;

commit;
