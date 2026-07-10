-- 006-data-ingest test suite
--
-- Scope:
-- - api.ingest_report() mTLS header gate and CN routing logic
--
-- Expected:
-- - rejects missing/invalid TLS verification/header inputs
-- - rejects unknown gateway CN
-- - rejects watcher CN not belonging to authenticated gateway
-- - accepts valid gateway/watcher pairing and inserts report row

begin;
select plan(7);

-- ---------------------------------------------------------------------------
-- Fixture setup
-- ---------------------------------------------------------------------------

insert into sites(name, info, perimeter)
values ('t_ingest_site', null, '((20,20),(20,21),(21,21),(21,20))'::path)
on conflict do nothing;

insert into gateways(site, cn, name, info, location)
select s.id, 'gw-ingest-01', 't_ingest_gateway', null, '(20.5,20.5)'::point
from sites s
where s.name = 't_ingest_site'
on conflict (site, cn) do nothing;

insert into watchers(gateway, cn, name, info, location)
select g.id, 'w-ingest-01', 't_ingest_watcher', null, '(20.25,20.25)'::point
from gateways g
where g.cn = 'gw-ingest-01'
on conflict (gateway, cn) do nothing;

set local role anon;

-- ---------------------------------------------------------------------------
-- 1) header validation
-- ---------------------------------------------------------------------------

select set_config('request.headers', '{}'::json::text, true);

select throws_ok(
	$$select api.ingest_report('w-ingest-01', now(), 10)$$,
	'42501',
	'mTLS client verification required',
	'ingest_report rejects when x-client-verify is missing/invalid'
);

select set_config(
	'request.headers',
	json_build_object(
		'x-client-verify', 'SUCCESS'
	)::text,
	true
);

select throws_ok(
	$$select api.ingest_report('w-ingest-01', now(), 10)$$,
	'22023',
	'missing client DN header',
	'ingest_report rejects when x-client-dn is missing'
);

select set_config(
	'request.headers',
	json_build_object(
		'x-client-verify', 'SUCCESS',
		'x-client-dn', 'OU=Gateway,O=CDA,C=FR'
	)::text,
	true
);

select throws_ok(
	$$select api.ingest_report('w-ingest-01', now(), 10)$$,
	'22023',
	'unable to extract CN from client DN',
	'ingest_report rejects when DN has no CN component'
);

-- ---------------------------------------------------------------------------
-- 2) gateway/watcher consistency checks
-- ---------------------------------------------------------------------------

select set_config(
	'request.headers',
	json_build_object(
		'x-client-verify', 'SUCCESS',
		'x-client-dn', 'CN=gw-unknown-99,OU=Gateway,O=CDA,C=FR'
	)::text,
	true
);

select throws_ok(
	$$select api.ingest_report('w-ingest-01', now(), 10)$$,
	'42501',
	'unknown gateway certificate CN',
	'ingest_report rejects unknown gateway CN'
);

select set_config(
	'request.headers',
	json_build_object(
		'x-client-verify', 'SUCCESS',
		'x-client-dn', 'CN=gw-ingest-01,OU=Gateway,O=CDA,C=FR'
	)::text,
	true
);

select throws_ok(
	$$select api.ingest_report('w-does-not-belong', now(), 10)$$,
	'23503',
	'watcher does not belong to authenticated gateway',
	'ingest_report rejects watcher not owned by gateway'
);

-- ---------------------------------------------------------------------------
-- 3) success path
-- ---------------------------------------------------------------------------

select lives_ok(
	$$select api.ingest_report('w-ingest-01', '2035-01-01 12:00:00+00'::timestamptz, 42)$$,
	'ingest_report succeeds for valid authenticated gateway and watcher'
);

set local role postgres;
select is(
	(
		select count(*)::bigint
		from reports r
		join watchers w on w.id = r.watcher
		where w.cn = 'w-ingest-01'
			and r.moment = '2035-01-01 12:00:00'::timestamp
			and r.report = 42
	),
	1::bigint,
	'ingest_report inserts expected report row'
);

reset role;
select * from finish();
rollback;
