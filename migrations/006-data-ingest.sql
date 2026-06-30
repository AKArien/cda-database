begin;
select _v.register_patch('006-data-ingest', ARRAY['005-column-security'], NULL);

create function api.ingest_report(
	watcher_name text,
	moment_in timestamptz,
	report_in int
) returns void as $$
declare
	headers json;
	client_verify text;
	client_dn text;
	client_cn text;
	gateway_id int;
	watcher_id int;
begin
	headers := current_setting('request.headers', true)::json;

	client_verify := headers->>'x-client-verify';
	if coalesce(client_verify, '') <> 'SUCCESS' then
		raise insufficient_privilege using message = 'mTLS client verification required';
	end if;

	client_dn := headers->>'x-client-dn';
	if client_dn is null or client_dn = '' then
		raise invalid_parameter_value using message = 'missing client DN header';
	end if;

	-- DN format : CN=gw-hq-01,OU=Gateway,O=CDA,C=FR
	client_cn := substring(client_dn from 'CN=([^,]+)');
	if client_cn is null or client_cn = '' then
		raise invalid_parameter_value using message = 'unable to extract CN from client DN';
	end if;

	select gw.id
	into gateway_id
	from gateways gw
	where gw.cn = client_cn;

	if gateway_id is null then
		raise insufficient_privilege using message = 'unknown gateway certificate CN';
	end if;

	select w.id
	into watcher_id
	from watchers w
	where w.gateway = gateway_id
		and w.name = watcher_name;

	if watcher_id is null then
		raise foreign_key_violation using message = 'watcher does not belong to authenticated gateway';
	end if;

	insert into reports(moment, watcher, report)
	values (moment_in, watcher_id, report_in);
end;
$$ language plpgsql security definer;

revoke all on function api.ingest_report(text, timestamptz, int) from public;
grant execute on function api.ingest_report(text, timestamptz, int) to anon;

commit;
