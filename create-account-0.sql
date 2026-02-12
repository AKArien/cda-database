\getenv name0 ACCOUNT_ZERO_NAME
\getenv pass0 ACCOUNT_ZERO_PASS

insert into auth.accesses (
    name,
    admin_notes,
    pass,
    role
) values (
    :name0,
    "GENERATED DURING INITIALISATION ACCORDING TO ENVIRONMENT SET",
    :pass0,
    account_0
);