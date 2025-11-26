psql -v SECRET="$JWT_SECRET" -c "alter database cda set "app.jwt_secret" TO :'SECRET';"
