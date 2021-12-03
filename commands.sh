make enable
cat << EOF >payload.json
{
  "policy": "length = 7\nrule \"charset\" {\n  charset = \"abcdefghijklmnopqrstuvwxyz\"\n  min-chars = 2\n}\nrule \"charset\" {\n  charset = \"ABCDEFGHIJKLMNOPQRSTUVWXYZ\"\n  min-chars = 2\n}\nrule \"charset\" {\n  charset = \"0123456789\"\n  min-chars = 2\n}"
}
EOF

curl \
    --header "X-Vault-Token: root" \
    --request PUT \
    --data @payload.json \
    http://127.0.0.1:8200/v1/sys/policies/password/mypolicy

vault write db2/config hostname=moayad.test port=55000
vault write db2/static-role/myrole username=myusername password_policy=mypolicy seed_password=moayadpasswordseed
vault write db2/static-role/myrole1 username=myusername password_policy=mypolicy seed_password=moayadpasswordseed
vault write db2/static-role/myrole2 username=myusername password_policy=mypolicy seed_password=moayadpasswordseed
vault write db2/static-role/myrole2 username=myusername1 password_policy=mypolicy seed_password=moayadpasswordseed1
vault read db2/static-role/myrole
vault list db2/static-role
vault read db2/static-role/myrole2
vault read db2/static-cred/myrole2
#vault read db2/creds/myrole
