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

vault write db2/config hostname="10.0.2.2" port=50000
vault write db2/static-role/myrole username=moayad password_policy=mypolicy database=dojo current_password=vCu5RYrb
vault read db2/static-role/myrole
vault list db2/static-role
vault read db2/static-role/myrole
vault write -f db2/rotate-cred/myrole
vault read db2/static-cred/myrole


