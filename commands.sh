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

vault write db2/config username=moayad password=mypassword url=myurl.com
vault write db2/role/myrole username=myusername password_policy=mypolicy seed_password=moayadpasswordseed
vault read db2/role/myrole
vault read db2/creds/myrole
