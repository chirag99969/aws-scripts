### To retrive tags for IAM Users, reading from the file test
```
while read -r line; do
  echo -n "User: $line "
  email=$(aws iam list-user-tags --user-name "$line" | jq -r '.Tags[] | select(.Key=="email") | .Value')
  if [[ -z $email ]]; then
    echo "NA"
  else
    echo "$email"
  fi
done < test
```
