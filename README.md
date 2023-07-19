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

### To tag the users, Keeping username in one file and email (tags) in second file

```
exec {fdA}<user
exec {fdB}<email 
while read -r -u "$fdA" lineA && read -r -u "$fdB" lineB; do aws iam tag-user --user-name $lineA --tags '{"Key": "email", "Value": "'$lineB'"}'; do
ne
exec {fdA}>&- {fdB}>&-
```
