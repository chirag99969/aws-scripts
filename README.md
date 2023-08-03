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

### Tagging aws iamuser accounts using a while loop (reading username from file)

```
while read -r line; do aws iam tag-user --user-name $line --tags '{"Key": "type", "Value": "iamuser"}'; done <$julyinput
```

### To scrape all the Open Security Groups for all Regions, iterate throgh all the inbound rules within a security group

```
#!/bin/bash

# Function to get the values from the JSON object or print "NA" if empty
get_value() {
  local value="$1"
  if [[ -z "$value" ]]; then
    echo "NA"
  else
    echo "$value"
  fi
}

# Output CSV header
echo "Region,GroupName,GroupId,VpcId,IpProtocol,FromPort,ToPort,CidrIp"

# Get list of AWS regions
regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output json)

# Process each region
for region in $(echo "$regions" | jq -r '.[]'); do
  # Get list of Security Groups for the current region
  security_groups=$(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups[?IpPermissions[].IpRanges[?CidrIp == `0.0.0.0/0`]]' --output json)

  # Process each Security Group and extract required fields
  for group in $(echo "$security_groups" | jq -r '.[] | @base64'); do
    _jq() {
      echo "$group" | base64 --decode | jq -r "$1"
    }

    group_name=$(_jq '.GroupName')
    group_id=$(_jq '.GroupId')
    vpc_id=$(_jq '.VpcId')

    # Process each inbound rule for the Security Group
    for rule in $(_jq '.IpPermissions[] | @base64'); do
      _jq_rule() {
        echo "$rule" | base64 --decode | jq -r "$1"
      }

      ip_protocol=$(_jq_rule '.IpProtocol')
      from_port=$(_jq_rule '.FromPort')
      to_port=$(_jq_rule '.ToPort')

      # Check if the rule has "0.0.0.0/0" in CidrIp
      if _jq_rule '.IpRanges[].CidrIp | contains("0.0.0.0/0")' | grep -q true; then
        cidr_ip="0.0.0.0/0"
      else
        cidr_ip="NA"
      fi

      # Output the values in CSV format for each inbound rule
      echo "$region,$(get_value "$group_name"),$(get_value "$group_id"),$(get_value "$vpc_id"),$(get_value "$ip_protocol"),$(get_value "$from_port"),$(get_value "$to_port"),$(get_value "$cidr_ip")"
    done
  done
done
```
### Get the list of usernames for which Force_MFA policy is not attached

```
#!/bin/bash

# Get the list of users
users=$(aws iam list-users --profile AWS-Volterra-secops | jq -r '.Users[].UserName')

# Loop through each user and check for the presence of "Force_MFA" policy
for user in $users; do
    policies=$(aws iam list-attached-user-policies --user-name "$user" --profile AWS-Volterra-secops | jq -r '.AttachedPolicies[].PolicyName')

    # Check if "Force_MFA" policy is not present in the list of policies
    if ! echo "$policies" | grep -q "Force_MFA"; then
        echo "Username: $user"
        
    fi
done
```

### Generate credential report and append owner email information retrived from IAM user tags in the column against usernames

```
#!/bin/bash

# Function to get the values from the JSON object or print "NA" if empty
get_value() {
  local value="$1"
  if [[ -z "$value" ]]; then
    echo "NA"
  else
    echo "$value"
  fi
}

# Output CSV header
echo "user,password_enabled,access_key_1_active,access_key_2_active,mfa_active,email" > credential_report_output.csv

# Get the AWS Credential Report in CSV format using the specified profile
aws --profile AWS-Volterra-prod-secops iam generate-credential-report
aws --profile AWS-Volterra-prod-secops iam wait credential-report-not-present
aws --profile AWS-Volterra-prod-secops iam generate-credential-report
aws --profile AWS-Volterra-prod-secops iam wait credential-report-complete
aws --profile AWS-Volterra-prod-secops iam get-credential-report --output text --query 'Content' | base64 -d > credential_report.csv

# Process each IAM user in the credential report
while IFS=',' read -r user password_enabled access_key_1_active access_key_2_active mfa_active; do
  # Get the email tag for the IAM user using the specified profile
  email=$(aws --profile AWS-Volterra-prod-secops iam list-user-tags --user-name "$user" --query 'Tags[?Key==`email`].Value' --output text)

  # Output the values in CSV format
  echo "$(get_value "$user"),$(get_value "$password_enabled"),$(get_value "$access_key_1_active"),$(get_value "$access_key_2_active"),$(get_value "$mfa_active"),$(get_value "$email")" >> credential_report_output.csv
done < <(tail -n +2 credential_report.csv)

```

