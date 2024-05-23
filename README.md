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

# AWS Account ID
AWS_ACCOUNT_ID="xxxxxxxxxxxx"

# Policy ARN to check for
POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/Force_MFA"

# Get all users in the account
all_users=$(aws iam list-users --query 'Users[*].UserName' --output text)

# Loop through each user and check for the presence of the specified policy
for user in $all_users; do
    policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[*].PolicyArn' --output text)

    # Check if the specified policy is not present in the list of policies
    if ! echo "$policies" | grep -q "$POLICY_ARN"; then
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
aws --profile cybersecnerd iam generate-credential-report
aws --profile cybersecnerd iam wait credential-report-not-present
aws --profile cybersecnerd iam generate-credential-report
aws --profile cybersecnerd iam wait credential-report-complete
aws --profile cybersecnerd iam get-credential-report --output text --query 'Content' | base64 -d > credential_report.csv

# Process each IAM user in the credential report
while IFS=',' read -r user password_enabled access_key_1_active access_key_2_active mfa_active; do
  # Get the email tag for the IAM user using the specified profile
  email=$(aws --profile cybersecnerd iam list-user-tags --user-name "$user" --query 'Tags[?Key==`email`].Value' --output text)

  # Output the values in CSV format
  echo "$(get_value "$user"),$(get_value "$password_enabled"),$(get_value "$access_key_1_active"),$(get_value "$access_key_2_active"),$(get_value "$mfa_active"),$(get_value "$email")" >> credential_report_output.csv
done < <(tail -n +2 credential_report.csv)

```

# Deploy AWS Aconfig rules using conformance pack

```
aws configservice put-conformance-pack --conformance-pack-name secops-rds --template-s3-uri "s3://bucketname/Operational-rds-CIS-GlobalResources.yml" --delivery-s3-bucket bucketname --region us-east-2 --profile TEST-PROFILE
```

## Describe stacks

```
for REGION in $(aws ec2 describe-regions --profile AWS-Volterra-prod-secops | jq -r ".Regions[].RegionName"); do echo $REGION && aws cloudformation describe-stacks --profile AWS-Volterra-prod-secops --region $REGION| jq -r ".Stacks[].StackName";done
```


## IAM Policy COnditional Access 

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "organizations:*",
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "aws:userid": "AROAWxxxxxxxxxxxxx:gulatic@google.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "account:PutAlternateContact",
                "account:DeleteAlternateContact",
                "account:GetAlternateContact",
                "account:GetContactInformation",
                "account:PutContactInformation",
                "account:ListRegions",
                "account:EnableRegion",
                "account:DisableRegion"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "aws:userid": "AROAWxxxxxxxxxxxxx:gulatic@google.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "iam:AWSServiceName": "organizations.amazonaws.com"
                }
            }
        }
    ]
}
```

### AttachUserPoliciesForSpecificPolicies

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAttachUserPolicyForSpecificPolicies",
      "Effect": "Allow",
      "Action": "iam:AttachUserPolicy",
      "Resource": "*",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyArn": [
            "arn:aws:iam::123456789012:policy/policy1",
            "arn:aws:iam::123456789012:policy/policy2"
          ]
        }
      }
    }
  ]
}
```

# Lambda Function for sending email notification to IAM Account owners retrieving email from tags, AWS Configs Access Key age, sending emails using SES to rotate keys
```
import boto3
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name='us-east-2')
    response = client.get_secret_value(SecretId=secret_name)
    secret = json.loads(response['SecretString'])
    return secret

def send_email_smtp(sender_email, recipient_email, smtp_username, smtp_password, subject, body):
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Connect to the SMTP server
    server = smtplib.SMTP('email-smtp.us-west-2.amazonaws.com', 587)  # Replace with SES SMTP server and port
    server.starttls()

    # Login with SMTP credentials
    server.login(smtp_username, smtp_password)

    # Send the email
    server.sendmail(sender_email, recipient_email, msg.as_string())

    # Close the SMTP server connection
    server.quit()

#### Lambda entry point
def lambda_handler(event, context):
    # Retrieve SMTP credentials from Secrets Manager
    secret_name = 'secops_smtp'  # Replace with the name of your secret in Secrets Manager
    secret = get_secret(secret_name)
    smtp_username = secret['smtp_username']
    smtp_password = secret['smtp_password']

    # Replace these with your sender and target email addresses
    sender_email = 'google-service-account-siem@cloud.google.com'
    target_email = 'chirag.gulati@google.com'  # Add your target email address here

    # AWS Config and IAM clients
    config_client = boto3.client('config', 
                                 aws_access_key_id="AKIA123",
                                 aws_secret_access_key="p4Q3123")
    iam_client = boto3.client('iam', 
                              aws_access_key_id="AKIA123",
                              aws_secret_access_key="p4Q3123")

    # Get non-compliant IAM access keys from AWS Config
    response_users = iam_client.list_users()
    response_config = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName='IAM_Access_KEYS_ROTATED',
        ComplianceTypes=['NON_COMPLIANT'],
        Limit=99
    )

    # Create a dictionary to map resource IDs to user names
    resource_id_to_username = {user['UserId']: user['UserName'] for user in response_users['Users']}

    # Counter for number of UserName values
    user_count = 0

    # Iterate over the EvaluationResults
    for evaluation_result in response_config['EvaluationResults']:
        resource_id = evaluation_result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']

        # Check if the resource ID exists in the dictionary
        if resource_id in resource_id_to_username:
            username = resource_id_to_username[resource_id]
            user_count += 1  # Increment the counter

            # Get the tags for the user
            try:
                response_tags = iam_client.list_user_tags(UserName=username)
                user_tags = response_tags['Tags']
                # Find the 'email' tag and send an email if found
                email_tag = next((tag['Value'] for tag in user_tags if tag['Key'] == 'email'), None)
                if email_tag is not None:
                    # Construct email subject and body
                    subject = 'IAM Access Keys Rotation Alert'
                    body = f"Hello {username},\n\nYour AWS IAM access keys are not rotated as per policy.\n\nResource ID: {resource_id}\nUser Name: {username}\n\nPlease take necessary action to rotate your access keys.\n\nRegards,\nYour AWS Account"

                    # Send email using SES function
                    if email_tag == target_email:
                        send_email_smtp(sender_email, email_tag, smtp_username, smtp_password, subject, body)
                else:
                    print("Email tag not found for user:", username)
            except Exception as e:
                print("Error retrieving tags for user:", username, "-", str(e))
        else:
            print("Resource ID:", resource_id, "UserName: Not found")

    print("Total Users:", user_count)

    return {
        'statusCode': 200,
        'body': 'Email sent successfully!'
    }
```

# Lambda Function for SES and AWS Secrets manager

```
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name='YOUR_REGION')
    response = client.get_secret_value(SecretId=secret_name)
    secret = json.loads(response['SecretString'])
    return secret

def send_email_smtp(sender_email, recipient_email, smtp_username, smtp_password):
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Test Email from SES using SMTP'
    body = 'This is a test email sent from SES using SMTP.'
    msg.attach(MIMEText(body, 'plain'))

    # Connect to the SMTP server
    server = smtplib.SMTP('YOUR_SMTP_SERVER', 587)  # Replace with SES SMTP server and port
    server.starttls()

    # Login with SMTP credentials
    server.login(smtp_username, smtp_password)

    # Send the email
    server.sendmail(sender_email, recipient_email, msg.as_string())

    # Close the SMTP server connection
    server.quit()

# Lambda entry point
def lambda_handler(event, context):
    # Retrieve SMTP credentials from Secrets Manager
    secret_name = 'YOUR_SECRET_NAME'  # Replace with the name of your secret in Secrets Manager
    secret = get_secret(secret_name)
    smtp_username = secret['smtp_username']
    smtp_password = secret['smtp_password']

    # Replace these with your sender and recipient email addresses
    sender_email = 'YOUR_SENDER_EMAIL'
    recipient_email = 'RECIPIENT_EMAIL'

    send_email_smtp(sender_email, recipient_email, smtp_username, smtp_password)

    return {
        'statusCode': 200,
        'body': 'Email sent successfully!'
    }
```


# Lambda Fuction for sending IAM User tags to Splunk 

```
import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    # Get the current date in YYYY-MM-DD-HH:MM:SS format
    current_date = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')

    # Initialize the boto3 client for IAM
    iam_client = boto3.client('iam')

    # Initialize the boto3 client for S3
    s3_client = boto3.client('s3')

    # List IAM users
    response = iam_client.list_users()
    users = response['Users']

    # Initialize an empty list to store user tags
    user_tags_list = []

    # Loop through each user and get their tags
    for user in users:
        user_name = user['UserName']
        user_id = user['UserId']
        arn = user['Arn']
        #CreateDate = user['CreateDate']
        #PasswordLastUsed = user['PasswordLastUsed']
        tags_response = iam_client.list_user_tags(UserName=user_name)
        tags = tags_response['Tags']
        
        # Filter the tags to get 'type' and 'email'
        type_tag = next((tag['Value'] for tag in tags if tag['Key'] == 'type'), None)
        email_tag = next((tag['Value'] for tag in tags if tag['Key'] == 'email'), None)
        
        # Create a dictionary with the required information
        user_tags = {
            'userName': user_name,
            'aws_accountId': '123456789',
            'user_id': user_id,
            'arn': arn,
            #'CreateDate': CreateDate,
            #'PasswordLastUsed': PasswordLastUsed,
            'type': type_tag,
            'email': email_tag
        }
        
        # Append the dictionary to the list
        user_tags_list.append(user_tags)

    # Convert the list to JSON format
    #user_tags_json = json.dumps(user_tags_list)
    user_tags_json = "\n".join(json.dumps(user_tags) for user_tags in user_tags_list)

    # Define the S3 bucket and key
    bucket_name = 'bucketName'
    folder_name = 'folder'
    file_name = f'output_tags_{current_date}.json'
    s3_key = f'{folder_name}/{file_name}'

    # Upload the JSON data to S3
    s3_client.put_object(Bucket=bucket_name, Key=s3_key, Body=user_tags_json)

    # Return the response
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Data uploaded successfully',
            's3_key': s3_key
        })
    }

# Note: To run this code locally for testing, you can uncomment the following lines:
# if __name__ == "__main__":
#     lambda_handler(None, None)

