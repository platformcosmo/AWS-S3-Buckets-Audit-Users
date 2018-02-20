# AWS-S3-Buckets-Audit-Users
The script summarizes all the Users in your AWS Account regarding their S3 Bucket Privilleges

## AWS Config and Permissions:
Use AWS Credentials as environment variables on the system. You can set the file manually also under ~/.aws/credentials. For example:

```
$ cat .aws/credentials 
[default]
aws_access_key_id = AKTRYYOURBESTTOCRACK
aws_secret_access_key = SHHH************************************
```

### Permissions:
* IAM ReadOnly
* S3 ReadOnly


## Code
Python 2.7

## Dependencies
* boto3
* json

## Example Output:

```
UserName: user1
    User Inline Policy: inline_policy_1
        S3 Bucket: arn:aws:s3:::s3bucket-1
            Action: s3:*
    User Inline Policy: managed_policy_1
        S3 Bucket: arn:aws:s3:::s3bucket_2
            Action: s3:*
    Group Name: group_1
        Inline Policy: group_inline_policy_1
            S3 Bucket: arn:aws:s3:::s3bucket_3
                Action: s3:*
    Group Name: group_2
        Managed Policy: group_managed_policy_1
            S3 Bucket: arn:aws:s3:::s3bucket_4
                Action: s3:*
```
