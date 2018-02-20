'''
Enumerates the Users and their S3 bucket privileges through the following way:
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

Author: aarvee

Notice: Please note that this script is in Beta Stage and any bug fixes or issues can be notofied to me via github!
'''

import boto3
import json

class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

iam = boto3.client('iam')
iamresource = boto3.resource('iam')
roles = iam.list_roles()
users = iam.list_users()
s3 = boto3.resource('s3')
s3client = boto3.client('s3')

list_of_buckets = s3client.list_buckets()
print color.CYAN + color.BOLD + '----------------------------------------------------'
print 'No. of S3 Buckets: {}'.format(len(list_of_buckets["Buckets"]))
print 'List given below:'
print '----------------------------------------------------' + color.END
for bucket in list_of_buckets["Buckets"]:
    # NOTE: LISTING OF FILES IN THE BUCKETS HAS BEEN COMMENTED OUT AS IT TAKES A LONG TIME IF YOU HAVE LARGE NUMBER OF FILES IN BUCKETS
    # Create a paginator to pull 1000 objects at a time
    #paginator = s3client.get_paginator('list_objects')
    #pageresponse = paginator.paginate(Bucket=bucket["Name"])
    #s3objects_list = []
    #try:
        # PageResponse Holds 1000 objects at a time and will continue to repeat in chunks of 1000.
    #    for pageobject in pageresponse:
    #        for file in pageobject["Contents"]:
    #            s3objects_list.append(file["Key"])
    #except KeyError:
    #    print 'EMPTY BUCKET'
    #    pass
    # Final Result
    print color.CYAN + 'Bucket Name: {}'.format(bucket['Name']) + color.END


# Enumerate all the roles
Role_list = roles['Roles']
role_arn_list = []
for role in Role_list:
    role_arn_list.append(role['Arn'])

# Enumerate all the users and their policies and groups
for key in users['Users']:
    user_name = key['UserName']
    print color.CYAN + '=' * 112 + color.END
    print color.BOLD + color.RED + 'UserName: {}'.format(user_name) + color.END
    Inline_user_policies = iam.list_user_policies(UserName=user_name)
    Managed_user_policies = iam.list_attached_user_policies(UserName=user_name)
    List_of_Groups = iam.list_groups_for_user(UserName=key['UserName'])

    managed_policy_list = []            # All Managed policies
    final_managed_policy_list = []      # All Managed policies with S3 Bucket action
    managed_policy_action_list = []     # All Managed Policy S3 Action list
    managed_policy_resource_list = []   # All Managed Policy S3 Buckets

    inline_policy_list = []             # All Inline policies
    final_inline_policy_list = []       # All Inline policies with S3 Bucket action
    inline_policy_action_list = []      # All Inline Policy S3 Action list
    inline_policy_resource_list = []    # All Inline Policy S3 Buckets

    group_inline_policy_list = []           # All Groups Inline policies with S3 Bucket action
    group_inline_policy_action_list = []    # All Groups Inline Policy S3 Action list
    group_inline_policy_resource_list = []  # All Groups Inline Policy S3 Buckets

    group_managed_policy_list = []          # All Groups Managed policies with S3 Bucket action
    group_managed_policy_action_list = []   # All Groups Managed Policy S3 Action list
    group_managed_policy_resource_list = [] # All Groups Managed Policy S3 Buckets

    # Read all the Inline policies attached to the user
    for inline_policy_name in Inline_user_policies['PolicyNames']:
        inline_policy_list.append(inline_policy_name)
        for policy_name in inline_policy_list:
            description = iam.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            # Convert the output into JSON
            desc_json = json.dumps(description)
            final_desc = json.loads(desc_json)

            # Load Statement in the Policy Document into a separate JSON
            desc_stmt = json.dumps(final_desc['PolicyDocument']['Statement'])
            final_stmt = json.loads(desc_stmt)

            # Iterate through all the Actions in the Statement JSON as there could be multiple Actions
            for statement in final_stmt:
                action_raw = json.dumps(statement['Action'])
                action_json = json.loads(action_raw)

                resource_raw = json.dumps(statement['Resource'])
                resource_json = json.loads(resource_raw)

                flag = '0'
                if type(resource_json) is list:
                    for s3bucket in resource_json:
                        if 's3' in s3bucket:
                            if flag == '0':
                                print color.YELLOW + '\tUser Inline Policy: {}'.format(inline_policy_name) + color.END
                                flag = '1'
                            print color.BLUE + '\t\tS3 Bucket: {}'.format(s3bucket) + color.END
                            if type(action_json) is list:
                                for action_print in action_json:
                                    print color.PURPLE + '\t\t\tAction: {}'.format(action_print) + color.END
                            else:
                                print color.PURPLE + '\t\t\tAction: {}'.format(action_json) + color.END
                else:
                    if 's3' in resource_json:
                        if flag == '0':
                            print color.YELLOW + '\tUser Inline Policy: {}'.format(inline_policy_name) + color.END
                            flag = '1'
                        print color.BLUE + '\t\tS3 Bucket: {}'.format(resource_json) + color.END
                        if type(action_json) is list:
                            for action_print in action_json:
                                print color.PURPLE + '\t\t\tAction: {}'.format(action_print) + color.END
                        else:
                            print color.PURPLE + '\t\t\tAction: {}'.format(action_json) + color.END

    # Read all the Managed Policies of every user
    for managed_policy in Managed_user_policies['AttachedPolicies']:
        policy_arn = managed_policy['PolicyArn']
        managed_policy_list.append(managed_policy['PolicyName'])
        for policy_name in managed_policy_list:
            description = iam.get_policy(
                PolicyArn=policy_arn
            )
            policy_policy = description['Policy']
            policy_version = policy_policy['DefaultVersionId']
            document = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            )
            document_policy_version = document['PolicyVersion']
            document_policy_doc = document_policy_version['Document']
            document_policy_statement = document_policy_doc['Statement']
            policy_doc_dump = json.dumps(document_policy_statement)
            policy_doc_json = json.loads(policy_doc_dump)

            flag = '0'
            if type(policy_doc_json) is list:
                for policy in policy_doc_json:
                    policy_dump = json.dumps(policy)
                    policy_json = json.loads(policy_dump)

                    flag = '0'
                    if type(policy_json['Resource']) is list:
                        for resource in policy_json['Resource']:
                            flag2 = '0'
                            if ('s3' in resource) or ('*' == resource):
                                try:
                                    if type(policy_json['Action']) is list:
                                        for action_print in policy_json['Action']:
                                            if ('s3' in action_print) or ('*' == action_print):
                                                if flag == '0':
                                                    print color.YELLOW + '\tUser Managed Policy: {}'.format(managed_policy['PolicyName']) + color.END
                                                    flag = '1'
                                                if flag2 == '0':
                                                    print color.BLUE + '\t\tS3 Bucket: {}'.format(resource) + color.END
                                                    flag2 = '1'
                                                print color.PURPLE + '\t\t\tAction: {}'.format(action_print) + color.END
                                    else:
                                        if ('s3' in policy_json['Action']) or ('*' == policy_json['Action']):
                                            if flag == '0':
                                                print color.YELLOW + '\tUser Managed Policy: {}'.format(managed_policy['PolicyName']) + color.END
                                                flag = '1'
                                            if flag2 == '0':
                                                print color.BLUE + '\t\tS3 Bucket: {}'.format(resource) + color.END
                                                flag2 = '1'
                                            print color.PURPLE + '\t\t\tAction: {}'.format(policy_json['Action']) + color.END

                                except KeyError:
                                    pass

                    else:
                        resource = policy_json['Resource']
                        flag2 = '0'
                        if ('s3' in resource) or ('*' == resource):
                            try:
                                if type(policy_json['Action']) is list:
                                    for action_print in policy_json['Action']:
                                        if ('s3' in action_print) or ('*' == action_print):
                                            if flag == '0':
                                                print color.YELLOW + '\tUser Managed Policy: {}'.format(managed_policy['PolicyName']) + color.END
                                                flag = '1'
                                            if flag2 == '0':
                                                print color.BLUE + '\t\tS3 Bucket: {}'.format(resource) + color.END
                                                flag2 = '1'
                                            print color.PURPLE + '\t\t\tAction: {}'.format(action_print) + color.END
                                else:
                                    action_print = policy_json['Action']
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag == '0':
                                            print color.YELLOW + '\tUser Managed Policy: {}'.format(managed_policy['PolicyName']) + color.END
                                            flag = '1'
                                        if flag2 == '0':
                                            print color.BLUE + '\t\tS3 Bucket: {}'.format(resource) + color.END
                                            flag2 = '1'
                                        print color.PURPLE + '\t\t\tAction: {}'.format(action_print) + color.END

                            except KeyError:
                                pass


    # Find the Users in the Groups that have S3 Access
    for group_dump in List_of_Groups['Groups']:

        group = iamresource.Group(group_dump['GroupName'])

        # A Group can have inline policies and managed policies attached to it
        inline_group_policy = list(group.policies.all())
        managed_group_policy = list(group.attached_policies.all())

        flag_group = '0'
        # Start the function if a User is a part of a group that has Inline Policies
        if inline_group_policy:
            flag3 = '0'
            flag_inline_policy = '0'
            for policy in inline_group_policy:
                group_policy_doc_raw = policy.policy_document
                group_policy_doc_raw_json = json.dumps(group_policy_doc_raw)
                group_policy_doc_json = json.loads(group_policy_doc_raw_json)
                statement_raw = group_policy_doc_json['Statement']
                statement_dump = json.dumps(statement_raw)
                statement_json = json.loads(statement_dump)

                flag4 = '0'
                if type(statement_json) is list:
                    for statement in statement_json:
                        if type(statement['Resource']) is list:
                            for resource in statement['Resource']:
                                if ('s3' in resource) or ('*' == resource):
                                    if type(statement['Action']) is list:
                                        for action_print in statement['Action']:
                                            if ('s3' in action_print) or ('*' == action_print):
                                                if flag3 == '0':
                                                    print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                                    flag3 = '1'
                                                if flag_inline_policy == '0':
                                                    print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                                    flag_inline_policy = '1'
                                                if flag4 == '0':
                                                    print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                                    flag4 = '1'
                                                print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                    else:
                                        action_print = statement['Action']
                                        if ('s3' in action_print) or ('*' == action_print):
                                            if flag3 == '0':
                                                print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                                flag3 = '1'
                                            if flag_inline_policy == '0':
                                                print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                                flag_inline_policy = '1'
                                            if flag4 == '0':
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                                flag4 = '1'
                                            print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                        else:
                            resource = statement['Resource']
                            if ('s3' in resource) or ('*' == resource):
                                if type(statement['Action']) is list:
                                    for action_print in statement['Action']:
                                        if ('s3' in action_print) or ('*' == action_print):
                                            if flag3 == '0':
                                                print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                                flag3 = '1'
                                            if flag_inline_policy == '0':
                                                print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                                flag_inline_policy = '1'
                                            if flag4 == '0':
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                                flag4 = '1'
                                            print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                else:
                                    action_print = statement['Action']
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag3 == '0':
                                            print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                            flag3 = '1'
                                        if flag_inline_policy == '0':
                                            print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                            flag_inline_policy = '1'
                                        if flag4 == '0':
                                            print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                            flag4 = '1'
                                        print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END

                else:
                    statement = statement_json
                    if type(statement['Resource']) is list:
                        for resource in statement['Resource']:
                            if ('s3' in resource) or ('*' == resource):
                                if type(statement['Action']) is list:
                                    for action_print in statement['Action']:
                                        if ('s3' in action_print) or ('*' == action_print):
                                            if flag3 == '0':
                                                print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                                flag3 = '1'
                                            if flag_inline_policy == '0':
                                                print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                                flag_inline_policy = '1'
                                            if flag4 == '0':
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                                flag4 = '1'
                                            print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                else:
                                    action_print = statement['Action']
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag3 == '0':
                                            print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                            flag3 = '1'
                                        if flag_inline_policy == '0':
                                            print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                            flag_inline_policy = '1'
                                        if flag4 == '0':
                                            print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                            flag4 = '1'
                                        print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                    else:
                        resource = statement['Resource']
                        if ('s3' in resource) or ('*' == resource):
                            if type(statement['Action']) is list:
                                for action_print in statement['Action']:
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag3 == '0':
                                            print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                            flag3 = '1'
                                        if flag_inline_policy == '0':
                                            print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                            flag_inline_policy = '1'
                                        if flag4 == '0':
                                            print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                            flag4 = '1'
                                        print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                            else:
                                action_print = statement['Action']
                                if ('s3' in action_print) or ('*' == action_print):
                                    if flag3 == '0':
                                        print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                        flag3 = '1'
                                    if flag_inline_policy == '0':
                                        print color.YELLOW + '\t\tInline Policy: {}'.format(arn) + color.END
                                        flag_inline_policy = '1'
                                    if flag4 == '0':
                                        print color.BLUE + '\t\t\tS3 Bucket: {}'.format(resource) + color.END
                                        flag4 = '1'
                                    print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END

        # Start the function if a User is a part of a group that has Managed Policies
        if managed_group_policy:
            for policy in managed_group_policy:
                policy_string = str(policy)
                remove, result1 = policy_string.split("iam.Policy(arn='")
                arn, remove = result1.split("')")
                description = iam.get_policy(
                    PolicyArn=arn
                )
                policy_policy = description['Policy']
                policy_version = policy_policy['DefaultVersionId']
                document = iam.get_policy_version(
                    PolicyArn=arn,
                    VersionId=policy_version
                )
                document_policy_version = document['PolicyVersion']
                document_policy_doc = document_policy_version['Document']
                document_policy_statement = document_policy_doc['Statement']
                policy_doc = json.dumps(document_policy_statement)
                policy_doc_json = json.loads(policy_doc)

                flag_managed_policy = '0'
                for policy in policy_doc_json:
                    policy_dump = json.dumps(policy)
                    policy_json = json.loads(policy_dump)

                    try:
                        flag5 = '0'
                        if policy_json['Resource'] is dict:
                            for resource in policy_json['Resource']:
                                if type(policy_json['Action']) is list:
                                    for action_print in policy_json['Action']:
                                        if ('s3' in action_print) or ('*' == action_print):
                                            if flag_group == '0':
                                                print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                                flag_group = '1'
                                            if flag_managed_policy == '0':
                                                print color.YELLOW + '\t\tManaged Policy: {}'.format(arn) + color.END
                                                flag_managed_policy = '1'

                                            if flag5 == '0':
                                                if type(resource) is list:
                                                    for bucket_name in resource:
                                                        print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                        print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                                else:
                                                    bucket_name = resource
                                                    print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                    print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                                flag5 = '1'

                                else:
                                    action_print = policy_json['Action']
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag_group == '0':
                                            print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                            flag_group = '1'
                                        if flag_managed_policy == '0':
                                            print color.YELLOW + '\t\tManaged Policy: {}'.format(arn) + color.END
                                            flag_managed_policy = '1'

                                        if flag5 == '0':
                                            if type(resource) is list:
                                                for bucket_name in resource:
                                                    print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                    print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                            else:
                                                bucket_name = resource
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                            flag5 = '1'

                        else:
                            resource = policy_json['Resource']
                            if type(policy_json['Action']) is list:
                                for action_print in policy_json['Action']:
                                    if ('s3' in action_print) or ('*' == action_print):
                                        if flag_group == '0':
                                            print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                        flag_group = '1'
                                        if flag_managed_policy == '0':
                                            print color.YELLOW + '\t\tManaged Policy: {}'.format(arn) + color.END
                                            flag_managed_policy = '1'

                                        if flag5 == '0':
                                            if type(resource) is list:
                                                for bucket_name in resource:
                                                    print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                    print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                            else:
                                                bucket_name = resource
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                            flag5 = '1'

                            else:
                                action_print = policy_json['Action']
                                if ('s3' in action_print) or ('*' == action_print):
                                    if flag_group == '0':
                                        print color.DARKCYAN + '\tGroup Name: {}'.format(group_dump['GroupName']) + color.END
                                        flag_group = '1'
                                    if flag_managed_policy == '0':
                                        print color.YELLOW + '\t\tManaged Policy: {}'.format(arn) + color.END
                                        flag_managed_policy = '1'

                                    if flag5 == '0':
                                        if type(resource) is list:
                                            for bucket_name in resource:
                                                print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                                print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                        else:
                                            bucket_name = resource
                                            print color.BLUE + '\t\t\tS3 Bucket: {}'.format(bucket_name) + color.END
                                            print color.PURPLE + '\t\t\t\tAction: {}'.format(action_print) + color.END
                                        flag5 = '1'

                    except KeyError:
                        print KeyError
                        pass