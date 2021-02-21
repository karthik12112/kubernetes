from troposphere.iam import (
    Role,
    PolicyType
)

from troposphere import (
    Template,
    Ref,
    GetAtt
)


t = Template()

t.add_description("EKS stack")


# create role
def create_prod_template(jasontemplate):
    t = Template()
    eksrole = t.add_resource(Role(
        "EKSRoletest",
        RoleName="EKS",
        ManagedPolicyArns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy", "arn:aws:iam::aws:policy/AmazonEKSServicePolicy" ],
        AssumeRolePolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
        Path="/"
    ))

    t.add_resource(PolicyType(
        "ekspolicy",
        PolicyName="eksypolicy",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "1",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeRegions",
                        "ec2:DescribeImages",
                        "ec2:DescribeInstances",
                        "ec2:DescribeTags",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeVpcs",
                        "iam:ListAccountAliases"
                    ],
                    "Resource": [
                        "*"
                    ]
                }
            ]
        },
        Roles=[Ref(eksrole)]
    ))
    role_id = GetAtt(eksrole, "Arn")
    return t, role_id


if __name__ == "__main__":
    t = Template()
    test = create_prod_template(t)
    print(t.to_yaml())
