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
                            "AWS": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
        Path="/"
    ))
    role_id = GetAtt(eksrole, "Arn")
    return t, role_id
