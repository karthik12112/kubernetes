from troposphere.eks import (Cluster, ResourcesVpcConfig)
from vpc.vpc import create_vpc
from subnets.subnets import create_subnet
from iam.iam_eks import (create_prod_template)
from troposphere import Parameter, Ref, Template
from security_groups.eks_sg import create_sg
from troposphere import (
    Template,
    Select,
    GetAZs,
    GetAtt,
    Tags,
    Sub
)
from troposphere.iam import (
    Role,
    PolicyType,
    InstanceProfile
)
from troposphere.policies import (
    AutoScalingRollingUpdate,
    CreationPolicy,
    ResourceSignal,
    UpdatePolicy
)
from troposphere import Base64, Join
from troposphere import Parameter, Ref, Template
from troposphere import cloudformation, autoscaling
from troposphere.autoscaling import AutoScalingGroup, Tag
from troposphere.autoscaling import LaunchConfiguration
from troposphere.elasticloadbalancing import LoadBalancer
from troposphere.policies import (
    AutoScalingReplacingUpdate, AutoScalingRollingUpdate, UpdatePolicy
)
import troposphere.ec2 as ec2
import troposphere.elasticloadbalancing as elb
t = Template()
# prints subnetid list and template to create role
t, role_id = create_prod_template(t)
t, vpcids = create_vpc(t)
t, subnetids = create_subnet(t, vpcids)
t, sg_output = create_sg(t, subnetids)
sg_output_id_list = []
for x, y in sg_output.items():
    sg_output_id_list.append(y)

subnetids_output_id_list = []
for x, y in subnetids["SubnetIds"].items():
    subnetids_output_id_list.append(y)

ref_region = Ref('AWS::Region')
# prints roleid and template to create role
ClusterName = t.add_parameter(Parameter(
    "ClusterName",
    Type="String",
    Description="Name of an eks",
    Default="test-eks"
))
eksResourcesVpcConfig = ResourcesVpcConfig(
    SecurityGroupIds=sg_output_id_list,
    SubnetIds=subnetids_output_id_list
    )

eks = t.add_resource(Cluster(
    "eks",
    Name=Ref(ClusterName),
    ResourcesVpcConfig=eksResourcesVpcConfig,
    RoleArn=role_id
    ))

AmiId = t.add_parameter(Parameter(
    "AmiId",
    Type="String",
    Default="ami-0d3998d69ebe9b214",
    Description="The AMI id for the api instances",
))

KeyName = t.add_parameter(Parameter(
    "KeyName",
    Type="String",
    Description="Name of an existing EC2 KeyPair to enable SSH access",
    MinLength="1",
    AllowedPattern="[\x20-\x7E]*",
    MaxLength="255",
    Default="karthik-lab",
    ConstraintDescription="can contain only ASCII characters.",
))

ec2role = t.add_resource(Role(
    "Ec2Roletest",
    RoleName="eksworker",
    ManagedPolicyArns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy", "arn:aws:iam::aws:policy/AmazonEKSServicePolicy", "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"],
    AssumeRolePolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": [
                            "ssm.amazonaws.com",
                            "ec2.amazonaws.com"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
    Path="/"
))
StackName = Ref('AWS::StackName')
region = Ref('AWS::Region')
clustername = Ref(ClusterName)
SSMEC2 = t.add_resource(InstanceProfile(
        "SSMEC2",
        InstanceProfileName="SSM-EC2",
        Roles=[Ref("Ec2Roletest")]
    ))
LaunchConfig = t.add_resource(LaunchConfiguration(
    "LaunchConfiguration",
    UserData=Base64(Join('', [
        "#!/bin/bash\n",
        "/etc/eks/bootstrap.sh ", clustername, "\n"
        "INSTANCEID=$(curl -s -m 60 http://169.254.169.254/latest/meta-data/instance-id)", "\n"
        "/opt/aws/bin/cfn-signal -e $?",
        " --resource 'autoScalingGroup'",
        " --stack ", Ref("AWS::StackName"),
        " --region ", Ref("AWS::Region"), "\n"
    ])),
    ImageId=Ref(AmiId),
    AssociatePublicIpAddress=True,
    KeyName=Ref(KeyName),
    IamInstanceProfile=Ref("SSMEC2"),
    SecurityGroups=sg_output_id_list,
    InstanceType="t2.micro",
))
AutoScalingGroup = t.add_resource(AutoScalingGroup(
    "autoScalingGroup",
    DependsOn='eks',
    DesiredCapacity=3,
    MinSize=1,
    MaxSize=3,
    VPCZoneIdentifier=subnetids_output_id_list,
    LaunchConfigurationName=Ref("LaunchConfiguration"),
    UpdatePolicy=UpdatePolicy(
        AutoScalingRollingUpdate=AutoScalingRollingUpdate(
            PauseTime="PT15M",
            WaitOnResourceSignals=True,
            MinInstancesInService="1",
        )
    )
))

if __name__ == "__main__":
    template = (t.to_json())
    print template
    # f = open("network_backoffice.template", 'w+')
    # f.write(template)
    # f.close()
