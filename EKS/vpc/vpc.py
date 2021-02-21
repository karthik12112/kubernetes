from troposphere import (
    Export,
    Sub,
    Output,
    Join,
    Parameter,
    Ref,
    Template
)
# from security_groups.eks_sg import create_sg
from troposphere.ec2 import (
    VPC,
)


def create_vpc(t):
    # ref_stack_id = Ref('AWS::StackId')
    # ref_region = Ref('AWS::Region')
    # ref_stack_name = Ref('AWS::StackName')
    # no_value = Ref("AWS::NoValue")
    # ref_account = Ref('AWS::AccountId')
    output = {}
    vpcenvcidr = t.add_parameter(Parameter(
        "VPCEnvCidr",
        Type="String",
        Description="VPC Cidr",
    ))
    output["vpcenvcidr"] = Ref(vpcenvcidr)
    env = t.add_parameter(Parameter(
        "Environment",
        Type="String",
        Description="The environment being deployed into",
    ))
    output["env"] = Ref(env)
    # t.add_condition(
    #     "ProdCheck",
    #     Or(
    #         Equals(Ref(env), "prod"),
    #         Equals(Ref(env), "staging")
    #     )
    # )
    service = t.add_parameter(Parameter(
        "Service",
        Type="String",
        Description="Service Name",
    ))
    output["service"] = Ref(service)
    # Service ID is the 3rd octet on CIDR
    service_id = t.add_parameter(Parameter(
        "ServiceID",
        Type="String",
        Description="Service ID",
        Default="0"
    ))
    output["service_id"] = Ref(service_id)
    vpc = t.add_resource(VPC(
        "VPC",
        CidrBlock=Join('', [output["vpcenvcidr"], ".", output["service_id"], ".0/16"]),
        EnableDnsSupport="true",
        EnableDnsHostnames="true",
        Tags=[
            {"Key": "Name", "Value": Ref(env)}
        ],
    ))
    output["vpc"] = Ref(vpc)
    outputs = t.add_output([
        Output(
            "VPC",
            Value=Ref(vpc),
            Export=Export(Sub("${AWS::StackName}-VPC")),
            Description="VPC"
        )
    ])
    # t = create_sg(t, output)
    # output["SubnetIds"] = [Ref(pubsubneta), Ref(pubsubnetb), Ref(pubsubnetc)]
    # SubnetIds = [Ref(pubsubneta), Ref(pubsubnetb), Ref(pubsubnetc)]
    # security_group_id = [GetAtt(sgtrusted, "GroupId")]
    return t, output


if __name__ == "__main__":
    t = Template()
    t.add_description("EKS stack")
    t, output = create_vpc(t)
    template = (t.to_json())
    print(template)
    # f = open("vpc.template", 'w+')
    # f.write(t)
    # f.close()
