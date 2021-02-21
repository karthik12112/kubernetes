from troposphere import (
    Export,
    Sub,
    Output,
    Join,
    GetAtt,
    Select,
    GetAZs,
    Parameter,
    Ref,
    Tags,
    Template
)
# from security_groups.eks_sg import create_sg
from troposphere.ec2 import (
    SubnetRouteTableAssociation,
    EIP,
    Subnet,
    InternetGateway,
    NatGateway,
    VPCGatewayAttachment,
    Route,
    RouteTable
)


def create_subnet(t, output):
    ref_region = Ref('AWS::Region')

    igw = t.add_resource(InternetGateway(
        "InternetGateway",
        Tags=Tags(
            Name=Join("", [output["service"], "-", output["env"]])
        )
    ))
    GWattachment = t.add_resource(VPCGatewayAttachment(
        "AttachGateway",
        VpcId=output["vpc"],
        InternetGatewayId=Ref("InternetGateway"),
    ))
    # Pub Subnet Availability Zone A
    pubsubneta = t.add_resource(
        Subnet(
            'PubSubnetA',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '0', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("0", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PubA"])
            )
        )
    )
    # Pub Subnet Availability Zone B
    pubsubnetb = t.add_resource(
        Subnet(
            'PubSubnetB',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '1', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("1", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PubB"])
            )
        )
    )
    # Pub Subnet Availability Zone C
    pubsubnetc = t.add_resource(
        Subnet(
            'PubSubnetC',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '2', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("2", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PubC"])
            )
        )
    )
    # Private Subnet Availability Zone A
    privsubneta = t.add_resource(
        Subnet(
            'PrivSubnetA',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '3', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("0", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PrivA"])
            )
        )
    )
    # Private Subnet Availability Zone B
    privsubnetb = t.add_resource(
        Subnet(
            'PrivSubnetB',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '4', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("1", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PrivB"])
            )
        )
    )
    # Private Subnet Availability Zone C
    privsubnetc = t.add_resource(
        Subnet(
            'PrivSubnetC',
            CidrBlock=Join('', [output["vpcenvcidr"], '.', '5', '.0/24']),
            VpcId=output["vpc"],
            AvailabilityZone=Select("2", GetAZs(ref_region)),
            Tags=Tags(
                Name=Join("", [output["service"], "-", output["env"], "-PrivC"])
            )
        )
    )
    output["SubnetIds"] = {}
    output["SubnetIds"]["pubsubneta"] = Ref(pubsubneta)
    output["SubnetIds"]["pubsubnetb"] = Ref(pubsubnetb)
    output["SubnetIds"]["pubsubnetc"] = Ref(pubsubnetc)
    output["SubnetIds"]["privsubneta"] = Ref(privsubneta)
    output["SubnetIds"]["privsubnetb"] = Ref(privsubnetb)
    output["SubnetIds"]["privsubnetc"] = Ref(privsubnetc)
    # NAT Gateway
    # Availability Zone A
    nat_eip_a = t.add_resource(EIP(
        'NATeipA',
        Domain="vpc"
    ))
    nat_gw_a = t.add_resource(NatGateway(
        'NatGwA',
        AllocationId=GetAtt(nat_eip_a, 'AllocationId'),
        SubnetId=Ref(pubsubneta),
    ))
    # Availability Zone B
    nat_eip_b = t.add_resource(EIP(
        'NATeipB',
        Domain="vpc"
    ))
    nat_gw_b = t.add_resource(NatGateway(
        'NatGwB',
        AllocationId=GetAtt(nat_eip_b, 'AllocationId'),
        SubnetId=Ref(pubsubnetb),
    ))
    # Availability Zone C
    nat_eip_c = t.add_resource(EIP(
        'NATeipC',
        Domain="vpc"
    ))
    nat_gw_c = t.add_resource(NatGateway(
        'NatGwC',
        AllocationId=GetAtt(nat_eip_c, 'AllocationId'),
        SubnetId=Ref(pubsubnetc),
    ))
    pubroutetable = t.add_resource(RouteTable(
        "PubRouteTable",
        VpcId=output["vpc"],
        Tags=Tags(
            Name=Join("", [output["service"], "-", output["env"], "-", "PubRT"])
        )
    ))
    pubroute = t.add_resource(Route(
        "PubRoute",
        DependsOn="AttachGateway",
        RouteTableId=Ref(pubroutetable),
        DestinationCidrBlock="0.0.0.0/0",
        GatewayId=Ref(igw)
    ))
    privroutetablea = t.add_resource(RouteTable(
        "PrivRouteTableA",
        VpcId=output["vpc"],
        Tags=Tags(
            Name=Join("", [output["service"], "-", output["env"], "-", "PrivRT-A"])
        )
    ))
    privroutea = t.add_resource(Route(
        "PrivRouteA",
        RouteTableId=Ref(privroutetablea),
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=Ref(nat_gw_a)
    ))
    privroutetableb = t.add_resource(RouteTable(
        "PrivRouteTableB",
        VpcId=output["vpc"],
        Tags=Tags(
            Name=Join("", [output["service"], "-", output["env"], "-", "PrivRT-B"])
        )
    ))
    privrouteb = t.add_resource(Route(
        "PrivRouteB",
        RouteTableId=Ref(privroutetableb),
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=Ref(nat_gw_b)
    ))
    privroutetablec = t.add_resource(RouteTable(
        "PrivRouteTableC",
        VpcId=output["vpc"],
        Tags=Tags(
            Name=Join("", [output["service"], "-", output["env"], "-", "PrivRT-C"])
        )
    ))
    privroutec = t.add_resource(Route(
        "PrivRouteC",
        RouteTableId=Ref(privroutetablec),
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=Ref(nat_gw_c)
    ))
    subnetroutetableassociationpuba = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPubA',
        SubnetId=Ref(pubsubneta),
        RouteTableId=Ref(pubroutetable),
    ))
    subnetroutetableassociationpubb = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPubB',
        SubnetId=Ref(pubsubnetb),
        RouteTableId=Ref(pubroutetable),
    ))
    subnetroutetableassociationpubc = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPubC',
        SubnetId=Ref(pubsubnetc),
        RouteTableId=Ref(pubroutetable),
    ))
    subnetroutetableassociationpriva = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPrivA',
        SubnetId=Ref(privsubneta),
        RouteTableId=Ref(privroutetablea),
    ))
    subnetroutetableassociationprivb = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPrivB',
        SubnetId=Ref(privsubnetb),
        RouteTableId=Ref(privroutetableb),
    ))
    subnetroutetableassociationprivc = t.add_resource(SubnetRouteTableAssociation(
        'SubnetRouteTableAssociationPrivC',
        SubnetId=Ref(privsubnetc),
        RouteTableId=Ref(privroutetablec),
    ))

    outputs = t.add_output([
        Output(
            "IGW",
            Value=Ref(igw),
            Export=Export(Sub("${AWS::StackName}-IGW")),
            Description="Internet Gateway"
        ),
        Output(
            "NatGWA",
            Value=Ref(nat_gw_a),
            Export=Export(Sub("${AWS::StackName}-NATGatewayA")),
            Description="NAT Gateway AZ A"
        ),
        Output(
            "NatGWB",
            Value=Ref(nat_gw_b),
            Export=Export(Sub("${AWS::StackName}-NATGatewayB")),
            Description="NAT Gateway AZ B"
        ),
        Output(
            "NatGWC",
            Value=Ref(nat_gw_c),
            Export=Export(Sub("${AWS::StackName}-NATGatewayC")),
            Description="NAT Gateway AZ C"
        ),
        Output(
            "VPCEnvCidr",
            Value=output["vpcenvcidr"],
            Export=Export(Sub("${AWS::StackName}-CIDR")),
            Description="First 2 CIDR Block of the VPC"
        ),
        Output(
            "ServiceID",
            Value=output["service_id"],
            Export=Export(Sub("${AWS::StackName}-ServiceID")),
            Description="3rd Oct of CIDR block"
        ),
        Output(
            "PUBSUBNETA",
            Value=Ref(pubsubneta),
            Export=Export(Sub("${AWS::StackName}-PubSubnetA")),
            Description="Public A Subnet"
        ),
        Output(
            "PUBSUBNETB",
            Value=Ref(pubsubnetb),
            Export=Export(Sub("${AWS::StackName}-PubSubnetB")),
            Description="Public B Subnet"
        ),
        Output(
            "PUBSUBNETC",
            Value=Ref(pubsubnetc),
            Export=Export(Sub("${AWS::StackName}-PubSubnetC")),
            Description="Public C Subnet"
        ),
        Output(
            "PRIVSUBNETA",
            Value=Ref(privsubneta),
            Export=Export(Sub("${AWS::StackName}-PrivSubnetA")),
            Description="Priv A Subnet"
        ),
        Output(
            "PRIVSUBNETB",
            Value=Ref(privsubnetb),
            Export=Export(Sub("${AWS::StackName}-PrivSubnetB")),
            Description="Priv B Subnet"
        ),
        Output(
            "PRIVSUBNETC",
            Value=Ref(privsubnetc),
            Export=Export(Sub("${AWS::StackName}-PrivSubnetC")),
            Description="Priv C Subnet"
        ),
    ])
    # t = create_sg(t, output)
    # output["SubnetIds"] = [Ref(pubsubneta), Ref(pubsubnetb), Ref(pubsubnetc)]
    # SubnetIds = [Ref(pubsubneta), Ref(pubsubnetb), Ref(pubsubnetc)]
    # security_group_id = [GetAtt(sgtrusted, "GroupId")]
    return t, output


if __name__ == "__main__":
    t = Template()
    t.add_description("creates subnets")
    vpcenvcidr = t.add_parameter(Parameter(
        "VPCEnvCidr",
        Type="String",
        Description="VPC Cidr",
    ))
    env = t.add_parameter(Parameter(
        "Environment",
        Type="String",
        Description="The environment being deployed into",
    ))
    service = t.add_parameter(Parameter(
        "Service",
        Type="String",
        Description="Service Name",
    ))
    # Service ID is the 3rd octet on CIDR
    service_id = t.add_parameter(Parameter(
        "ServiceID",
        Type="String",
        Description="Service ID",
        Default="0"
    ))
    t, output = create_subnet(t)
    template = (t.to_json())
    print(template)
    #f = open("vpc.template", 'w+')
    #f.write(t)
    #f.close()
