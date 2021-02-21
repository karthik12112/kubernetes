from troposphere.ec2 import (
    SecurityGroup,
    SecurityGroupRule
)

from troposphere import (
    Template,
    GetAtt,
    Join
)
import argparse


def create_sg(t, vpc):
    sglocal = t.add_resource(SecurityGroup(
        "VPCAccess",
        GroupDescription="VPC Access Only",
        SecurityGroupIngress=[
            SecurityGroupRule(
                IpProtocol='-1',
                CidrIp=Join('', [vpc["vpcenvcidr"], '.', vpc["service_id"], '.0/24']),
                FromPort='-1',
                ToPort='-1'
            )
        ],
        VpcId=vpc['vpc']
    ))
    sgtrusted = t.add_resource(SecurityGroup(
        "TrustedAccess",
        GroupDescription="Access From Trusted Locations",
        SecurityGroupIngress=[
            # ECS Offices
            SecurityGroupRule(
                IpProtocol='-1',
                CidrIp=Join('', ['74.117.20.10/32']),
                FromPort='-1',
                ToPort='-1'
            ),
            SecurityGroupRule(
                IpProtocol='-1',
                CidrIp=Join('', ['74.117.22.10/32']),
                FromPort='-1',
                ToPort='-1'
            ),
            SecurityGroupRule(
                IpProtocol='-1',
                CidrIp=Join('', ['199.106.147.10/32']),
                FromPort='-1',
                ToPort='-1'
            )
        ],
        VpcId=vpc['vpc']
    ))
    output_sg = {}
    output_sg["sgtrusted"] = GetAtt(sgtrusted, "GroupId")
    output_sg["sglocal"] = GetAtt(sglocal, "GroupId")
    return t, output_sg


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--vpc", action="store", help="vpc id")
    parseargs = parser.parse_args()
    vpc = parseargs.vpc
    t = Template()
    t = create_sg(t, vpc)
    template = (t.to_json())
    print(template)
    # f = open("vpc.template", 'w+')
    # f.write(t)
    # f.close()
