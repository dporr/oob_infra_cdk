from constructs import Construct
from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_ec2 as ec2,
    CfnOutput
)



class OobInfraCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.public_vpc =  ec2.Vpc(self,
                                   "public_vpc",
                                   restrict_default_security_group= True,
                                #    ip_addresses= ec2.IpAddresses("10.0.0.0/16"),
                                #    subnet_configuration= ec2.SubnetConfiguration(
                                #     cidr_mask= 24,
                                #     name = "igw",
                                    subnet_configuration = [ec2.SubnetConfiguration( 
                                        name = "vpc-public-subnet",
                                        subnet_type = ec2.SubnetType.PUBLIC )
                                        ]
                                #    )                          
        )
        self.instance_role = iam.Role(
            self,
            "ec2_instance_role",
            assumed_by = iam.ServicePrincipal("ec2.amazonaws.com")
        )
        #Adding manged policy  for SSM. This is needed to SSH into the isntance over a secure channel w/o exposing the SSH service over the internet
        self.instance_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name('AmazonSSMManagedInstanceCore')
        )

        #Create ec2 instance
        #Copied from: https://medium.com/@thecoderefinery/aws-cdk-how-to-install-ssm-agent-via-userdata-32029fe2afbd
        #define a user data script to install & launch our web server
        self.ssm_user_data = ec2.UserData.for_linux()
        #TODO: Is there a best way of getting SSM agent w/o hardcoding it here?
        SSM_AGENT_RPM = "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"
        OOB_DOMAIN = "oob.theartofhacking.club"
        INTERACTSSH_LATEST = "https://github.com/projectdiscovery/interactsh/releases/download/v1.1.9/interactsh-server_1.1.9_linux_amd64.zip"
        self.ssm_user_data.add_commands(f"sudo yum install -y ${SSM_AGENT_RPM}", "sudo systemctl status amazon-ssm-agent")
        #Install and instantiate interactsh-server
        self.ssm_user_data.add_commands(f"curl -L -o interactsh.zip {INTERACTSSH_LATEST}")
        self.ssm_user_data.add_commands("unzip interactsh.zip", "chmod +x interactsh-server", "mv interactsh-server /usr/bin/interactsh-server")
        self.ssm_user_data.add_commands(f"interactsh-server -domain {OOB_DOMAIN}")
        self.ec2_instance = ec2.Instance(
            self,
            "ec2-instance",
            vpc = self.public_vpc,
            #Keep it cheap https://aws.amazon.com/ec2/instance-types/t2/
            #DigitalOcean is cheaper... https://www.digitalocean.com/pricing/droplets
            instance_type = ec2.InstanceType.of(ec2.InstanceClass.T2,
                                                ec2.InstanceSize.MICRO),
            machine_image =  ec2.MachineImage.latest_amazon_linux2(),
            role = self.instance_role,
            instance_name = "ec2-instance",
            user_data = self.ssm_user_data,
            associate_public_ip_address = True,
            require_imdsv2 = True
        )
        CfnOutput(
            self,
            "oob-instance-id",
            value = self.ec2_instance.instance_id
        )
        CfnOutput(
            self,
            "oob-instance-ip:dns",
            value = f"{self.ec2_instance.instance_public_ip}:{self.ec2_instance.instance_public_dns_name}",
            export_name="ec2-public-ip")
        #Add SSM permissions to initiate sessions from EC2 console and CLI
        #as described here: https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-quickstart.html
        self.instance_role.add_to_policy(
            iam.PolicyStatement(
                effect = iam.Effect.ALLOW,
                actions =  ['ssm:StartSession','ssm:SendCommand'],
                #TODO: Scope down to region/account
                resources = ["arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell"]
            )
        )

        self.instance_role.add_to_policy(
            iam.PolicyStatement(
                effect = iam.Effect.ALLOW,
                actions = ['ssm:DescribeSessions',
                            'ssm:GetConnectionStatus',
                            'ssm:DescribeInstanceInformation',
                            'ssm:DescribeInstanceProperties',
                            'ec2:DescribeInstances'],
                #TODO: Scope down to region/account
                resources = ['*']
            )
        )

        # Add SG rules for the listeners
        sg = ec2.SecurityGroup(self, "sg-interactsh-listeners",
                               vpc = self.public_vpc )
        sg.add_ingress_rule(peer = ec2.Peer.any_ipv4(), 
                            connection = ec2.Port.tcp(80),
                            description="Allow HTTP access from anywhere")
        sg.add_ingress_rule(peer = ec2.Peer.any_ipv4(), 
                            connection = ec2.Port.tcp(443),
                            description="Allow HTTPS access from anywhere")
        self.ec2_instance.add_security_group(sg)