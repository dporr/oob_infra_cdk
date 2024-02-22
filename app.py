#!/usr/bin/env python3

import aws_cdk as cdk

from oob_infra_cdk.oob_infra_cdk_stack import OobInfraCdkStack


app = cdk.App()
OobInfraCdkStack(app, "OobInfraCdkStack")

app.synth()
