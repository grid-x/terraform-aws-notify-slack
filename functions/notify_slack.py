from __future__ import print_function
from urllib.error import HTTPError
import os, boto3, json, base64
import urllib.request, urllib.parse
import logging
import hashlib

accounts = {
    "aae9d79a60f753f541a63bd1b1d760bc": "dev",
    "39a6661a8b3f6cb6dc363ce91c0a9578": "staging",
    "5699182b286c1b617ffda1f0c5db34ca": "prod",
    "cd22ac23b5fa1235541b91ea1f1a299c": "ds-staging",
    "1568c3bdd4a42fea04e7da2871249ef1": "ds-prod",
    "55400ed1f95a6acd78a51f7f6efb6d5f": "gridbox",
}

cwPrefix = "https://eu-central-1.console.aws.amazon.com/cloudwatch/home?region=eu-central-1#logsV2:log-groups/log-group/cloudtrail-multi-region/log-events"
cwSuffix = "$26start$3D-43200000"  # last 12 hours
cwAlarms = {
    "UnauthorizedAPICalls": "$3FfilterPattern$3D$257B$2520($2524.errorCode$2520$253D$2520$2522*UnauthorizedOperation$2522)$2520$257C$257C$2520($2524.errorCode$2520$253D$2520$2522AccessDenied*$2522)$2520$257D",
    "IAMChanges": "$3FfilterPattern$3D$257B($2524.eventName$253DDeleteGroupPolicy)$257C$257C($2524.eventName$253DDeleteRolePolicy)$257C$257C($2524.eventName$253DDeleteUserPolicy)$257C$257C($2524.eventName$253DPutGroupPolicy)$257C$257C($2524.eventName$253DPutRolePolicy)$257C$257C($2524.eventName$253DPutUserPolicy)$257C$257C($2524.eventName$253DCreatePolicy)$257C$257C($2524.eventName$253DDeletePolicy)$257C$257C($2524.eventName$253DCreatePolicyVersion)$257C$257C($2524.eventName$253DDeletePolicyVersion)$257C$257C($2524.eventName$253DAttachRolePolicy)$257C$257C($2524.eventName$253DDetachRolePolicy)$257C$257C($2524.eventName$253DAttachUserPolicy)$257C$257C($2524.eventName$253DDetachUserPolicy)$257C$257C($2524.eventName$253DAttachGroupPolicy)$257C$257C($2524.eventName$253DDetachGroupPolicy)$257D",
    "SecurityGroupChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520AuthorizeSecurityGroupIngress)$2520$257C$257C$2520($2524.eventName$2520$253D$2520AuthorizeSecurityGroupEgress)$2520$257C$257C$2520($2524.eventName$2520$253D$2520RevokeSecurityGroupIngress)$2520$257C$257C$2520($2524.eventName$2520$253D$2520RevokeSecurityGroupEgress)$2520$257C$257C$2520($2524.eventName$2520$253D$2520CreateSecurityGroup)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteSecurityGroup)$257D",
    "VPCChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520CreateVpc)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteVpc)$2520$257C$257C$2520($2524.eventName$2520$253D$2520ModifyVpcAttribute)$2520$257C$257C$2520($2524.eventName$2520$253D$2520AcceptVpcPeeringConnection)$2520$257C$257C$2520($2524.eventName$2520$253D$2520CreateVpcPeeringConnection)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteVpcPeeringConnection)$2520$257C$257C$2520($2524.eventName$2520$253D$2520RejectVpcPeeringConnection)$2520$257C$257C$2520($2524.eventName$2520$253D$2520AttachClassicLinkVpc)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DetachClassicLinkVpc)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DisableVpcClassicLink)$2520$257C$257C$2520($2524.eventName$2520$253D$2520EnableVpcClassicLink)$2520$257D",
    "RouteTableChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520CreateRoute)$2520$257C$257C$2520($2524.eventName$2520$253D$2520CreateRouteTable)$2520$257C$257C$2520($2524.eventName$2520$253D$2520ReplaceRoute)$2520$257C$257C$2520($2524.eventName$2520$253D$2520ReplaceRouteTableAssociation)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteRouteTable)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteRoute)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DisassociateRouteTable)$2520$257D",
    "NetworkGWChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520CreateCustomerGateway)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteCustomerGateway)$2520$257C$257C$2520($2524.eventName$2520$253D$2520AttachInternetGateway)$2520$257C$257C$2520($2524.eventName$2520$253D$2520CreateInternetGateway)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteInternetGateway)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DetachInternetGateway)$2520$257D",
    "NoMFAConsoleSignin": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520$2522ConsoleLogin$2522)$2520$2526$2526$2520($2524.additionalEventData.MFAUsed$2521$253D$2520$2522Yes$2522)$2520$257D",
    "ConsoleSigninFailures": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520ConsoleLogin)$2520$2526$2526$2520($2524.errorMessage$2520$253D$2520$2522Failed$2520authentication$2522)$2520$257D",
    "CloudTrailCfgChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520CreateTrail)$2520$257C$257C$2520($2524.eventName$2520$253D$2520UpdateTrail)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteTrail)$2520$257C$257C$2520($2524.eventName$2520$253D$2520StartLogging)$2520$257C$257C$2520($2524.eventName$2520$253D$2520StopLogging)$2520$257D",
    "S3BucketPolicyChanges": "$3FfilterPattern$3D$257B$2520($2524.eventSource$2520$253D$2520s3.amazonaws.com)$2520$2526$2526$2520(($2524.eventName$2520$253D$2520PutBucketAcl)$2520$257C$257C$2520($2524.eventName$2520$253D$2520PutBucketPolicy)$2520$257C$257C$2520($2524.eventName$2520$253D$2520PutBucketCors)$2520$257C$257C$2520($2524.eventName$2520$253D$2520PutBucketLifecycle)$2520$257C$257C$2520($2524.eventName$2520$253D$2520PutBucketReplication)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteBucketPolicy)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteBucketCors)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteBucketLifecycle)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteBucketReplication))$2520$257D",
    "NACLChanges": "$3FfilterPattern$3D$257B$2520($2524.eventName$2520$253D$2520CreateNetworkAcl)$2520$257C$257C$2520($2524.eventName$2520$253D$2520CreateNetworkAclEntry)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteNetworkAcl)$2520$257C$257C$2520($2524.eventName$2520$253D$2520DeleteNetworkAclEntry)$2520$257C$257C$2520($2524.eventName$2520$253D$2520ReplaceNetworkAclEntry)$2520$257C$257C$2520($2524.eventName$2520$253D$2520ReplaceNetworkAclAssociation)$2520$257D",
    "OrganizationsChanges": "$3FfilterPattern$3D$257B+$2528$2524.eventSource+$253D+organizations.amazonaws.com$2529+$2526$2526+$2528$2528$2524.eventName+$253D+$2522AcceptHandshake$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522AttachPolicy$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522CreateAccount$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522CreateOrganizationalUnit$2522$2529+$257C$257C+$2528$2524.eventName$253D+$2522CreatePolicy$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DeclineHandshake$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DeleteOrganization$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DeleteOrganizationalUnit$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DeletePolicy$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DetachPolicy$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522DisablePolicyType$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522EnablePolicyType$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522InviteAccountToOrganization$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522LeaveOrganization$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522MoveAccount$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522RemoveAccountFromOrganization$2522$2529+$257C$257C+$2528$2524.eventName+$253D+$2522UpdatePolicy$2522$2529+$257C$257C+$2528$2524.eventName+$253D$2522UpdateOrganizationalUnit$2522$2529$2529+$257D",
    "RootUsage": "$3FfilterPattern$3D$257B+$2524.userIdentity.type+$253D+$2522Root$2522+$2526$2526+$2524.userIdentity.invokedBy+NOT+EXISTS+$2526$2526+$2524.eventType$2521$253D+$2522AwsServiceEvent$2522+$257D",
    "DisableOrDeleteCMK": "$3FfilterPattern$3D$257B+$2528$2524.eventSource+$253D+kms.amazonaws.com$2529+$2526$2526+$2528$2528$2524.eventName+$253D+DisableKey$2529+$257C$257C+$2528$2524.eventName+$253D+ScheduleKeyDeletion$2529$2529+$257D",
    "AWSConfigChanges": "$3FfilterPattern$3D$257B+$2528$2524.eventSource+$253D+config.amazonaws.com$2529+$2526$2526+$2528$2528$2524.eventName$253DStopConfigurationRecorder$2529$257C$257C$2528$2524.eventName$253DDeleteDeliveryChannel$2529$257C$257C$2528$2524.eventName$253DPutDeliveryChannel$2529$257C$257C$2528$2524.eventName$253DPutConfigurationRecorder$2529$2529+$257D",
}

# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ["AWS_REGION"]
    try:
        kms = boto3.client("kms", region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))[
            "Plaintext"
        ]
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")


def cloudwatch_notification(message, region):
    account = accounts[hashlib.md5(message["AWSAccountId"].encode("utf-8")).hexdigest()]
    states = {"OK": "good", "INSUFFICIENT_DATA": "warning", "ALARM": "danger"}

    alarmName = message["AlarmName"]

    fields = [
        {"title": "Alarm Name", "value": alarmName, "short": True},
        {"title": "Account", "value": account, "short": True},
    ]

    alarmURL = cwAlarms.get(alarmName)
    if alarmURL:
        fields.append(
            {
                "title": "Link to Logs",
                "value": "<" + cwPrefix + alarmURL + cwSuffix + "|Cloudwatch>",
            }
        )

    return {
        "color": states[message["NewStateValue"]],
        "fallback": "Alarm {} triggered".format(message["AlarmName"]),
        "mrkdwn_in": ["fields"],
        "fields": fields,
    }


def config_notification(message):
    account = accounts[hashlib.md5(message["account"].encode("utf-8")).hexdigest()]
    fields = [{"title": "Account", "value": account}]

    arn = message["detail"]["configurationItem"].get("ARN")

    if arn:
        fields.append({"title": "ARN", "value": arn, "short": False})

    for k, v in message["detail"]["configurationItemDiff"]["changedProperties"].items():
        if "previousValue" in v and "updatedValue" in v:
            fields.append(
                {"title": "-" + k, "value": str(v["previousValue"]), "short": True}
            )
            fields.append(
                {"title": "+" + k, "value": str(v["updatedValue"]), "short": True}
            )
        else:
            fields.append({"title": k, "value": str(v)})
    return {"fallback": "Config changed", "fields": fields}


def default_notification(subject, message):
    return {
        "fallback": "A new message",
        "fields": [
            {
                "title": subject if subject else "Message",
                "value": json.dumps(message) if type(message) is dict else message,
                "short": False,
            }
        ],
    }


# Send a message to a slack channel
def notify_slack(subject, message, region):
    slack_url = os.environ["SLACK_WEBHOOK_URL"]
    if not slack_url.startswith("http"):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ["SLACK_CHANNEL"]
    slack_username = os.environ["SLACK_USERNAME"]
    slack_emoji = os.environ["SLACK_EMOJI"]

    payload = {
        "channel": slack_channel,
        "username": slack_username,
        "icon_emoji": slack_emoji,
        "attachments": [],
    }

    if type(message) is str:
        try:
            message = json.loads(message)
        except json.JSONDecodeError as err:
            logging.exception(f"JSON decode error: {err}")

    if "AlarmName" in message:
        notification = cloudwatch_notification(message, region)
        payload["text"] = "AWS CloudWatch notification - " + message["AlarmName"]
        payload["attachments"].append(notification)
    elif (
        "detail" in message
        and message["detail"]["messageType"] == "ConfigurationItemChangeNotification"
    ):
        notification = config_notification(message)
        payload["text"] = "AWS Config Change"
        payload["attachments"].append(notification)
    else:
        payload["text"] = "AWS notification"
        payload["attachments"].append(default_notification(subject, message))

    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)

    try:
        result = urllib.request.urlopen(req, data)
        return json.dumps({"code": result.getcode(), "info": result.info().as_string()})

    except HTTPError as e:
        logging.error("{}: result".format(e))
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})


def lambda_handler(event, context):
    if "LOG_EVENTS" in os.environ and os.environ["LOG_EVENTS"] == "True":
        logging.warning("Event logging enabled: `{}`".format(json.dumps(event)))

    subject = event["Records"][0]["Sns"]["Subject"]
    message = event["Records"][0]["Sns"]["Message"]
    region = event["Records"][0]["Sns"]["TopicArn"].split(":")[3]
    response = notify_slack(subject, message, region)

    if json.loads(response)["code"] != 200:
        logging.error(
            "Error: received status `{}` using event `{}` and context `{}`".format(
                json.loads(response)["info"], event, context
            )
        )

    return response
