import boto3
from botocore.exceptions import ClientError

def publish_to_sns(topic_arn: str, subject: str, message: str) -> None:
    """
    Publish a message to the given SNS topic.
    Raises ClientError on failure.
    """
    sns = boto3.client("sns")
    try:
        response = sns.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        # Optionally, you could print or log response["MessageId"]
    except ClientError as e:
        # Bubble up the exception so main() can catch it
        raise
