import {
  CloudFormationClient,
  DescribeStacksCommand,
  ResourceStatus,
} from '@aws-sdk/client-cloudformation';

const cfnClient = new CloudFormationClient();

export const isRollbackInProgress = async (stackId: string): Promise<boolean> => {
  const command = new DescribeStacksCommand({
    StackName: stackId,
  });
  const response = await cfnClient.send(command);

  if (response.Stacks && response.Stacks.length > 0) {
    const stackStatus = response.Stacks[0].StackStatus;
    return (
      stackStatus === ResourceStatus.ROLLBACK_IN_PROGRESS ||
      stackStatus === ResourceStatus.UPDATE_ROLLBACK_IN_PROGRESS
    );
  }

  throw new Error(
    `Stack not found or no stacks returned from DescribeStacks command, stackId: ${stackId}`,
  );
};
