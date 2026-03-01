import {
  CloudFormationClient,
  DescribeStacksCommand,
  ResourceStatus,
} from '@aws-sdk/client-cloudformation';
import { mockClient } from 'aws-sdk-client-mock';
import { isRollbackInProgress } from '../lib/cloudformation-utils';

const cfnMock = mockClient(CloudFormationClient);

describe('cloudformation-utils', () => {
  beforeEach(() => {
    cfnMock.reset();
  });

  describe('isRollbackInProgress', () => {
    const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345678';

    test('should return true when stack status is ROLLBACK_IN_PROGRESS', async () => {
      cfnMock.on(DescribeStacksCommand).resolves({
        Stacks: [
          {
            StackId: stackId,
            StackName: 'test-stack',
            StackStatus: ResourceStatus.ROLLBACK_IN_PROGRESS,
            CreationTime: new Date(),
          },
        ],
      });

      const result = await isRollbackInProgress(stackId);

      expect(result).toBe(true);
      expect(cfnMock.calls()).toHaveLength(1);
      const call = cfnMock.call(0);
      const command = call.args[0] as DescribeStacksCommand;
      expect(command.input.StackName).toBe(stackId);
    });

    test('should return true when stack status is UPDATE_ROLLBACK_IN_PROGRESS', async () => {
      cfnMock.on(DescribeStacksCommand).resolves({
        Stacks: [
          {
            StackId: stackId,
            StackName: 'test-stack',
            StackStatus: ResourceStatus.UPDATE_ROLLBACK_IN_PROGRESS,
            CreationTime: new Date(),
          },
        ],
      });

      const result = await isRollbackInProgress(stackId);

      expect(result).toBe(true);
    });

    test('should return false when stack status is CREATE_COMPLETE', async () => {
      cfnMock.on(DescribeStacksCommand).resolves({
        Stacks: [
          {
            StackId: stackId,
            StackName: 'test-stack',
            StackStatus: ResourceStatus.CREATE_COMPLETE,
            CreationTime: new Date(),
          },
        ],
      });

      const result = await isRollbackInProgress(stackId);

      expect(result).toBe(false);
    });

    test('should throw error when no stacks are returned', async () => {
      cfnMock.on(DescribeStacksCommand).resolves({
        Stacks: [],
      });

      await expect(isRollbackInProgress(stackId)).rejects.toThrow(
        `Stack not found or no stacks returned from DescribeStacks command, stackId: ${stackId}`,
      );
    });

    test('should throw error when Stacks is undefined', async () => {
      cfnMock.on(DescribeStacksCommand).resolves({});

      await expect(isRollbackInProgress(stackId)).rejects.toThrow(
        `Stack not found or no stacks returned from DescribeStacks command, stackId: ${stackId}`,
      );
    });

    test('should handle CloudFormation API errors', async () => {
      const error = new Error('CloudFormation API error');
      cfnMock.on(DescribeStacksCommand).rejects(error);

      await expect(isRollbackInProgress(stackId)).rejects.toThrow('CloudFormation API error');
    });
  });
});
