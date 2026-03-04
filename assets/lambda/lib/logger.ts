/**
 * Logger utility that adds context (repository name and image tag) to log messages.
 * This helps distinguish logs from different images when using SingletonFunction.
 */

export interface LoggerContext {
  repositoryName: string;
  imageTag: string;
}

export class Logger {
  private prefix: string;

  constructor(context: LoggerContext) {
    this.prefix = `[${context.repositoryName}:${context.imageTag}]`;
  }

  log(message: string): void {
    console.log(`${this.prefix} ${message}`);
  }

  warn(message: string): void {
    console.warn(`${this.prefix} ${message}`);
  }

  error(message: string): void {
    console.error(`${this.prefix} ${message}`);
  }
}
