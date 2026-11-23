import pc from 'picocolors';

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

export class Logger {
  public static info(message: string, context?: string): void {
    const ctx = context ? pc.cyan(`[${context}] `) : '';
    console.log(`${pc.blue('ℹ')} ${ctx}${message}`);
  }

  public static success(message: string, context?: string): void {
    const ctx = context ? pc.cyan(`[${context}] `) : '';
    console.log(`${pc.green('✔')} ${ctx}${pc.green(message)}`);
  }

  public static warn(message: string, context?: string): void {
    const ctx = context ? pc.yellow(`[${context}] `) : '';
    console.warn(`${pc.yellow('⚠')} ${ctx}${pc.yellow(message)}`);
  }

  public static error(message: string, error?: unknown, context?: string): void {
    const ctx = context ? pc.red(`[${context}] `) : '';
    console.error(`${pc.red('✖')} ${ctx}${pc.red(message)}`);
    if (error && error instanceof Error && error.stack) {
      console.error(pc.gray(error.stack));
    }
  }
}
