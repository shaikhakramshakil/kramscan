import { BaseVulnerabilityPlugin, PluginContext } from "../types";

export class SQLInjectionPlugin extends BaseVulnerabilityPlugin {
  readonly name = "SQL Injection Detector";
  readonly type = "sqli" as const;
  readonly description = "Detects SQL Injection vulnerabilities";
  
  private readonly errorBasedPayloads = [
    "'",
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "' OR 1=1--",
    "' UNION SELECT 1--",
    "1' AND '1'='1",
  ];
  
  private readonly timeBasedPayloads = [
    "' AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
  ];
  
  private readonly sqlErrors = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL",
    "SQLite",
    "ODBC",
    "JET Database",
    "Microsoft Access Driver",
    "unterminated",
    "mysql_num_rows",
    "mysql_query",
    "Microsoft SQL Native Client error",
    "SQLServer JDBC Driver",
    "ORA-00933",
    "PG::SyntaxError",
    "Warning: pg_",
    "Syntax error",
  ];
  
  async testParameter(context: PluginContext, param: string, _value: string) {
    // Test for error-based SQL injection
    for (const payload of this.errorBasedPayloads) {
      try {
        const url = new URL(context.url);
        url.searchParams.set(param, payload);
        
        await context.page.goto(url.toString(), { 
          waitUntil: "networkidle2", 
          timeout: context.timeout 
        });
        
        const content = await context.page.content();
        
        for (const error of this.sqlErrors) {
          if (content.includes(error)) {
            return this.success(
              this.createVulnerability(
                "SQL Injection",
                `The parameter '${param}' is vulnerable to SQL injection. Database error messages were detected.`,
                context.url,
                "critical",
                `Error: ${error}`,
                "Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
                "CWE-89"
              )
            );
          }
        }
      } catch (error) {
        return this.failure((error as Error).message);
      }
    }
    
    // Test for time-based blind SQL injection
    let baselineTime = 0;
    try {
      const baselineStart = Date.now();
      await context.page.goto(context.url, { 
        waitUntil: "networkidle2", 
        timeout: context.timeout 
      });
      baselineTime = Date.now() - baselineStart;
    } catch (error) {
      return this.failure((error as Error).message);
    }
    
    for (const payload of this.timeBasedPayloads) {
      try {
        const url = new URL(context.url);
        url.searchParams.set(param, payload);
        
        const startTime = Date.now();
        await context.page.goto(url.toString(), { 
          waitUntil: "networkidle2", 
          timeout: context.timeout 
        });
        const testTime = Date.now() - startTime;
        
        if (testTime > baselineTime + 3000) {
          return this.success(
            this.createVulnerability(
              "Blind SQL Injection",
              `Time-based blind SQL injection detected on parameter '${param}'. Response time indicates successful payload execution.`,
              context.url,
              "high",
              `Response time increased by ${testTime - baselineTime}ms with sleep payload`,
              "Use parameterized queries. Implement input validation and proper error handling.",
              "CWE-89"
            )
          );
        }
      } catch (error) {
        return this.failure((error as Error).message);
      }
    }
    
    return this.failure();
  }
}
