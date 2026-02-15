import { Page } from "puppeteer";
import { Vulnerability, VulnerabilityType, Severity } from "../core/vulnerability-detector";

export interface PluginContext {
  page: Page;
  url: string;
  baseUrl: string;
  timeout: number;
  userAgent: string;
}

export interface VulnerabilityTestResult {
  found: boolean;
  vulnerability?: Vulnerability;
  error?: string;
}

export interface VulnerabilityPlugin {
  readonly name: string;
  readonly type: VulnerabilityType;
  readonly description: string;
  readonly enabled: boolean;
  
  /**
   * Test a URL parameter for this vulnerability
   */
  testParameter?(context: PluginContext, param: string, value: string): Promise<VulnerabilityTestResult>;
  
  /**
   * Test a form input for this vulnerability
   */
  testFormInput?(context: PluginContext, formData: FormData): Promise<VulnerabilityTestResult>;
  
  /**
   * Analyze page content for this vulnerability
   */
  analyzeContent?(context: PluginContext, content: string): Promise<Vulnerability[]>;
  
  /**
   * Analyze HTTP headers for this vulnerability
   */
  analyzeHeaders?(context: PluginContext, headers: Record<string, string>): Promise<Vulnerability[]>;
}

export interface FormData {
  action: string;
  method: string;
  inputs: Array<{
    name: string;
    type: string;
    value?: string;
  }>;
}

export abstract class BaseVulnerabilityPlugin implements VulnerabilityPlugin {
  abstract readonly name: string;
  abstract readonly type: VulnerabilityType;
  abstract readonly description: string;
  enabled = true;
  
  protected createVulnerability(
    title: string,
    description: string,
    url: string,
    severity: Severity,
    evidence?: string,
    remediation?: string,
    cwe?: string
  ): Vulnerability {
    return {
      type: this.type,
      severity,
      title,
      description,
      url,
      evidence,
      remediation,
      cwe,
    };
  }
  
  protected success(vulnerability: Vulnerability): VulnerabilityTestResult {
    return { found: true, vulnerability };
  }
  
  protected failure(error?: string): VulnerabilityTestResult {
    return { found: false, error };
  }
}
