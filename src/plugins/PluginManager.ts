import { Page } from "puppeteer";
import { VulnerabilityPlugin, PluginContext, FormData } from "./types";
import { Vulnerability } from "../core/vulnerability-detector";

export interface PluginExecutionResult {
  plugin: string;
  vulnerabilities: Vulnerability[];
  errors: Array<{ url: string; error: string }>;
  duration: number;
}

export class PluginManager {
  private plugins: Map<string, VulnerabilityPlugin> = new Map();
  private enabledPlugins: Set<string> = new Set();
  
  register(plugin: VulnerabilityPlugin): void {
    this.plugins.set(plugin.name, plugin);
    if (plugin.enabled) {
      this.enabledPlugins.add(plugin.name);
    }
  }
  
  unregister(pluginName: string): boolean {
    this.enabledPlugins.delete(pluginName);
    return this.plugins.delete(pluginName);
  }
  
  enable(pluginName: string): boolean {
    if (this.plugins.has(pluginName)) {
      this.enabledPlugins.add(pluginName);
      return true;
    }
    return false;
  }
  
  disable(pluginName: string): boolean {
    return this.enabledPlugins.delete(pluginName);
  }
  
  getPlugin(name: string): VulnerabilityPlugin | undefined {
    return this.plugins.get(name);
  }
  
  getAllPlugins(): VulnerabilityPlugin[] {
    return Array.from(this.plugins.values());
  }
  
  getEnabledPlugins(): VulnerabilityPlugin[] {
    return Array.from(this.enabledPlugins)
      .map(name => this.plugins.get(name))
      .filter((p): p is VulnerabilityPlugin => p !== undefined);
  }
  
  async testParameter(
    context: PluginContext,
    param: string,
    value: string
  ): Promise<PluginExecutionResult[]> {
    const results: PluginExecutionResult[] = [];
    
    for (const plugin of this.getEnabledPlugins()) {
      if (!plugin.testParameter) continue;
      
      const startTime = Date.now();
      const vulnerabilities: Vulnerability[] = [];
      const errors: Array<{ url: string; error: string }> = [];
      
      try {
        const result = await plugin.testParameter(context, param, value);
        if (result.found && result.vulnerability) {
          vulnerabilities.push(result.vulnerability);
        }
        if (result.error) {
          errors.push({ url: context.url, error: result.error });
        }
      } catch (error) {
        errors.push({ 
          url: context.url, 
          error: (error as Error).message 
        });
      }
      
      results.push({
        plugin: plugin.name,
        vulnerabilities,
        errors,
        duration: Date.now() - startTime,
      });
    }
    
    return results;
  }
  
  async testFormInput(
    context: PluginContext,
    formData: FormData
  ): Promise<PluginExecutionResult[]> {
    const results: PluginExecutionResult[] = [];
    
    for (const plugin of this.getEnabledPlugins()) {
      if (!plugin.testFormInput) continue;
      
      const startTime = Date.now();
      const vulnerabilities: Vulnerability[] = [];
      const errors: Array<{ url: string; error: string }> = [];
      
      try {
        const result = await plugin.testFormInput(context, formData);
        if (result.found && result.vulnerability) {
          vulnerabilities.push(result.vulnerability);
        }
        if (result.error) {
          errors.push({ url: context.url, error: result.error });
        }
      } catch (error) {
        errors.push({ 
          url: context.url, 
          error: (error as Error).message 
        });
      }
      
      results.push({
        plugin: plugin.name,
        vulnerabilities,
        errors,
        duration: Date.now() - startTime,
      });
    }
    
    return results;
  }
  
  async analyzeContent(
    context: PluginContext,
    content: string
  ): Promise<PluginExecutionResult[]> {
    const results: PluginExecutionResult[] = [];
    
    for (const plugin of this.getEnabledPlugins()) {
      if (!plugin.analyzeContent) continue;
      
      const startTime = Date.now();
      const errors: Array<{ url: string; error: string }> = [];
      
      try {
        const vulnerabilities = await plugin.analyzeContent(context, content);
        
        results.push({
          plugin: plugin.name,
          vulnerabilities,
          errors,
          duration: Date.now() - startTime,
        });
      } catch (error) {
        errors.push({ 
          url: context.url, 
          error: (error as Error).message 
        });
        
        results.push({
          plugin: plugin.name,
          vulnerabilities: [],
          errors,
          duration: Date.now() - startTime,
        });
      }
    }
    
    return results;
  }
  
  async analyzeHeaders(
    context: PluginContext,
    headers: Record<string, string>
  ): Promise<PluginExecutionResult[]> {
    const results: PluginExecutionResult[] = [];
    
    for (const plugin of this.getEnabledPlugins()) {
      if (!plugin.analyzeHeaders) continue;
      
      const startTime = Date.now();
      const errors: Array<{ url: string; error: string }> = [];
      
      try {
        const vulnerabilities = await plugin.analyzeHeaders(context, headers);
        
        results.push({
          plugin: plugin.name,
          vulnerabilities,
          errors,
          duration: Date.now() - startTime,
        });
      } catch (error) {
        errors.push({ 
          url: context.url, 
          error: (error as Error).message 
        });
        
        results.push({
          plugin: plugin.name,
          vulnerabilities: [],
          errors,
          duration: Date.now() - startTime,
        });
      }
    }
    
    return results;
  }
}

export const pluginManager = new PluginManager();
