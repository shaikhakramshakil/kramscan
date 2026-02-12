import { Finding, SkillContext, SkillResult } from "./types";

type SkillRunner = (context: SkillContext) => Promise<SkillResult>;

async function runHeadersSkill(context: SkillContext): Promise<SkillResult> {
  const response = await context.http.get(context.targetUrl);
  const headers: Record<string, string> = {};

  for (const [key, value] of Object.entries(response.headers)) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }

  const checks: Array<{
    key: string;
    title: string;
    recommendation: string;
  }> = [
    {
      key: "strict-transport-security",
      title: "Missing HSTS header",
      recommendation: "Enable Strict-Transport-Security with a long max-age and includeSubDomains."
    },
    {
      key: "content-security-policy",
      title: "Missing Content-Security-Policy header",
      recommendation: "Define a CSP to restrict scripts, styles, and frames."
    },
    {
      key: "x-frame-options",
      title: "Missing X-Frame-Options header",
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN."
    },
    {
      key: "x-content-type-options",
      title: "Missing X-Content-Type-Options header",
      recommendation: "Set X-Content-Type-Options to nosniff."
    },
    {
      key: "referrer-policy",
      title: "Missing Referrer-Policy header",
      recommendation: "Set Referrer-Policy to strict-origin-when-cross-origin or similar."
    },
    {
      key: "permissions-policy",
      title: "Missing Permissions-Policy header",
      recommendation: "Set Permissions-Policy to restrict sensitive browser APIs."
    }
  ];

  const findings: Finding[] = checks
    .filter((check) => !headers[check.key])
    .map((check) => ({
      id: `headers-${check.key}`,
      skillId: "headers",
      title: check.title,
      severity: "low",
      description: `The response did not include the ${check.key} header.`,
      recommendation: check.recommendation
    }));

  return {
    skillId: "headers",
    findings
  };
}

async function runPlaceholderSkill(skillId: string, context: SkillContext): Promise<SkillResult> {
  context.logger.warn(`${skillId} is not implemented yet. Returning no findings.`);
  return {
    skillId,
    findings: []
  };
}

export const builtinSkillRunners: Record<string, SkillRunner> = {
  headers: runHeadersSkill,
  sqli: (context) => runPlaceholderSkill("sqli", context),
  xss: (context) => runPlaceholderSkill("xss", context),
  csrf: (context) => runPlaceholderSkill("csrf", context),
  idor: (context) => runPlaceholderSkill("idor", context),
  jwt: (context) => runPlaceholderSkill("jwt", context)
};
