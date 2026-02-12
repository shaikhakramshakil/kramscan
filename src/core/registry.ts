import fs from "fs";
import path from "path";
import { SkillMetadata } from "../skills/types";
import { loadSkillMetadata } from "../skills/loader";

function getSkillsRoot(): string {
  return path.resolve(process.cwd(), "skills");
}

export function listSkills(): SkillMetadata[] {
  const skillsRoot = getSkillsRoot();
  if (!fs.existsSync(skillsRoot)) {
    return [];
  }

  const entries = fs.readdirSync(skillsRoot, { withFileTypes: true });
  const skills: SkillMetadata[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }

    const skillDir = path.join(skillsRoot, entry.name);
    const meta = loadSkillMetadata(skillDir);
    if (meta) {
      skills.push(meta);
    }
  }

  return skills;
}

export function getSkillMetadata(skillId: string): SkillMetadata | undefined {
  return listSkills().find((skill) => skill.id === skillId);
}
