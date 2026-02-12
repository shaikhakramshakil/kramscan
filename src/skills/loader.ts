import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import { SkillMetadata } from "./types";

export function loadSkillMetadata(skillDir: string): SkillMetadata | null {
  const skillPath = path.join(skillDir, "skill.yaml");
  if (!fs.existsSync(skillPath)) {
    return null;
  }

  const raw = fs.readFileSync(skillPath, "utf-8");
  const doc = yaml.load(raw) as SkillMetadata | undefined;

  if (!doc || !doc.id || !doc.name) {
    return null;
  }

  return {
    id: doc.id,
    name: doc.name,
    description: doc.description ?? "",
    tags: doc.tags ?? [],
    category: doc.category
  };
}
