import { Skill, SkillContext, SkillResult } from "./types";

export abstract class BaseSkill implements Skill {
  abstract id: string;
  abstract name: string;
  abstract description: string;
  abstract tags: string[];

  abstract run(context: SkillContext): Promise<SkillResult>;
}
