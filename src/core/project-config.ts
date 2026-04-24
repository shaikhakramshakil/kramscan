/**
 * Project-level configuration (.kramscanrc)
 *
 * Discovers and loads a .kramscanrc file from the current working directory
 * (or any parent directory) and merges it with the global config. Project
 * settings override global settings, but sensitive fields (ai.apiKey) are
 * never read from the project file.
 */

import * as fs from "fs";
import * as path from "path";

export const PROJECT_CONFIG_FILENAME = ".kramscanrc";

/**
 * Represents the subset of config fields that can be set at the project level.
 * Intentionally excludes ai.apiKey for security.
 */
export interface ProjectConfig {
    scan?: {
        defaultProfile?: string;
        defaultTimeout?: number;
        maxThreads?: number;
        followRedirects?: boolean;
        verifySSL?: boolean;
        rateLimitPerSecond?: number;
        strictScope?: boolean;
        include?: string[];
        exclude?: string[];
        profiles?: Record<string, {
            depth?: number;
            timeout?: number;
            maxPages?: number;
            maxLinksPerPage?: number;
        }>;
    };
    report?: {
        defaultFormat?: string;
        companyName?: string;
        includeScreenshots?: boolean;
        severityThreshold?: string;
    };
    gate?: {
        failOn?: string;
        maxVulns?: number;
    };
    plugins?: {
        disabled?: string[];
    };
}

/**
 * Search for a .kramscanrc file starting from `startDir` and walking up
 * to the filesystem root. Returns the parsed contents and file path,
 * or null if no file is found.
 */
export function findProjectConfig(startDir: string = process.cwd()): { config: ProjectConfig; filepath: string } | null {
    for (let dir = path.resolve(startDir); ; dir = path.dirname(dir)) {
        const candidate = path.join(dir, PROJECT_CONFIG_FILENAME);

        if (fs.existsSync(candidate)) {
            try {
                const raw = fs.readFileSync(candidate, "utf-8");
                const parsed = JSON.parse(raw) as ProjectConfig;

                // Strip any ai.apiKey that might have been added by mistake
                const sanitized = parsed as Record<string, unknown>;
                if (sanitized.ai && typeof sanitized.ai === "object") {
                    delete (sanitized.ai as Record<string, unknown>).apiKey;
                }

                return { config: parsed, filepath: candidate };
            } catch {
                // Malformed file — skip it silently
                return null;
            }
        }

        const parent = path.dirname(dir);
        if (parent === dir) break; // reached filesystem root
    }

    return null;
}

/**
 * Deep merge `source` into `target`, returning a new object. Arrays are
 * replaced, not concatenated. Undefined values in source are skipped.
 */
export function deepMerge<T extends Record<string, unknown>>(target: T, source: Record<string, unknown>): T {
    const result = { ...target };

    for (const key of Object.keys(source)) {
        const srcVal = source[key];
        const tgtVal = (result as Record<string, unknown>)[key];

        if (srcVal === undefined) continue;

        if (
            srcVal !== null &&
            typeof srcVal === "object" &&
            !Array.isArray(srcVal) &&
            tgtVal !== null &&
            typeof tgtVal === "object" &&
            !Array.isArray(tgtVal)
        ) {
            (result as Record<string, unknown>)[key] = deepMerge(
                tgtVal as Record<string, unknown>,
                srcVal as Record<string, unknown>
            );
        } else {
            (result as Record<string, unknown>)[key] = srcVal;
        }
    }

    return result;
}
