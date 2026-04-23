import { run } from "./cli";
import { setupGlobalErrorHandlers } from "./core/errors";
import updateNotifier from "update-notifier";
import fs from "fs";
import path from "path";

// Ensure uncaught exceptions and unhandled rejections produce useful output
setupGlobalErrorHandlers();

try {
    const pkgPath = path.join(__dirname, "../package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    updateNotifier({ pkg }).notify({ isGlobal: true });
} catch (error) {
    // Silently ignore if update notification fails
}

run().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
