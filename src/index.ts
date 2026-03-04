import { run } from "./cli";
import { setupGlobalErrorHandlers } from "./core/errors";

// Ensure uncaught exceptions and unhandled rejections produce useful output
setupGlobalErrorHandlers();

run().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
