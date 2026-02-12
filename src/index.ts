import { run } from "./cli";

run().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
