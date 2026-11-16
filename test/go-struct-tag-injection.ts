// Regression test for the Go struct-tag code-injection vulnerability (CWE-94).
//
// A JSON Schema property name is attacker-controlled. The Go renderer writes it
// into a struct tag that was emitted as a raw string literal (`json:"..."`).
// Because a raw string literal is delimited by backticks and cannot contain
// one, a property name containing a backtick used to terminate the literal
// early, turning the remainder of the name into arbitrary top-level Go code
// that would compile and run.
//
// This test renders Go from a schema whose property name carries such a payload
// and asserts the output is inert: the backtick must live inside an interpreted
// (double-quoted) string literal and must not introduce any top-level Go.
//
// Run with: ts-node --project src/tsconfig.json test/go-struct-tag-injection.ts

import { quicktype, SchemaTypeSource } from "../src/index";

const PAYLOAD = "a`};func init(){println(123)};var _ = func(){//";

function assert(cond: boolean, message: string): void {
    if (!cond) {
        console.error("FAIL: " + message);
        process.exit(1);
    }
}

async function main(): Promise<void> {
    const schema = JSON.stringify({
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        title: "Thing",
        properties: { [PAYLOAD]: { type: "string" } }
    });

    const source: SchemaTypeSource = { name: "Thing", schema } as any;
    const result = await quicktype({
        lang: "go",
        sources: [source],
        rendererOptions: { package: "main" }
    } as any);
    const go = result.lines.join("\n");

    // The payload backtick must not sit inside a raw string literal tag.
    assert(go.indexOf("`json:") < 0, "backtick-delimited raw struct tag must not be used for a name containing a backtick");

    // The tag must be an interpreted string literal carrying the escaped name.
    assert(go.indexOf('"json:\\"') >= 0, "struct tag for a backtick name must be a double-quoted Go string literal");

    // No part of the payload may become top-level Go code.
    assert(!/^\s*func init\s*\(/m.test(go), "payload must not inject a top-level func init");
    assert(go.indexOf("println(123)") < 0 || go.indexOf('"json:\\"') >= 0, "payload must remain inside a string literal");

    console.log("PASS: Go struct tag with a backtick in the property name is safely escaped");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
