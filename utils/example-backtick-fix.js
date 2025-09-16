#!/usr/bin/env node

/**
 * Example script showing how to properly escape backticks in JavaScript template literals
 * for attack flow diagrams containing PowerShell code.
 *
 * This demonstrates the issue and solution for preventing "Invalid or unexpected token" errors.
 */

console.log("=== Attack Flow JavaScript Template Literal Backtick Escaping Demo ===\n");

// PROBLEM: This will cause a JavaScript syntax error
console.log("❌ INCORRECT (causes syntax error):");
console.log("This JavaScript code will fail to parse:");
console.log('code: `Set-ItemProperty -Path "HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Features" `');
console.log('    `-Name "TamperProtection" -Value 0`');

// SOLUTION: Properly escaped backticks
console.log("\n✅ CORRECT (properly escaped):");
const phaseData = {
    1: {
        title: "Disable Windows Defender",
        // Note: Backticks inside the template literal content are escaped
        code: `Set-ItemProperty -Path "HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Features" \\\`\n    \\\`-Name "TamperProtection" -Value 0`
    }
};

console.log("This JavaScript code works correctly:");
console.log('code: `Set-ItemProperty -Path "HKLM:\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows Defender\\\\\\\\Features" \\\\\\`\\n    \\\\\\`-Name "TamperProtection" -Value 0`');

console.log("\n📋 Key Points:");
console.log("1. PowerShell line continuation backticks (`) must be escaped as (\\\\`) inside JavaScript template literals");
console.log("2. The template literal backticks themselves (outer `) should NOT be escaped");
console.log("3. Only escape backticks that are CONTENT within the template literal");
console.log("4. Test your generated HTML in a browser console to verify syntax");

console.log("\n🔧 Quick Fix Pattern:");
console.log("Find:    ` (backtick in PowerShell code inside template literals)");
console.log("Replace: \\\\` (double-escaped backtick)");

// Demonstrate the working code
console.log("\n🧪 Testing the corrected code:");
try {
    console.log("Phase 1 title:", phaseData[1].title);
    console.log("Phase 1 code preview:", phaseData[1].code.substring(0, 50) + "...");
    console.log("✅ JavaScript executed successfully!");
} catch (error) {
    console.log("❌ JavaScript error:", error.message);
}

console.log("\n📝 The actual issue in attack flow diagrams:");
console.log("When PowerShell commands with line continuation are embedded in HTML JavaScript,");
console.log("the backticks break JavaScript parsing, causing 'Invalid or unexpected token' errors.");

console.log("\n✅ Solution: Use the validation and fix utilities provided:");
console.log("./utils/validate-attack-flow-html.sh your_file.html");
console.log("./utils/fix-attack-flow-backticks.sh your_file.html");

console.log("\n🎯 Common problematic patterns:");
console.log("- Set-ItemProperty ... ` (line continuation)");
console.log("- Get-ItemProperty ... ` (line continuation)");
console.log("- New-Item ... ` (line continuation)");
console.log("- Remove-Item ... ` (line continuation)");

console.log("\n=== End Demo ===");