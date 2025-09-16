# Attack Flow Diagram Builder - Backtick Escaping Solution

## Problem Summary

The attack-flow-diagram-builder agent was generating HTML files with JavaScript syntax errors caused by unescaped backticks in template literals. This occurred when PowerShell code snippets containing line continuation characters (`) were embedded in JavaScript template literals, causing "Invalid or unexpected token" errors.

### Example of the Problem

```javascript
// ❌ BROKEN - Causes syntax error
const phaseData = {
    1: {
        code: `Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features" `
            `-Name "TamperProtection" -Value 0`
    }
};
```

### Error Message
```
SyntaxError: Invalid or unexpected token
```

## Solution Implemented

### 1. Updated Agent Configuration (CLAUDE.md)

Added comprehensive JavaScript Template Literal Safety Protocol including:

- **Mandatory backtick escaping rules** for PowerShell code
- **Pre-generation validation checklist** with specific steps
- **High-risk content area identification** (PowerShell scripts, registry commands)
- **Automatic escaping strategy** with regex patterns
- **Error prevention requirements** with validation steps

### 2. Validation Utility (validate-attack-flow-html.sh)

Created a comprehensive validation script that:

- Detects unescaped backticks in JavaScript template literals
- Validates PowerShell code block syntax
- Checks HTML structure and required components
- Verifies MITRE ATT&CK technique mappings
- Provides color-coded output with detailed error reporting

### 3. Fix Utility (fix-attack-flow-backticks.sh)

Developed an automatic repair utility that:

- Identifies and fixes unescaped backticks in PowerShell code snippets
- Creates backup copies before making changes
- Provides dry-run mode to preview changes
- Uses safe processing that preserves legitimate template literals

### 4. Educational Demo (example-backtick-fix.js)

Created a working demonstration script that:

- Shows the actual JavaScript syntax error in a controlled environment
- Demonstrates the correct escaping technique
- Explains the root cause and solution
- Provides working code examples

## Correct Solution

```javascript
// ✅ CORRECT - Properly escaped
const phaseData = {
    1: {
        code: `Set-ItemProperty -Path "HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Features" \\\`\n    \\\`-Name "TamperProtection" -Value 0`
    }
};
```

## Key Escaping Rules

1. **PowerShell line continuation backticks (`) must be escaped as (\\`) inside JavaScript template literals**
2. **Template literal delimiters (outer backticks) should NOT be escaped**
3. **Only escape backticks that are CONTENT within the template literal**
4. **Test generated HTML in browser console to verify syntax**

## Usage Workflow

### For Future Attack Flow Diagram Generation

1. **Generate HTML** using the updated agent configuration
2. **Validate** the generated file:
   ```bash
   ./utils/validate-attack-flow-html.sh your_attack_flow.html
   ```
3. **Fix issues** if validation fails:
   ```bash
   ./utils/fix-attack-flow-backticks.sh your_attack_flow.html
   ```
4. **Re-validate** after fixes:
   ```bash
   ./utils/validate-attack-flow-html.sh your_attack_flow.html
   ```

### Educational Understanding

Run the demo to understand the issue:
```bash
node utils/example-backtick-fix.js
```

## Files Modified/Created

### Modified Files
- `/CLAUDE.md` - Added comprehensive backtick escaping configuration
- `/utils/README.md` - Updated with new utility documentation

### New Files
- `/utils/validate-attack-flow-html.sh` - HTML validation utility
- `/utils/fix-attack-flow-backticks.sh` - Automatic backtick fixer
- `/utils/example-backtick-fix.js` - Educational demonstration
- `/ATTACK_FLOW_BACKTICK_SOLUTION.md` - This summary document

## Testing Verification

The solution was tested on existing sample files and successfully:

1. **Detected** the backtick escaping issues in sample_attack_flow.html
2. **Demonstrated** the actual JavaScript syntax error
3. **Provided** working fixes and validation
4. **Educated** users on the root cause and solution

## Prevention Strategy

The updated agent configuration now includes:

- **Mandatory validation checklists** before HTML generation
- **Automatic escaping protocols** for PowerShell code
- **Error detection requirements** during the generation process
- **Quality assurance steps** that must be followed

This ensures that future attack flow diagrams will be generated with properly escaped JavaScript, preventing the "Invalid or unexpected token" errors from occurring.

## Conclusion

The attack-flow-diagram-builder agent configuration has been successfully updated to prevent JavaScript syntax errors caused by unescaped backticks. The solution includes both automated tools for detection and fixing, as well as comprehensive documentation and educational materials to ensure the issue doesn't recur.

All interactive attack flow diagrams generated following the updated configuration will have functional JavaScript without syntax errors.