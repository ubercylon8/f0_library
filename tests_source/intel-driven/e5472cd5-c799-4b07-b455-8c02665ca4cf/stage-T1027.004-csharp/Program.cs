/*
STAGE 2 (v2): Native C# In-Memory Roslyn Compile & Reflective Load
         (T1027.004 + T1027.010 + T1620)

v2 CHANGES FROM v1:
  - REMOVED: powershell.exe + CSharpCodeProvider loader script
    (CompileAssemblyFromSource throws PlatformNotSupportedException on
    .NET Core/5+, so v1's approach only worked on .NET Framework 4.x).
  - ADDED: Native .NET 8 self-contained single-file executable using
    Microsoft.CodeAnalysis.CSharp (Roslyn) for in-memory compilation.
  - RATIONALE: Modern-runtime equivalent of real-HONESTCUE's .NET Framework
    4.x CSharpCodeProvider. ATT&CK mapping (T1027.004 + T1027.010 + T1620)
    is unchanged because the technique — compile-after-delivery +
    reflective load — is identical; only the API surface is modernized.
    Real HONESTCUE on Win7/Win10/Server2012 uses CSharpCodeProvider;
    HONESTCUE on modern systems (Win11 w/ .NET 8) would use Roslyn.

Reads the GitHub-sourced C# (written by stage 1 to
c:\F0\honestcue_stage2_source.cs), then:

  (a) Uses Microsoft.CodeAnalysis.CSharp.CSharpCompilation.Create(...)
      to compile the source to an in-memory byte[] PE via Emit(MemoryStream)
      (T1027.004 - compile after delivery).

  (b) Assembly.Load(byte[]) reflectively loads the bytes without csc.exe
      spawning a child process (T1620 - Reflective Code Loading;
      T1027.010 - Command Obfuscation via indirect assembly loading).

  (c) Invokes the HonestcueStage2.Run() entry point, which:
         - reads HKLM\SOFTWARE\Microsoft\Windows Defender\Features
         - writes a marker to c:\Users\fortika-test\honestcue_marker.txt

Detection opportunities (differ from v1 — no csc.exe, no powershell!):
  - Microsoft.CodeAnalysis.CSharp.dll load event in a non-dev process
  - Assembly.Load(byte[]) AMSI scan event on modern AMSI-enabled hosts
  - Image load of clrcompression.dll + SharedFramework runtime loads
    from a single-file self-extracted .NET 8 binary
  - Marker file written to ARTIFACT_DIR (not whitelisted)
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Basic.Reference.Assemblies;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

namespace Honestcue.Stage2
{
    internal static class Program
    {
        // These constants MUST stay in lockstep with the Go orchestrator &
        // stage-1 handoff path. LOG_DIR / ARTIFACT_DIR are NOT constants on
        // Windows — real HONESTCUE uses hardcoded paths.
        private const string TEST_UUID = "e5472cd5-c799-4b07-b455-8c02665ca4cf";
        private const string TECHNIQUE_ID = "T1027.004";
        private const int STAGE_ID = 2;

        private const string LOG_DIR = @"c:\F0";
        private const string CSHARP_HANDOFF = @"c:\F0\honestcue_stage2_source.cs";
        private const string ARTIFACT_DIR = @"c:\Users\fortika-test";
        private const string ARTIFACT_MARKER = @"c:\Users\fortika-test\honestcue_marker.txt";

        // Exit codes — MUST match Go stage orchestrator codes.
        private const int StageSuccess = 0;
        private const int StageBlocked = 126;
        private const int StageQuarantined = 105;
        private const int StageError = 999;

        // Stage log file (plain text — this C# process does not share the
        // Go test_logger.go state; it writes its own minimal trail).
        private const string STAGE2_LOG = @"c:\F0\stage2_roslyn.log";

        private static StreamWriter logWriter;

        private static int Main(string[] args)
        {
            try
            {
                Directory.CreateDirectory(LOG_DIR);
                logWriter = new StreamWriter(
                    new FileStream(STAGE2_LOG, FileMode.Create, FileAccess.Write, FileShare.Read),
                    new UTF8Encoding(false));
                logWriter.AutoFlush = true;
            }
            catch (Exception)
            {
                // Non-fatal; we still proceed without disk logging.
            }

            Log("INFO", "Starting Roslyn in-memory compile + reflective load (.NET 8 self-contained)");

            try
            {
                int rc = PerformTechnique();
                Log("INFO", "PerformTechnique returned " + rc);
                Shutdown();
                return rc;
            }
            catch (Exception ex)
            {
                Log("ERROR", "Uncaught: " + ex.GetType().Name + ": " + ex.Message);
                int rc = DetermineExitCode(ex);
                Shutdown();
                return rc;
            }
        }

        private static int PerformTechnique()
        {
            // Step 1: verify stage-1 handoff exists
            if (!File.Exists(CSHARP_HANDOFF))
            {
                Log("ERROR", "stage1 handoff source not available: " + CSHARP_HANDOFF);
                return StageError;
            }
            string sourceCode = File.ReadAllText(CSHARP_HANDOFF);
            Log("INFO", "Loaded stage-1 C# source (" + sourceCode.Length + " chars)");

            // Step 2: parse via Roslyn
            SyntaxTree tree;
            try
            {
                tree = CSharpSyntaxTree.ParseText(sourceCode);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Roslyn parse failed: " + ex.Message);
                return StageError;
            }

            // Step 3: collect runtime assembly references for compilation.
            //
            // v2.2: Use Basic.Reference.Assemblies.Net80 (Jared Parsons /
            // Roslyn team), which embeds the full .NET 8 reference assembly
            // set (BCL + Microsoft.Win32.Registry) as resources inside the
            // Basic.Reference.Assemblies.Net80.dll library. This is the
            // canonical Roslyn-in-single-file-publish solution.
            //
            // Why v2.1's triple-fallback resolver returned zero references:
            //   - .NET 8 self-contained single-file publish does NOT unpack
            //     runtime reference assemblies to AppContext.BaseDirectory
            //     (it unpacks only native libs when IncludeNativeLibrariesForSelfExtract=true;
            //     managed assemblies stay inside the bundle).
            //   - Assembly.Location returns empty string for assemblies loaded
            //     from the single-file bundle (IL3000 is the warning, but
            //     suppressing it doesn't make the location magically exist).
            //   - typeof(object).Assembly.Location was empty; all three
            //     fallbacks produced the same zero-reference result, leading
            //     to CS0518 "Predefined type 'System.Object' is not defined".
            IEnumerable<MetadataReference> references = Net80.References.All;
            Log("INFO", "Roslyn compile references: " + references.Count()
                + " (via Basic.Reference.Assemblies.Net80)");

            // Step 4: compile to in-memory PE via Roslyn
            var compilation = CSharpCompilation.Create(
                assemblyName: "HonestcueStage2.InMemory",
                syntaxTrees: new[] { tree },
                references: references,
                options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)
                    .WithOptimizationLevel(OptimizationLevel.Release)
                    .WithPlatform(Platform.AnyCpu));

            byte[] peBytes;
            using (var ms = new MemoryStream())
            {
                EmitResult emit = compilation.Emit(ms);
                if (!emit.Success)
                {
                    var sb = new StringBuilder();
                    sb.Append("roslyn emit failed: ");
                    foreach (var d in emit.Diagnostics)
                    {
                        if (d.Severity == DiagnosticSeverity.Error)
                        {
                            sb.Append(d.Id).Append(' ').Append(d.GetMessage()).Append("; ");
                        }
                    }
                    Log("ERROR", sb.ToString());
                    return StageError;
                }
                peBytes = ms.ToArray();
            }
            Log("INFO", "Roslyn emit succeeded: in-memory PE = " + peBytes.Length + " bytes");

            // Step 5: Assembly.Load(byte[]) — the reflective-load IOC that
            // AMSI/ETW detect on. This is the detection surface that matters,
            // not the compile step. T1620 proper.
            Assembly asm;
            try
            {
                asm = Assembly.Load(peBytes);
                Log("INFO", "Assembly.Load(byte[]) succeeded: FullName=" + asm.FullName);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Assembly.Load(byte[]) failed: " + ex.Message);
                return DetermineExitCode(ex);
            }

            // Step 6: locate HonestcueStage2 type and invoke Run()
            Type t = asm.GetType("HonestcueStage2");
            if (t == null)
            {
                Log("ERROR", "type HonestcueStage2 not found in reflectively-loaded assembly");
                return StageError;
            }
            MethodInfo m = t.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
            if (m == null)
            {
                Log("ERROR", "method Run not found on HonestcueStage2");
                return StageError;
            }

            object result;
            try
            {
                result = m.Invoke(null, null);
            }
            catch (TargetInvocationException tie)
            {
                Log("ERROR", "Run() threw: " + (tie.InnerException != null ? tie.InnerException.Message : tie.Message));
                return DetermineExitCode(tie.InnerException ?? tie);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Run() threw: " + ex.Message);
                return DetermineExitCode(ex);
            }

            string runResult = result == null ? "<null>" : result.ToString();
            Log("INFO", "Run() returned: " + runResult);

            // Step 7: verify marker file was actually written
            System.Threading.Thread.Sleep(1000);
            if (!File.Exists(ARTIFACT_MARKER))
            {
                Log("ERROR", "marker file missing after reflective load: " + ARTIFACT_MARKER);
                return StageError;
            }
            var markerInfo = new FileInfo(ARTIFACT_MARKER);
            Log("INFO", "Marker confirmed: " + ARTIFACT_MARKER + " (" + markerInfo.Length + " bytes)");

            Log("INFO", "Detection points: Microsoft.CodeAnalysis.CSharp.dll load, "
                + "Assembly.Load(byte[]) AMSI, marker in c:\\Users\\fortika-test, "
                + "single-file self-extracted .NET 8 runtime");

            return StageSuccess;
        }

        private static int DetermineExitCode(Exception ex)
        {
            if (ex == null) return StageError;
            string msg = ex.Message ?? string.Empty;
            string lower = msg.ToLowerInvariant();

            // Blame-free keyword checks — per Bug Prevention Rule 1.
            if (lower.Contains("access denied") || lower.Contains("access is denied")
                || lower.Contains("permission denied") || lower.Contains("operation not permitted"))
            {
                return StageBlocked;
            }
            if (lower.Contains("quarantine") || lower.Contains("virus") || lower.Contains("threat detected"))
            {
                return StageQuarantined;
            }
            if (lower.Contains("amsi") || lower.Contains("applocker") || lower.Contains("wdac"))
            {
                return StageBlocked;
            }
            if (lower.Contains("not found") || lower.Contains("does not exist")
                || lower.Contains("no such") || lower.Contains("not running")
                || lower.Contains("not available") || lower.Contains("unavailable")
                || lower.Contains("missing"))
            {
                return StageError;
            }
            return StageError;
        }

        private static void Log(string level, string message)
        {
            string line = "[" + DateTime.UtcNow.ToString("o") + "] [" + level + "] [" + TECHNIQUE_ID + "] " + message;
            Console.WriteLine(line);
            if (logWriter != null)
            {
                try { logWriter.WriteLine(line); } catch { /* ignore */ }
            }
        }

        private static void Shutdown()
        {
            if (logWriter != null)
            {
                try { logWriter.Flush(); logWriter.Dispose(); } catch { }
                logWriter = null;
            }
        }
    }

}
