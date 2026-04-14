/*
HONESTCUE v2 Lab Payload — stage2_payload.exe

Benign marker PE fetched by Stage 3 from GitHub-raw, dropped to
c:\Windows\Temp\honestcue_payload.exe, and executed.

Behavior:
  - Reads HKLM\SOFTWARE\Microsoft\Windows Defender (registry read IOC)
  - Writes c:\Users\fortika-test\honestcue_payload_marker.txt as proof of execution

This binary is intentionally MEANT TO BE F0RT1KA-SIGNED before upload to
the GitHub raw-hosting repo, so it can pass Authenticode checks while
still being a signal of HONESTCUE-style stage-2 file-drop-from-trusted-
hosting. See lab_assets/README.md § "Build & Sign".
*/

using System;
using System.IO;
using System.Text;

namespace Honestcue.LabPayload
{
    internal static class Program
    {
        private const string ARTIFACT_DIR = @"c:\Users\fortika-test";
        private const string MARKER_PATH = @"c:\Users\fortika-test\honestcue_payload_marker.txt";

        private static int Main(string[] args)
        {
            Console.WriteLine("[honestcue-lab-payload] starting");
            try
            {
                Directory.CreateDirectory(ARTIFACT_DIR);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[honestcue-lab-payload] mkdir failed: " + ex.Message);
                return 1;
            }

            var sb = new StringBuilder();
            sb.AppendLine("honestcue-v2-stage3-payload-executed");
            sb.AppendLine("timestamp_utc=" + DateTime.UtcNow.ToString("o"));
            sb.AppendLine("pid=" + Environment.ProcessId);
            sb.AppendLine("hostname=" + Environment.MachineName);
            sb.AppendLine("user=" + Environment.UserName);

            try
            {
                File.WriteAllText(MARKER_PATH, sb.ToString(), new UTF8Encoding(false));
                Console.WriteLine("[honestcue-lab-payload] marker written: " + MARKER_PATH);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[honestcue-lab-payload] marker write failed: " + ex.Message);
                return 2;
            }

            Console.WriteLine("[honestcue-lab-payload] complete");
            return 0;
        }
    }
}
