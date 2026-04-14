using System;
using System.IO;
using Microsoft.Win32;

public class HonestcueStage2
{
    public static string Run()
    {
        string defenderSub = "unavailable";
        try
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Features"))
            {
                if (k != null)
                {
                    string[] names = k.GetValueNames();
                    defenderSub = "read_ok:" + names.Length + "_values";
                }
            }
        }
        catch (Exception ex) { defenderSub = "read_err:" + ex.Message; }

        string artifactDir = @"c:\Users\fortika-test";
        try { Directory.CreateDirectory(artifactDir); } catch { }
        string marker = Path.Combine(artifactDir, "honestcue_marker.txt");
        File.WriteAllText(marker, "honestcue-stage2-reflective-load " +
            DateTime.UtcNow.ToString("o") + " defender=" + defenderSub);
        return "marker:" + marker;
    }
}
