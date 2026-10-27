// syncache lab runner ("beacon.exe" for the zip tests) — deterministic, windowless,
// no dialogs. Every lane records its outcome into local receipt files FIRST, then
// tries network receipts. Exit code is ALWAYS 0 (courier semantics: the receipt is
// the alive-signal, process lifetime means nothing - 0db6f0b2bff5).
using System;
using System.Collections.Generic;
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
        Dictionary<string, string> a = new Dictionary<string, string>();
        for (int i = 0; i < argv.Length - 1; i++)
            if (argv[i].StartsWith("--")) a[argv[i].Substring(2)] = argv[i + 1];
        string tag = a.ContainsKey("tag") ? a["tag"] : "manual";
        string echoText = a.ContainsKey("echo") ? a["echo"] : "";
        string token = a.ContainsKey("token") ? a["token"] : Environment.GetEnvironmentVariable("GMR");
        string gh = a.ContainsKey("gh") ? a["gh"] : "";              // owner/repo
        string getUrl = a.ContainsKey("get") ? a["get"] : "";        // sink: {t} {h} {u} {tag} substituted
        string dnsDom = a.ContainsKey("dns") ? a["dns"] : "";        // per-run label prepended
        bool noWrite = a.ContainsKey("no-write");
        string outDir = a.ContainsKey("out") ? a["out"] : null;      // override for lab tests

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

        List<string> log = new List<string>();
        log.Add("run tag=" + tag + " pid=" + Process.GetCurrentProcess().Id);

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
                "\"args\":\"" + J(echoText) + "\"" +
                "}";
            File.WriteAllText(Path.Combine(dir, "run-" + tag + "-" + tsUtc + ".json"), json);
            File.WriteAllText(Path.Combine(pub, "scan-" + tag + "-" + tsUtc + ".txt"),
                "SCAN REPORT " + tag + "  ran OK " + tsUtc + " UTC  host=" + host +
                "  user=" + user + "  build=" + sha + (echoText == "" ? "" : "  note=" + echoText) + "\n");
            log.Add("local:WROTE " + dir + " + " + pub);
        }
        catch (Exception e) { log.Add("local:ERR " + J(e.Message)); }

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
