/*
 * setup.cpp — Oxsium Framework Bootstrap Installer
 * Compiles with: g++ -std=c++17 -static -static-libgcc -static-libstdc++ setup.cpp -o setup.exe
 */

#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

namespace fs = std::filesystem;

/* ══════════════════════════════════════════════════════════════════════════
   ANSI color helpers  (Windows: enable VT mode; other OS: always on)
   ══════════════════════════════════════════════════════════════════════════ */

namespace ansi {

static bool enabled = true;

static void init() {
#ifdef _WIN32
    /* Switch console to UTF-8 so box-drawing chars render correctly */
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (GetConsoleMode(h, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        enabled = SetConsoleMode(h, mode);
    } else {
        enabled = false;
    }
#endif
}

static inline std::string c(const char* code) {
    return enabled ? std::string("\033[") + code + "m" : "";
}

static std::string RST()      { return c("0");    }
static std::string BOLD()     { return c("1");    }
static std::string DIM()      { return c("2");    }
static std::string RED()      { return c("31");   }
static std::string GREEN()    { return c("32");   }
static std::string YELLOW()   { return c("33");   }
static std::string CYAN()     { return c("36");   }
static std::string WHITE()    { return c("97");   }
static std::string OK_TAG()   { return c("1;32"); }
static std::string ERR_TAG()  { return c("1;31"); }
static std::string WARN_TAG() { return c("1;33"); }
static std::string INFO_TAG() { return c("1;36"); }
static std::string HDR()      { return c("1;34"); }
static std::string PATH_CLR() { return c("33");   }

} // namespace ansi

/* ── print helpers ────────────────────────────────────────────────────── */

static void ok(const std::string& msg) {
    std::cout << "  " << ansi::OK_TAG()   << "[ OK ]" << ansi::RST() << "  " << msg << "\n";
}
static void err(const std::string& msg) {
    std::cout << "  " << ansi::ERR_TAG()  << "[FAIL]" << ansi::RST() << "  "
              << ansi::RED() << msg << ansi::RST() << "\n";
}
static void warn(const std::string& msg) {
    std::cout << "  " << ansi::WARN_TAG() << "[WARN]" << ansi::RST() << "  "
              << ansi::YELLOW() << msg << ansi::RST() << "\n";
}
static void info(const std::string& msg) {
    std::cout << "  " << ansi::INFO_TAG() << "[INFO]" << ansi::RST() << "  " << msg << "\n";
}
static void bullet(const std::string& msg) {
    std::cout << "         " << ansi::DIM() << ">>" << ansi::RST() << "  " << msg << "\n";
}

static void step_header(int n, const std::string& title) {
    std::cout << "\n"
              << ansi::HDR()
              << "  +-- Step " << n << " ------------------------------------------+\n"
              << "  |  " << ansi::WHITE() << title << ansi::HDR() << "\n"
              << "  +--------------------------------------------------+"
              << ansi::RST() << "\n\n";
}

static void print_banner() {
    std::cout
        << "\n"
        << ansi::HDR()
        << "  +==================================================+\n"
        << "  |       " << ansi::WHITE() << "Oxsium Framework  -  Setup Installer"
        << ansi::HDR()  << "       |\n"
        << "  +==================================================+"
        << ansi::RST()  << "\n\n";
}

static void print_success(const fs::path& root) {
    std::cout
        << "\n"
        << ansi::OK_TAG()
        << "  +==================================================+\n"
        << "  |       " << ansi::WHITE() << "Installation completed successfully! "
        << ansi::OK_TAG() << "       |\n"
        << "  +==================================================+"
        << ansi::RST() << "\n\n";

    std::cout << ansi::BOLD() << "  Quick-start commands:" << ansi::RST() << "\n\n";
    std::cout << "    " << ansi::CYAN()   << "python start.py"
              << ansi::RST() << ansi::DIM() << "   =>  open NiceGUI control panel (browser at http://127.0.0.1:8080)\n" << ansi::RST();
    std::cout << "\n"
              << "    " << ansi::CYAN()   << "python start.py --connection-port 5000 --decision-port 5001"
              << ansi::RST() << ansi::DIM() << "\n" << ansi::RST();
    std::cout << "    " << ansi::DIM() << "=>  specify custom ports\n" << ansi::RST();
    std::cout << "\n"
              << "    " << ansi::CYAN()   << "python start.py --http-port 8080"
              << ansi::RST() << ansi::DIM() << "   =>  use custom HTTP port\n" << ansi::RST();
    std::cout << "\n"
              << ansi::DIM() << "  Virtual env : "
              << ansi::PATH_CLR() << (root / "oxsium").string()
              << ansi::RST() << "\n\n";
}

/* ══════════════════════════════════════════════════════════════════════════
   Core helpers
   ══════════════════════════════════════════════════════════════════════════ */

static std::string quote(const fs::path& p) { return '"' + p.string() + '"'; }
static int  run(const std::string& cmd)      { return std::system(cmd.c_str()); }
static bool command_ok(const std::string& cmd) { return run(cmd + " >nul 2>&1") == 0; }

#ifdef _WIN32
/* ── run_direct ───────────────────────────────────────────────────────────
   Launches  exe  with  args  directly via CreateProcess — no cmd.exe shell
   in between.  This avoids the "filename/directory/volume label syntax is
   incorrect" error that cmd.exe raises when a quoted executable path that
   contains spaces is followed by additional quoted arguments.

   exe   : full path to the executable  (e.g. C:\Program Files\Python312\python.exe)
   args  : the rest of the command line  (e.g. -m venv C:\some\path)
   Returns the process exit code, or -1 on launch failure.
   ──────────────────────────────────────────────────────────────────────── */
static int run_direct(const fs::path& exe, const std::string& args)
{
    /* CreateProcess wants a mutable command-line buffer that begins with
       the (quoted) executable followed by a space and the arguments.     */
    std::string cmdline = '"' + exe.string() + '"';
    if (!args.empty()) { cmdline += ' '; cmdline += args; }

    STARTUPINFOW        si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    std::wstring wcmd(cmdline.begin(), cmdline.end());

    BOOL launched = CreateProcessW(
        exe.wstring().c_str(),   // lpApplicationName  — bypasses shell lookup
        wcmd.data(),             // lpCommandLine      — mutable buffer
        nullptr, nullptr,
        FALSE,                   // bInheritHandles
        0,                       // dwCreationFlags
        nullptr,                 // lpEnvironment      — inherit parent env
        nullptr,                 // lpCurrentDirectory — inherit CWD
        &si, &pi
    );

    if (!launched) return -1;

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}
#endif

/* ── project root ─────────────────────────────────────────────────────── */

static fs::path locate_root(const fs::path& start) {
    fs::path cur = start;
    while (!cur.empty()) {
        if (fs::exists(cur / "Main" / "requirements.txt")) return cur;
        fs::path parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }
    return start;
}

/* ── Python detection ─────────────────────────────────────────────────── */

static bool python_exists()      { return command_ok("python --version"); }
static bool py_launcher_exists() { return command_ok("py -3 --version");  }

static fs::path scan_dir(const char* root_dir) {
    if (!root_dir) return {};
    fs::path base(root_dir);
    if (!fs::exists(base)) return {};
    for (const auto& e : fs::directory_iterator(base)) {
        if (!e.is_directory()) continue;
        fs::path direct = e.path() / "python.exe";
        if (fs::exists(direct)) return direct;
        if (e.path().filename().string().find("Python") != std::string::npos)
            for (const auto& sub : fs::recursive_directory_iterator(e.path()))
                if (sub.is_regular_file() && sub.path().filename() == "python.exe")
                    return sub.path();
    }
    return {};
}

static fs::path find_python_exe() {
    if (const char* loc = std::getenv("LOCALAPPDATA")) {
        fs::path base = fs::path(loc) / "Programs" / "Python";
        if (fs::exists(base))
            for (const auto& e : fs::directory_iterator(base)) {
                fs::path c = e.path() / "python.exe";
                if (fs::exists(c)) return c;
            }
    }
    fs::path found = scan_dir(std::getenv("ProgramFiles"));
    if (!found.empty()) return found;
    found = scan_dir(std::getenv("ProgramFiles(x86)"));
    if (!found.empty()) return found;
    if (python_exists())      return fs::path("python");
    if (py_launcher_exists()) return fs::path("py -3");
    return {};
}

/* ── Python installer ─────────────────────────────────────────────────── */

/*
 * Method 1 — winget (Windows 10 1709+ / Windows 11)
 */
static bool install_via_winget() {
    if (!command_ok("winget --version")) return false;

    info("Installing Python 3.12 via " + ansi::CYAN() + "winget" + ansi::RST() + " ...");
    std::cout << "\n";
    int rc = run("winget install -e --id Python.Python.3.12 "
                 "--accept-package-agreements --accept-source-agreements "
                 "--override \"/quiet InstallAllUsers=1 PrependPath=1 "
                 "Include_pip=1 Include_lib=1 Include_test=0\"");
    std::cout << "\n";
    if (rc != 0) {
        warn("winget install failed (exit code " + std::to_string(rc) + "). Trying fallback ...");
        return false;
    }
    ok("Python 3.12 installed via winget.");
    return true;
}

/*
 * Method 2 — PowerShell Invoke-WebRequest
 *   Downloads the official python.org installer to %TEMP% and runs it silently.
 *   /quiet         — completely silent
 *   InstallAllUsers=1  — system-wide install (ensures full stdlib + ensurepip)
 *   PrependPath=1  — adds python.exe to PATH automatically
 *   Include_pip=1  — force-include pip (prevents ensurepip missing error)
 *   Include_lib=1  — include standard library (required for venv)
 *   Include_test=0 — skip test suite to save space
 */
static bool install_via_powershell() {
    if (!command_ok("powershell -Command \"exit 0\"")) return false;

    info("Downloading Python 3.12 installer via " + ansi::CYAN() + "PowerShell" + ansi::RST() + " ...");

    /* Build the PowerShell one-liner:
       1. Download installer to %TEMP%\python-3.12-installer.exe
       2. Run it silently                                           */
    const std::string ps_script =
        "$url  = 'https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe';"
        "$dest = $env:TEMP + '\\python-3.12-installer.exe';"
        "Write-Host '  Downloading ...';"
        "Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing;"
        "Write-Host '  Running installer (silent) ...';"
        "Start-Process -FilePath $dest "
        "  -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1',"
        "    'Include_pip=1','Include_lib=1','Include_test=0' "
        "  -Wait -NoNewWindow;"
        "Remove-Item $dest -Force";

    std::string cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + ps_script + "\"";
    std::cout << "\n";
    int rc = run(cmd);
    std::cout << "\n";
    if (rc != 0) {
        warn("PowerShell download failed (exit code " + std::to_string(rc) + "). Trying fallback ...");
        return false;
    }
    ok("Python 3.12 installed via PowerShell.");
    return true;
}

/*
 * Method 3 — curl (ships with Windows 10 1803+)
 *   curl downloads the installer; then we run it silently with cmd /c start /wait
 */
static bool install_via_curl() {
    if (!command_ok("curl --version")) return false;

    info("Downloading Python 3.12 installer via " + ansi::CYAN() + "curl" + ansi::RST() + " ...");

    /* %TEMP% expands correctly inside cmd /c */
    const std::string download_cmd =
        "curl -L --progress-bar "
        "-o \"%TEMP%\\python-3.12-installer.exe\" "
        "https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe";

    std::cout << "\n";
    if (run(download_cmd) != 0) {
        std::cout << "\n";
        warn("curl download failed. Trying fallback ...");
        return false;
    }

    info("Running installer silently ...");
    std::cout << "\n";
    int rc = run("cmd /c start /wait \"\" "
                 "\"%TEMP%\\python-3.12-installer.exe\" "
                 "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_lib=1 Include_test=0");
    run("del /f /q \"%TEMP%\\python-3.12-installer.exe\" >nul 2>&1");
    std::cout << "\n";
    if (rc != 0) {
        warn("curl installer failed (exit code " + std::to_string(rc) + ").");
        return false;
    }
    ok("Python 3.12 installed via curl.");
    return true;
}

static bool install_python() {
    warn("Python was not found on this system.");
    std::cout << "\n  " << ansi::BOLD()
              << "Would you like to install Python 3.12 automatically? "
              << ansi::CYAN() << "[Y/N]" << ansi::RST() << ": ";

    std::string answer;
    std::getline(std::cin, answer);

    while (!answer.empty() && std::isspace((unsigned char)answer.front())) answer.erase(answer.begin());
    while (!answer.empty() && std::isspace((unsigned char)answer.back()))  answer.pop_back();
    for (auto& ch : answer) ch = static_cast<char>(std::tolower((unsigned char)ch));

    if (answer != "y" && answer != "yes") {
        std::cout << "\n";
        err("Setup aborted — Python is required to continue.");
        bullet("Download manually: " + ansi::CYAN() + "https://www.python.org/downloads/" + ansi::RST());
        std::cout << "\n";
        return false;
    }

    /* Try each method in order — stop at the first success */
    if (install_via_winget())     return true;
    if (install_via_powershell()) return true;
    if (install_via_curl())       return true;

    /* All methods failed */
    err("All automatic installation methods failed.");
    bullet("Please install manually: " + ansi::CYAN() + "https://www.python.org/downloads/" + ansi::RST());
    bullet("Then re-run setup.exe.");
    std::cout << "\n";
    return false;
}

static bool ensure_python() {
    if (python_exists() || py_launcher_exists()) {
        ok("Python detected on this system.");
        return true;
    }
    if (!install_python()) return false;

    bool found = python_exists() || py_launcher_exists() || !find_python_exe().empty();
    if (!found) {
        warn("Python installed but not yet visible in PATH.");
        bullet("Open a new terminal window and re-run setup.exe.");
    }
    return found;
}

/* ── venv helpers ─────────────────────────────────────────────────────── */

static fs::path venv_python(const fs::path& root) {
#ifdef _WIN32
    return root / "oxsium" / "Scripts" / "python.exe";
#else
    return root / "oxsium" / "bin" / "python";
#endif
}

static std::string python_command(const fs::path& root) {
    fs::path vp = venv_python(root);
    if (fs::exists(vp)) return quote(vp);
    fs::path inst = find_python_exe();
    if (!inst.empty()) {
        if (inst == fs::path("python") || inst == fs::path("py -3")) return inst.string();
        return quote(inst);
    }
    if (python_exists())      return "python";
    if (py_launcher_exists()) return "py -3";
    return {};
}

/* ── virtual environment ──────────────────────────────────────────────── */

/* ------------------------------------------------------------------ *
 *  diagnose_venv_failure()                                            *
 *  Called after `python -m venv` returns a non-zero exit code.       *
 *  Checks every likely cause and prints a labelled explanation so    *
 *  the user knows exactly what went wrong without reading logs.      *
 * ------------------------------------------------------------------ */
static void diagnose_venv_failure(const fs::path& interp_path,
                                  const fs::path& venv_dir,
                                  int             exit_code)
{
    std::cout << "\n"
              << ansi::ERR_TAG()
              << "  +-- Diagnostic Report ---------------------------------------+"
              << ansi::RST() << "\n\n";

    /* 1 ── interpreter reachable? ─────────────────────────────────── */
    bool interp_ok = false;
    if (interp_path == fs::path("python") || interp_path == fs::path("py -3")) {
        interp_ok = command_ok(interp_path.string() + " --version");
    } else {
        interp_ok = fs::exists(interp_path);
    }

    if (!interp_ok) {
        err("Interpreter not found or not executable.");
        bullet("Path checked : " + ansi::PATH_CLR() + interp_path.string() + ansi::RST());
        bullet("Python may have been installed but is not yet visible in this");
        bullet("process's PATH.  Open a NEW terminal and re-run setup.exe.");
    } else {
        ok("Interpreter exists  : " + interp_path.string());
    }

    /* 2 ── path contains characters Windows cmd mishandles ───────── *
     *  The main culprit seen in the log:                              *
     *    "The filename, directory name, or volume label syntax is     *
     *     incorrect."                                                 *
     *  This happens when the fully-quoted command still has a path    *
     *  segment that ends with a backslash immediately before the      *
     *  closing double-quote  (e.g.  "C:\foo\"  →  shell sees  \")    *
     *  OR when the path contains parentheses / special shell chars.   */
    {
        const std::string p = venv_dir.string();

        /* Trailing backslash-before-quote is the classic trigger */
        bool trailing_bs   = (!p.empty() && p.back() == '\\');

        /* Characters that confuse cmd.exe inside a quoted argument */
        bool bad_chars     = (p.find('(')  != std::string::npos ||
                              p.find(')')  != std::string::npos ||
                              p.find('!')  != std::string::npos ||
                              p.find('^')  != std::string::npos ||
                              p.find('&')  != std::string::npos ||
                              p.find('%')  != std::string::npos);

        /* Double-quote already in path name (very unusual, but check) */
        bool embedded_quote = (p.find('"') != std::string::npos);

        if (trailing_bs || bad_chars || embedded_quote) {
            err("Destination path contains characters that break cmd.exe quoting:");
            if (trailing_bs)    bullet("Trailing backslash before closing quote  →  \\\"");
            if (bad_chars)      bullet("Shell-special character  ( ) ! ^ & %  in path");
            if (embedded_quote) bullet("Embedded double-quote in path name");
            bullet("Path : " + ansi::PATH_CLR() + p + ansi::RST());
            bullet("Fix  : move the project to a path without these characters,");
            bullet("       e.g.  C:\\OxsiumFramework\\  (no spaces, no parens).");
        } else {
            ok("Destination path looks safe for cmd.exe quoting.");
        }

        /* Space in path — not fatal when properly quoted, but flag it */
        if (p.find(' ') != std::string::npos) {
            warn("Destination path contains spaces — this is allowed but can");
            bullet("cause problems with some Python venv builds on older Windows.");
            bullet("If the error persists, try:  C:\\OxsiumFramework\\oxsium");
        }
    }

    /* 3 ── target directory already exists but is broken ─────────── */
    if (fs::exists(venv_dir)) {
        bool has_pyvenv_cfg = fs::exists(venv_dir / "pyvenv.cfg");
        if (!has_pyvenv_cfg) {
            warn("Directory already exists but has no pyvenv.cfg — it may be");
            bullet("a leftover from a previous failed attempt.");
            bullet("Delete it and re-run:  rmdir /s /q \"" + venv_dir.string() + "\"");
        }
    }

    /* 4 ── disk space (rough heuristic via GetDiskFreeSpaceEx) ──────── */
#ifdef _WIN32
    {
        ULARGE_INTEGER free_bytes{};
        std::wstring wpath(venv_dir.wstring());
        if (GetDiskFreeSpaceExW(wpath.c_str(), &free_bytes, nullptr, nullptr)) {
            const unsigned long long free_mb = free_bytes.QuadPart / (1024ULL * 1024ULL);
            if (free_mb < 150ULL) {
                err("Low disk space: " + std::to_string(free_mb) + " MB free.");
                bullet("Python virtual environments need at least 150 MB.");
            } else {
                ok("Disk space OK  : " + std::to_string(free_mb) + " MB free.");
            }
        }
    }
#endif

    /* 5 ── ensurepip available in this Python build? ─────────────── */
    {
        std::string check_interp;
        if (interp_path == fs::path("python") || interp_path == fs::path("py -3"))
            check_interp = interp_path.string();
        else
            check_interp = quote(interp_path);

        if (!command_ok(check_interp + " -c \"import ensurepip\"")) {
            err("The ensurepip module is missing from this Python build.");
            bullet("On some stripped / embedded distributions venv cannot install pip.");
            bullet("Install the full Python 3.12 from https://www.python.org/downloads/");
        } else {
            ok("ensurepip module  : present.");
        }
    }

    /* 6 ── exit code hint ─────────────────────────────────────────── */
    std::cout << "\n";
    warn("venv exit code was " + std::to_string(exit_code) + ".  Common meanings:");
    if (exit_code == 1)
        bullet("General Python error — see the venv output above for the traceback.");
    else if (exit_code == 2)
        bullet("Bad command-line arguments passed to python.exe.");

#ifdef _WIN32
    /* Windows-specific: NTSTATUS / Win32 error mapped through CRT */
    else if (exit_code == 0xC0000135 || exit_code == -1073741515)
        bullet("DLL not found — Python install may be incomplete or corrupted.");
    else if (exit_code == 0xC0000005 || exit_code == -1073741819)
        bullet("Access violation — possible antivirus interference or corrupt install.");
#endif

    else {
        bullet("Uncommon code — run the command manually in a cmd window to see");
        bullet("the full error output:  " + ansi::CYAN() +
               quote(interp_path) + " -m venv " + quote(venv_dir) + ansi::RST());
    }

    std::cout << "\n"
              << ansi::ERR_TAG()
              << "  +------------------------------------------------------------+"
              << ansi::RST() << "\n\n";
}

static bool create_virtual_environment(const fs::path& root) {
    if (fs::exists(venv_python(root))) {
        ok("Virtual environment already exists.");
        bullet(ansi::PATH_CLR() + (root / "oxsium").string() + ansi::RST());
        return true;
    }

    /* Resolve interpreter: prefer explicit full path so a freshly-installed
       Python (not yet in the current process PATH cache) is found reliably. */
    fs::path interp_path = find_python_exe();
    std::string interp;
    if (!interp_path.empty()
        && interp_path != fs::path("python")
        && interp_path != fs::path("py -3")) {
        interp = quote(interp_path);        // full path, always works
    } else if (py_launcher_exists()) {
        interp = "py -3";
        interp_path = fs::path("py -3");
    } else if (python_exists()) {
        interp = "python";
        interp_path = fs::path("python");
    } else {
        err("No Python interpreter found \u2014 cannot create virtual environment.");
        return false;
    }

    const fs::path venv_dir = root / "oxsium";

    info("Creating virtual environment " + ansi::CYAN() + "oxsium" + ansi::RST() + " ...");

    int rc;
#ifdef _WIN32
    /* Use CreateProcess directly — bypasses cmd.exe so a python.exe path
       that contains spaces (e.g. C:\Program Files\Python312\python.exe)
       is passed as the application name, not as a shell token.  The venv
       destination is passed as a plain (unquoted) argument; CreateProcess
       does not go through cmd.exe tokenisation, so no extra quoting is
       needed and the "filename/directory syntax is incorrect" error never
       occurs.                                                             */
    if (interp_path != fs::path("python") && interp_path != fs::path("py -3")) {
        bullet(ansi::DIM() + interp_path.string() + " -m venv " + venv_dir.string() + ansi::RST());
        rc = run_direct(interp_path, "-m venv \"" + venv_dir.string() + "\"");
    } else {
        /* Fallback: interpreter is just "python" or "py -3" — use system() */
        const std::string cmd = interp + " -m venv \"" + venv_dir.string() + "\"";
        bullet(ansi::DIM() + cmd + ansi::RST());
        rc = run(cmd);
    }
#else
    const std::string cmd = interp + " -m venv \"" + venv_dir.string() + "\"";
    bullet(ansi::DIM() + cmd + ansi::RST());
    rc = run(cmd);
#endif

    if (rc != 0) {
        err("Failed to create virtual environment.");
        diagnose_venv_failure(interp_path, venv_dir, rc);
        return false;
    }
    ok("Virtual environment created.");
    bullet(ansi::PATH_CLR() + venv_dir.string() + ansi::RST());
    return true;
}

/* ── pip requirements ─────────────────────────────────────────────────── */

static bool install_requirements(const fs::path& root) {
    fs::path req = root / "Main" / "requirements.txt";
    if (!fs::exists(req)) {
        err("requirements.txt not found: " + req.string());
        return false;
    }

    /* Resolve the Python interpreter to a concrete fs::path so we can
       use run_direct() and bypass cmd.exe entirely.  This avoids the
       "'C:\Program' is not recognized" error that occurs when python.exe
       lives under C:\Program Files\ and system() passes the quoted path
       through cmd.exe tokenisation.                                       */
    fs::path interp_path = venv_python(root);
    if (!fs::exists(interp_path)) {
        interp_path = find_python_exe();
        if (interp_path.empty() || interp_path == fs::path("python")
                                || interp_path == fs::path("py -3")) {
            err("No usable Python interpreter found for pip.");
            return false;
        }
    }

#ifdef _WIN32
    auto pip_run = [&](const std::string& args) -> int {
        return run_direct(interp_path, args);
    };
#else
    auto pip_run = [&](const std::string& args) -> int {
        return run("\"" + interp_path.string() + "\" " + args);
    };
#endif

    info("Upgrading pip, setuptools and wheel ...");
    std::cout << "\n";
    if (pip_run("-m pip install --upgrade pip setuptools wheel") != 0) {
        std::cout << "\n";
        err("Failed to upgrade pip.");
        return false;
    }
    std::cout << "\n";
    info("Installing packages from requirements.txt ...");
    std::cout << "\n";
    if (pip_run("-m pip install -r \"" + req.string() + "\"") != 0) {
        std::cout << "\n";
        err("Failed to install requirements.");
        return false;
    }
    std::cout << "\n";
    ok("All packages installed successfully.");
    return true;
}

/* ── launcher writer ──────────────────────────────────────────────────── */

static bool write_file(const fs::path& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f << content;
    return static_cast<bool>(f);
}

static std::string start_py_template() {
    return
        "\"\"\"\n"
        "Oxsium Framework — NiceGUI Service Launcher\n"
        "Run: python launcher.py   (works with venv or system Python)\n"
        "\"\"\"\n"
        "from __future__ import annotations\n"
        "\n"
        "import importlib.util\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "import threading\n"
        "import time\n"
        "from pathlib import Path\n"
        "\n"
        "# ── Auto-install nicegui into whichever Python is running this script ─────────\n"
        "def _ensure_nicegui():\n"
        "    if importlib.util.find_spec(\"nicegui\") is not None:\n"
        "        return  # already installed\n"
        "    print(\"  [SETUP] nicegui not found — installing into current Python...\")\n"
        "    subprocess.check_call(\n"
        "        [sys.executable, \"-m\", \"pip\", \"install\", \"nicegui\", \"--quiet\"],\n"
        "        stdout=subprocess.DEVNULL,\n"
        "        stderr=subprocess.DEVNULL,\n"
        "    )\n"
        "    print(\"  [SETUP] nicegui installed successfully.\\n\")\n"
        "\n"
        "_ensure_nicegui()\n"
        "\n"
        "from nicegui import app, ui  # noqa: E402\n"
        "\n"
        "# ── Paths ─────────────────────────────────────────────────────────────────────\n"
        "ROOT = Path(__file__).resolve().parent\n"
        "VENV_PYTHON = (\n"
        "    ROOT / \"oxsium\"\n"
        "    / (\"Scripts\" if os.name == \"nt\" else \"bin\")\n"
        "    / (\"python.exe\" if os.name == \"nt\" else \"python\")\n"
        ")\n"
        "PYTHON = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)\n"
        "\n"
        "CONNECTION_PY = ROOT / \"Main\" / \"connect\" / \"connection.py\"\n"
        "DECISION_PY   = ROOT / \"Main\" / \"Decision Engine\" / \"Helpers\" / \"root_principal.py\"\n"
        "HTML_FILE     = ROOT / \"Main\" / \"Oxsium-Framework.html\"\n"
        "\n"
        "\n"
        "# ── Helpers ───────────────────────────────────────────────────────────────────\n"
        "def _load_port(filepath: Path, attr: str, fallback: int) -> int:\n"
        "    try:\n"
        "        spec = importlib.util.spec_from_file_location(filepath.stem, filepath)\n"
        "        mod  = importlib.util.module_from_spec(spec)\n"
        "        spec.loader.exec_module(mod)\n"
        "        return int(getattr(mod, attr, fallback))\n"
        "    except Exception:\n"
        "        return fallback\n"
        "\n"
        "\n"
        "def get_venv_env() -> dict:\n"
        "    env = os.environ.copy()\n"
        "    if os.name == \"nt\":\n"
        "        env[\"PATH\"] = str(ROOT / \"oxsium\" / \"Scripts\") + os.pathsep + env.get(\"PATH\", \"\")\n"
        "    else:\n"
        "        env[\"PATH\"] = str(ROOT / \"oxsium\" / \"bin\") + os.pathsep + env.get(\"PATH\", \"\")\n"
        "    env[\"VIRTUAL_ENV\"] = str(ROOT / \"oxsium\")\n"
        "    return env\n"
        "\n"
        "\n"
        "def _launch_kwargs() -> dict:\n"
        "    if os.name == \"nt\":\n"
        "        return {\"creationflags\": subprocess.CREATE_NEW_PROCESS_GROUP}\n"
        "    return {}\n"
        "\n"
        "\n"
        "# ── Service state ─────────────────────────────────────────────────────────────\n"
        "class Service:\n"
        "    def __init__(self, name: str, script: Path, default_port: int, port_attr: str):\n"
        "        self.name         = name\n"
        "        self.script       = script\n"
        "        self.default_port = default_port\n"
        "        self.port_attr    = port_attr\n"
        "        self.proc: subprocess.Popen | None = None\n"
        "        self.logs: list[str] = []\n"
        "        self.status  = \"stopped\"   # stopped | running | error\n"
        "        self._log_cb = None        # ui callback registered later\n"
        "\n"
        "    # public port (may be overridden by UI)\n"
        "    @property\n"
        "    def port(self) -> int:\n"
        "        return self._port if hasattr(self, \"_port\") else self.default_port\n"
        "\n"
        "    @port.setter\n"
        "    def port(self, v: int):\n"
        "        self._port = v\n"
        "\n"
        "    def add_log(self, line: str):\n"
        "        ts = time.strftime(\"%H:%M:%S\")\n"
        "        self.logs.append(f\"[{ts}]  {line}\")\n"
        "        if len(self.logs) > 500:\n"
        "            self.logs = self.logs[-400:]\n"
        "        if self._log_cb:\n"
        "            self._log_cb()\n"
        "\n"
        "    def start(self, ip: str):\n"
        "        if self.proc and self.proc.poll() is None:\n"
        "            return\n"
        "        if not self.script.exists():\n"
        "            self.status = \"error\"\n"
        "            self.add_log(f\"ERROR: script not found → {self.script}\")\n"
        "            return\n"
        "\n"
        "        cmd = [str(PYTHON), str(self.script)]\n"
        "        if self.name == \"Decision Engine\":\n"
        "            cmd += [\"server\", \"--ip\", ip, \"--port\", str(self.port)]\n"
        "        else:\n"
        "            cmd += [\"--ip\", ip, \"--port\", str(self.port)]\n"
        "\n"
        "        self.add_log(f\"Starting: {' '.join(cmd)}\")\n"
        "        try:\n"
        "            self.proc = subprocess.Popen(\n"
        "                cmd,\n"
        "                cwd=str(ROOT),\n"
        "                env=get_venv_env(),\n"
        "                stdout=subprocess.PIPE,\n"
        "                stderr=subprocess.STDOUT,\n"
        "                stdin=subprocess.DEVNULL,\n"
        "                text=True,\n"
        "                bufsize=1,\n"
        "                **_launch_kwargs(),\n"
        "            )\n"
        "            self.status = \"running\"\n"
        "            self.add_log(f\"PID {self.proc.pid} — listening on {ip}:{self.port}\")\n"
        "            threading.Thread(target=self._tail, daemon=True).start()\n"
        "            threading.Thread(target=self._watch, daemon=True).start()\n"
        "        except Exception as exc:\n"
        "            self.status = \"error\"\n"
        "            self.add_log(f\"LAUNCH ERROR: {exc}\")\n"
        "\n"
        "    def _tail(self):\n"
        "        try:\n"
        "            for line in self.proc.stdout:\n"
        "                self.add_log(line.rstrip())\n"
        "        except Exception:\n"
        "            pass\n"
        "\n"
        "    def _watch(self):\n"
        "        code = self.proc.wait()\n"
        "        if self.status == \"running\":\n"
        "            self.status = \"error\" if code != 0 else \"stopped\"\n"
        "            self.add_log(f\"Process exited — code {code}\")\n"
        "\n"
        "    def stop(self):\n"
        "        if self.proc and self.proc.poll() is None:\n"
        "            self.add_log(\"Stopping…\")\n"
        "            self.proc.terminate()\n"
        "            try:\n"
        "                self.proc.wait(timeout=5)\n"
        "            except subprocess.TimeoutExpired:\n"
        "                self.proc.kill()\n"
        "                self.proc.wait()\n"
        "            self.add_log(\"Stopped.\")\n"
        "        self.status = \"stopped\"\n"
        "        self.proc = None\n"
        "\n"
        "\n"
        "SERVICES = [\n"
        "    Service(\"Connection API\",  CONNECTION_PY, _load_port(CONNECTION_PY, \"PORT\", 5000), \"PORT\"),\n"
        "    Service(\"Decision Engine\", DECISION_PY,   _load_port(DECISION_PY,   \"PORT\", 5100), \"PORT\"),\n"
        "]\n"
        "\n"
        "\n"
        "# ── UI ────────────────────────────────────────────────────────────────────────\n"
        "def build_ui():\n"
        "    # global dark theme + Oxsium palette\n"
        "    ui.add_head_html(\"\"\"\n"
        "    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n"
        "    <link href=\"https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap\" rel=\"stylesheet\">\n"
        "    <style>\n"
        "      :root {\n"
        "        --bg-deep:   #0a0a0a;\n"
        "        --bg-base:   #111111;\n"
        "        --bg-panel:  #1a1a1a;\n"
        "        --bg-card:   #1f1f1f;\n"
        "        --bg-input:  #141414;\n"
        "        --border:    #2a2a2a;\n"
        "        --border-hi: #3d3d3d;\n"
        "        --accent:    #cc1a1a;\n"
        "        --accent-d:  #7a0f0f;\n"
        "        --accent-g:  rgba(204,26,26,.13);\n"
        "        --green:     #4caf50;\n"
        "        --amber:     #9e9e9e;\n"
        "        --red:       #cc1a1a;\n"
        "        --text-pri:  #d4d4d4;\n"
        "        --text-sec:  #7a7a7a;\n"
        "        --text-hi:   #f5f5f5;\n"
        "        --mono:      'Share Tech Mono', monospace;\n"
        "        --head:      'Rajdhani', sans-serif;\n"
        "        --ui:        'Space Mono', monospace;\n"
        "      }\n"
        "      * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "      body, .nicegui-content { background: var(--bg-deep) !important; }\n"
        "\n"
        "      /* topbar */\n"
        "      .ox-topbar {\n"
        "        background: var(--bg-base);\n"
        "        border-bottom: 1px solid var(--border);\n"
        "        padding: 0 24px;\n"
        "        height: 52px;\n"
        "        display: flex;\n"
        "        align-items: center;\n"
        "        gap: 14px;\n"
        "        position: sticky; top: 0; z-index: 100;\n"
        "      }\n"
        "      .ox-logo-mark {\n"
        "        width: 32px; height: 32px;\n"
        "        background: var(--accent);\n"
        "        clip-path: polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);\n"
        "        display: flex; align-items: center; justify-content: center;\n"
        "        font-family: var(--head); font-weight: 700; font-size: 13px;\n"
        "        color: #fff; letter-spacing: 1px; flex-shrink: 0;\n"
        "      }\n"
        "      .ox-title {\n"
        "        font-family: var(--head);\n"
        "        font-size: 18px; font-weight: 700;\n"
        "        color: var(--text-hi); letter-spacing: 2px;\n"
        "        text-transform: uppercase;\n"
        "      }\n"
        "      .ox-sub {\n"
        "        font-family: var(--mono);\n"
        "        font-size: 10px; color: var(--text-sec);\n"
        "        letter-spacing: 1px;\n"
        "        border-left: 2px solid var(--border);\n"
        "        padding-left: 12px;\n"
        "        margin-left: 4px;\n"
        "      }\n"
        "      .ox-badge {\n"
        "        margin-left: auto;\n"
        "        font-family: var(--mono);\n"
        "        font-size: 9px; color: var(--accent);\n"
        "        border: 1px solid var(--accent-d);\n"
        "        padding: 2px 8px; border-radius: 3px;\n"
        "        letter-spacing: 1.5px; text-transform: uppercase;\n"
        "        background: var(--accent-g);\n"
        "      }\n"
        "\n"
        "      /* global controls bar */\n"
        "      .ox-ctrl-bar {\n"
        "        background: var(--bg-panel);\n"
        "        border-bottom: 1px solid var(--border);\n"
        "        padding: 10px 24px;\n"
        "        display: flex; align-items: center; gap: 12px; flex-wrap: wrap;\n"
        "      }\n"
        "      .ox-ctrl-label {\n"
        "        font-family: var(--head);\n"
        "        font-size: 11px; font-weight: 700; letter-spacing: 1.5px;\n"
        "        color: var(--text-sec); text-transform: uppercase;\n"
        "      }\n"
        "\n"
        "      /* service grid */\n"
        "      .ox-grid {\n"
        "        display: grid;\n"
        "        grid-template-columns: repeat(auto-fit, minmax(520px, 1fr));\n"
        "        gap: 20px;\n"
        "        padding: 20px 24px;\n"
        "      }\n"
        "\n"
        "      /* service card */\n"
        "      .ox-card {\n"
        "        background: var(--bg-card);\n"
        "        border: 1px solid var(--border);\n"
        "        border-radius: 6px;\n"
        "        overflow: hidden;\n"
        "        display: flex; flex-direction: column;\n"
        "        transition: border-color .2s;\n"
        "      }\n"
        "      .ox-card.running  { border-color: rgba(76,175,80,.35); }\n"
        "      .ox-card.error    { border-color: rgba(204,26,26,.5); }\n"
        "\n"
        "      .ox-card-header {\n"
        "        padding: 14px 16px 12px;\n"
        "        border-bottom: 1px solid var(--border);\n"
        "        display: flex; align-items: center; gap: 12px;\n"
        "        background: var(--bg-panel);\n"
        "      }\n"
        "      .ox-status-dot {\n"
        "        width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;\n"
        "        background: var(--text-sec);\n"
        "        transition: background .3s;\n"
        "      }\n"
        "      .ox-status-dot.running { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite; }\n"
        "      .ox-status-dot.error   { background: var(--red);   box-shadow: 0 0 6px var(--red); }\n"
        "\n"
        "      @keyframes pulse {\n"
        "        0%,100% { opacity: 1; } 50% { opacity: .5; }\n"
        "      }\n"
        "\n"
        "      .ox-svc-name {\n"
        "        font-family: var(--head);\n"
        "        font-size: 15px; font-weight: 700; letter-spacing: 1.2px;\n"
        "        color: var(--text-hi); text-transform: uppercase;\n"
        "      }\n"
        "      .ox-svc-status {\n"
        "        font-family: var(--mono);\n"
        "        font-size: 10px; color: var(--text-sec); margin-top: 1px;\n"
        "      }\n"
        "      .ox-svc-status.running { color: var(--green); }\n"
        "      .ox-svc-status.error   { color: var(--red); }\n"
        "\n"
        "      /* port / ip row */\n"
        "      .ox-config-row {\n"
        "        display: flex; align-items: center; gap: 8px;\n"
        "        padding: 10px 16px; border-bottom: 1px solid var(--border);\n"
        "        background: var(--bg-base);\n"
        "        flex-wrap: wrap;\n"
        "      }\n"
        "      .ox-config-label {\n"
        "        font-family: var(--mono);\n"
        "        font-size: 10px; color: var(--text-sec);\n"
        "        letter-spacing: .8px; width: 36px; text-align: right;\n"
        "        text-transform: uppercase;\n"
        "      }\n"
        "      /* override NiceGUI input */\n"
        "      .ox-config-row .q-field { min-width: 0 !important; }\n"
        "      .ox-config-row .q-field__control { background: var(--bg-input) !important; }\n"
        "      .ox-config-row .q-field__native { color: var(--text-hi) !important; font-family: var(--mono) !important; font-size: 12px !important; }\n"
        "\n"
        "      /* log area */\n"
        "      .ox-log-header {\n"
        "        padding: 7px 16px;\n"
        "        background: var(--bg-base);\n"
        "        border-bottom: 1px solid var(--border);\n"
        "        display: flex; align-items: center; gap: 8px;\n"
        "      }\n"
        "      .ox-log-title {\n"
        "        font-family: var(--head); font-size: 10px; font-weight: 700;\n"
        "        color: var(--text-sec); letter-spacing: 1.5px; text-transform: uppercase;\n"
        "      }\n"
        "      .ox-log-count {\n"
        "        margin-left: auto;\n"
        "        font-family: var(--mono); font-size: 9px; color: var(--text-dim, #555);\n"
        "      }\n"
        "      .ox-log-box {\n"
        "        flex: 1; min-height: 220px; max-height: 320px;\n"
        "        overflow-y: auto;\n"
        "        padding: 12px 16px;\n"
        "        background: var(--bg-deep);\n"
        "        font-family: var(--mono); font-size: 11px; line-height: 1.65;\n"
        "        color: #888;\n"
        "        white-space: pre-wrap; word-break: break-all;\n"
        "      }\n"
        "      .ox-log-box::-webkit-scrollbar { width: 4px; }\n"
        "      .ox-log-box::-webkit-scrollbar-track { background: transparent; }\n"
        "      .ox-log-box::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: 2px; }\n"
        "\n"
        "      .ox-log-line { display: block; }\n"
        "      .ox-log-line .ts { color: var(--text-dim, #444); }\n"
        "      .ox-log-line .body { color: #9e9e9e; }\n"
        "      .ox-log-line.err .body  { color: var(--red); }\n"
        "      .ox-log-line.warn .body { color: #a5855a; }\n"
        "      .ox-log-line.ok .body   { color: var(--green); }\n"
        "\n"
        "      /* card footer */\n"
        "      .ox-card-footer {\n"
        "        padding: 10px 16px;\n"
        "        border-top: 1px solid var(--border);\n"
        "        background: var(--bg-panel);\n"
        "        display: flex; align-items: center; gap: 8px;\n"
        "      }\n"
        "\n"
        "      /* buttons */\n"
        "      .ox-btn {\n"
        "        font-family: var(--head); font-weight: 700; font-size: 12px;\n"
        "        letter-spacing: 1.2px; text-transform: uppercase;\n"
        "        border: 1px solid; border-radius: 4px;\n"
        "        padding: 5px 16px; cursor: pointer;\n"
        "        transition: background .15s, color .15s;\n"
        "        background: transparent;\n"
        "      }\n"
        "      .ox-btn-run  { color: var(--green); border-color: rgba(76,175,80,.4); }\n"
        "      .ox-btn-run:hover { background: rgba(76,175,80,.1); }\n"
        "      .ox-btn-stop { color: var(--red);   border-color: rgba(204,26,26,.4); }\n"
        "      .ox-btn-stop:hover { background: rgba(204,26,26,.1); }\n"
        "      .ox-btn-clear { color: var(--text-sec); border-color: var(--border); font-size: 10px; padding: 4px 10px; }\n"
        "      .ox-btn-clear:hover { background: var(--bg-hover, #202020); }\n"
        "      .ox-btn-all  { color: var(--text-hi); border-color: var(--border-hi); }\n"
        "      .ox-btn-all:hover { background: rgba(255,255,255,.05); }\n"
        "      .ox-btn-all-stop { color: var(--amber); border-color: rgba(158,158,158,.3); }\n"
        "      .ox-btn-all-stop:hover { background: rgba(158,158,158,.07); }\n"
        "\n"
        "      /* info strip */\n"
        "      .ox-info-strip {\n"
        "        padding: 8px 24px;\n"
        "        background: var(--bg-panel);\n"
        "        border-top: 1px solid var(--border);\n"
        "        display: flex; gap: 24px; flex-wrap: wrap;\n"
        "      }\n"
        "      .ox-info-item {\n"
        "        font-family: var(--mono); font-size: 10px; color: var(--text-sec);\n"
        "        display: flex; gap: 6px; align-items: center;\n"
        "      }\n"
        "      .ox-info-item span { color: var(--text-pri); }\n"
        "    </style>\n"
        "    \"\"\")\n"
        "\n"
        "    # ── Topbar ─────────────────────────────────────────────────────────────\n"
        "    with ui.element(\"div\").classes(\"ox-topbar\"):\n"
        "        ui.element(\"div\").classes(\"ox-logo-mark\").style(\"font-size:11px\").bind_text_from({}, \"OX\")\n"
        "        ui.html('<div class=\"ox-logo-mark\">OX</div><div class=\"ox-title\">Oxsium Framework</div>')\n"
        "        ui.html('<div class=\"ox-sub\">Service Launcher v2</div>')\n"
        "        ui.html('<div class=\"ox-badge\">Control Panel</div>')\n"
        "\n"
        "    # shared IP input value\n"
        "    shared_ip = {\"value\": \"0.0.0.0\"}\n"
        "\n"
        "    # ── Global controls ────────────────────────────────────────────────────\n"
        "    with ui.element(\"div\").classes(\"ox-ctrl-bar\"):\n"
        "        ui.html('<span class=\"ox-ctrl-label\">Global IP</span>')\n"
        "        global_ip = ui.input(value=\"0.0.0.0\").style(\n"
        "            \"width:150px; background:#141414; border:1px solid #2a2a2a; \"\n"
        "            \"border-radius:4px; padding:4px 8px; color:#d4d4d4; \"\n"
        "            \"font-family:'Share Tech Mono',monospace; font-size:12px;\"\n"
        "        ).props(\"dense outlined dark\")\n"
        "        global_ip.style(\"margin-right:8px\")\n"
        "\n"
        "        def start_all():\n"
        "            for svc in SERVICES:\n"
        "                svc.port = svc._port if hasattr(svc, \"_port\") else svc.default_port\n"
        "                svc.start(global_ip.value)\n"
        "            refresh_all()\n"
        "\n"
        "        def stop_all():\n"
        "            for svc in SERVICES:\n"
        "                svc.stop()\n"
        "            refresh_all()\n"
        "\n"
        "        ui.button(\"▶  Start All\", on_click=start_all).props(\"flat\").style(\n"
        "            \"font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; \"\n"
        "            \"letter-spacing:1.2px; color:#4caf50; border:1px solid rgba(76,175,80,.4); \"\n"
        "            \"border-radius:4px; padding:4px 14px; text-transform:uppercase;\"\n"
        "        )\n"
        "        ui.button(\"■  Stop All\", on_click=stop_all).props(\"flat\").style(\n"
        "            \"font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; \"\n"
        "            \"letter-spacing:1.2px; color:#9e9e9e; border:1px solid rgba(158,158,158,.3); \"\n"
        "            \"border-radius:4px; padding:4px 14px; text-transform:uppercase;\"\n"
        "        )\n"
        "\n"
        "    # ── Service cards ──────────────────────────────────────────────────────\n"
        "    card_refresh_fns: list = []\n"
        "\n"
        "    with ui.element(\"div\").classes(\"ox-grid\"):\n"
        "        for svc in SERVICES:\n"
        "            _build_service_card(svc, global_ip, card_refresh_fns)\n"
        "\n"
        "    def refresh_all():\n"
        "        for fn in card_refresh_fns:\n"
        "            fn()\n"
        "\n"
        "    # auto-refresh every 1 s\n"
        "    ui.timer(1.0, refresh_all)\n"
        "\n"
        "    # ── Info strip ─────────────────────────────────────────────────────────\n"
        "    ui.html(f\"\"\"\n"
        "    <div class=\"ox-info-strip\">\n"
        "      <div class=\"ox-info-item\">Python <span>{PYTHON}</span></div>\n"
        "      <div class=\"ox-info-item\">Venv <span>{'found' if VENV_PYTHON.exists() else 'not found — using system Python'}</span></div>\n"
        "      <div class=\"ox-info-item\">Connection Script <span>{'✓' if CONNECTION_PY.exists() else '✗ missing'}</span></div>\n"
        "      <div class=\"ox-info-item\">Decision Script <span>{'✓' if DECISION_PY.exists() else '✗ missing'}</span></div>\n"
        "    </div>\n"
        "    \"\"\")\n"
        "\n"
        "\n"
        "def _build_service_card(svc: Service, global_ip_input, refresh_list: list):\n"
        "    \"\"\"Builds one service card and registers its refresh function.\"\"\"\n"
        "\n"
        "    card_el     = ui.element(\"div\").classes(\"ox-card\")\n"
        "    header_el   = None\n"
        "    dot_el      = None\n"
        "    status_el   = None\n"
        "    log_el      = None\n"
        "    port_input  = None\n"
        "\n"
        "    with card_el:\n"
        "        # header\n"
        "        with ui.element(\"div\").classes(\"ox-card-header\") as header_el:\n"
        "            dot_el = ui.element(\"div\").classes(\"ox-status-dot\")\n"
        "            with ui.element(\"div\"):\n"
        "                ui.html(f'<div class=\"ox-svc-name\">{svc.name}</div>')\n"
        "                status_el = ui.element(\"div\").classes(\"ox-svc-status\").style(\"font-family:'Share Tech Mono',monospace; font-size:10px; color:#7a7a7a;\")\n"
        "                with status_el:\n"
        "                    ui.label(\"● STOPPED\")\n"
        "\n"
        "        # config row\n"
        "        with ui.element(\"div\").classes(\"ox-config-row\"):\n"
        "            ui.html('<span class=\"ox-config-label\">PORT</span>')\n"
        "            port_input = ui.number(value=svc.default_port, min=1, max=65535).style(\n"
        "                \"width:90px; background:#141414; border:1px solid #2a2a2a; \"\n"
        "                \"border-radius:4px; padding:3px 8px; color:#f5f5f5; \"\n"
        "                \"font-family:'Share Tech Mono',monospace; font-size:12px;\"\n"
        "            ).props(\"dense outlined dark\")\n"
        "\n"
        "            ui.html('<span class=\"ox-config-label\" style=\"margin-left:12px;\">IP</span>')\n"
        "            ui.html(f'<span style=\"font-family:\\'Share Tech Mono\\',monospace; font-size:11px; color:#7a7a7a;\">→ uses global IP</span>')\n"
        "\n"
        "        # log header\n"
        "        with ui.element(\"div\").classes(\"ox-log-header\"):\n"
        "            ui.html('<span class=\"ox-log-title\">Output Log</span>')\n"
        "            log_count_el = ui.element(\"span\").classes(\"ox-log-count\")\n"
        "            with log_count_el:\n"
        "                ui.label(\"0 lines\")\n"
        "\n"
        "        # log body\n"
        "        log_el = ui.element(\"div\").classes(\"ox-log-box\")\n"
        "\n"
        "        # footer buttons\n"
        "        with ui.element(\"div\").classes(\"ox-card-footer\"):\n"
        "            def make_start(s=svc, pi=port_input):\n"
        "                def _start():\n"
        "                    s.port = int(pi.value or s.default_port)\n"
        "                    s.start(global_ip_input.value)\n"
        "                return _start\n"
        "\n"
        "            def make_stop(s=svc):\n"
        "                def _stop():\n"
        "                    s.stop()\n"
        "                return _stop\n"
        "\n"
        "            def make_clear(s=svc):\n"
        "                def _clear():\n"
        "                    s.logs.clear()\n"
        "                return _clear\n"
        "\n"
        "            ui.button(\"▶ Start\", on_click=make_start()).props(\"flat\").style(\n"
        "                \"font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; \"\n"
        "                \"letter-spacing:1.2px; color:#4caf50; border:1px solid rgba(76,175,80,.4); \"\n"
        "                \"border-radius:4px; padding:4px 14px; text-transform:uppercase;\"\n"
        "            )\n"
        "            ui.button(\"■ Stop\", on_click=make_stop()).props(\"flat\").style(\n"
        "                \"font-family:'Rajdhani',sans-serif; font-weight:700; font-size:12px; \"\n"
        "                \"letter-spacing:1.2px; color:#cc1a1a; border:1px solid rgba(204,26,26,.4); \"\n"
        "                \"border-radius:4px; padding:4px 14px; text-transform:uppercase;\"\n"
        "            )\n"
        "            ui.element(\"div\").style(\"flex:1\")\n"
        "            ui.button(\"Clear\", on_click=make_clear()).props(\"flat\").style(\n"
        "                \"font-family:'Rajdhani',sans-serif; font-weight:600; font-size:10px; \"\n"
        "                \"letter-spacing:1px; color:#7a7a7a; border:1px solid #2a2a2a; \"\n"
        "                \"border-radius:4px; padding:3px 10px; text-transform:uppercase;\"\n"
        "            )\n"
        "\n"
        "    # ── refresh closure ────────────────────────────────────────────────────\n"
        "    def refresh():\n"
        "        st = svc.status\n"
        "        # card border class\n"
        "        card_el._props[\"class\"] = f\"ox-card {st}\"\n"
        "\n"
        "        # dot\n"
        "        dot_el._props[\"class\"] = f\"ox-status-dot {st}\"\n"
        "\n"
        "        # status text + color\n"
        "        status_el.clear()\n"
        "        color_map = {\"running\": \"#4caf50\", \"error\": \"#cc1a1a\", \"stopped\": \"#7a7a7a\"}\n"
        "        label_map = {\"running\": \"● RUNNING\", \"error\": \"● ERROR\",   \"stopped\": \"● STOPPED\"}\n"
        "        with status_el:\n"
        "            ui.label(label_map.get(st, st.upper())).style(\n"
        "                f\"font-family:'Share Tech Mono',monospace; font-size:10px; color:{color_map.get(st,'#7a7a7a')};\"\n"
        "            )\n"
        "\n"
        "        # logs\n"
        "        log_el.clear()\n"
        "        with log_el:\n"
        "            for line in svc.logs[-300:]:\n"
        "                low = line.lower()\n"
        "                cls = \"err\" if any(k in low for k in (\"error\",\"xeta\",\"traceback\",\"critical\",\"fail\")) \\\n"
        "                     else \"ok\" if any(k in low for k in (\"start\",\"listen\",\"pid\",\"ok\",\"success\",\"running\")) \\\n"
        "                     else \"warn\" if any(k in low for k in (\"warn\",\"xeberdarl\")) \\\n"
        "                     else \"\"\n"
        "                # split timestamp from body\n"
        "                if line.startswith(\"[\") and \"]\" in line:\n"
        "                    ts, body = line.split(\"]\", 1)\n"
        "                    html_line = (\n"
        "                        f'<span class=\"ts\">{ts}]</span>'\n"
        "                        f'<span class=\"body\">{body}</span>'\n"
        "                    )\n"
        "                else:\n"
        "                    html_line = f'<span class=\"body\">{line}</span>'\n"
        "                ui.html(f'<span class=\"ox-log-line {cls}\">{html_line}</span>')\n"
        "\n"
        "        # line count\n"
        "        log_count_el.clear()\n"
        "        with log_count_el:\n"
        "            ui.label(f\"{len(svc.logs)} lines\").style(\n"
        "                \"font-family:'Share Tech Mono',monospace; font-size:9px; color:#444;\"\n"
        "            )\n"
        "\n"
        "        # auto-scroll via JS\n"
        "        ui.run_javascript(\n"
        "            f\"var el=document.querySelectorAll('.ox-log-box')[{SERVICES.index(svc)}];\"\n"
        "            \"if(el) el.scrollTop=el.scrollHeight;\"\n"
        "        )\n"
        "\n"
        "    refresh_list.append(refresh)\n"
        "\n"
        "\n"
        "# ── Entry point ───────────────────────────────────────────────────────────────\n"
        "@ui.page(\"/\")\n"
        "def index():\n"
        "    build_ui()\n"
        "\n"
        "\n"
        "if __name__ in (\"__main__\", \"__mp_main__\"):\n"
        "    ui.run(\n"
        "        title=\"Oxsium Framework — Launcher\",\n"
        "        favicon=\"🔺\",\n"
        "        dark=True,\n"
        "        port=8080,\n"
        "        reload=False,\n"
        "        show=True,\n"
        "    )\n"
;
}

static bool create_launchers(const fs::path& root) {
    bool ok1 = write_file(
        root / "start.py",
        start_py_template()
    );
    if (!ok1) {
        err("Failed to write start.py script.");
        return false;
    }
    ok("start.py created");
    bullet(ansi::DIM() + "=>  NiceGUI control panel — open browser at http://127.0.0.1:8080" + ansi::RST());
    return true;
}


int main() {
    ansi::init();
    print_banner();

    const fs::path exe_path = fs::current_path() / "setup.exe";

    const fs::path root = locate_root(exe_path.parent_path());
    std::cout << ansi::DIM() << "  Project root : "
              << ansi::PATH_CLR() << root.string() << ansi::RST() << "\n";

    step_header(1, "Python Runtime Check");
    if (!ensure_python()) return 1;

    step_header(2, "Virtual Environment");
    if (!create_virtual_environment(root)) {
        err("Could not create virtual environment. Aborting.");
        return 1;
    }

    step_header(3, "Installing Dependencies");
    if (!install_requirements(root)) {
        err("Could not install required packages. Aborting.");
        return 1;
    }

    step_header(4, "Generating Launcher Scripts");
    if (!create_launchers(root)) {
        err("Could not generate launcher scripts. Aborting.");
        return 1;
    }

    print_success(root);
    return 0;
}