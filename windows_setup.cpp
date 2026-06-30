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
              << ansi::RST() << ansi::DIM() << "   =>  opens native desktop GUI (Dear PyGui window)\n" << ansi::RST();
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
        "Oxsium Framework — Dear PyGui Desktop Launcher\n"
        "Native GPU-rendered desktop application.\n"
        "Run: python start.py\n"
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
        "# ── Resolve venv & ensure dearpygui ──────────────────────────────────────────\n"
        "ROOT = Path(__file__).resolve().parent\n"
        "VENV_PYTHON = (\n"
        "    ROOT / \"oxsium\"\n"
        "    / (\"Scripts\" if os.name == \"nt\" else \"bin\")\n"
        "    / (\"python.exe\" if os.name == \"nt\" else \"python\")\n"
        ")\n"
        "PYTHON = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)\n"
        "\n"
        "\n"
        "def _ensure_pkg(pkg: str, pip_name: str | None = None) -> None:\n"
        "    \"\"\"\n"
        "    Make sure `pkg` is importable, preferring the oxsium venv.\n"
        "    Adds venv site-packages to sys.path first; falls back to pip install.\n"
        "    \"\"\"\n"
        "    if importlib.util.find_spec(pkg) is not None:\n"
        "        return\n"
        "\n"
        "    # Try injecting venv site-packages\n"
        "    venv_dir = ROOT / \"oxsium\"\n"
        "    if venv_dir.exists():\n"
        "        import glob as _glob\n"
        "        for pat in [\n"
        "            str(venv_dir / \"Lib\" / \"site-packages\"),\n"
        "            str(venv_dir / \"lib\" / \"python*\" / \"site-packages\"),\n"
        "        ]:\n"
        "            for sp in _glob.glob(pat):\n"
        "                if sp not in sys.path:\n"
        "                    sys.path.insert(0, sp)\n"
        "        if importlib.util.find_spec(pkg) is not None:\n"
        "            return\n"
        "\n"
        "    # Last resort: install into current interpreter\n"
        "    name = pip_name or pkg\n"
        "    print(f\"  [SETUP] '{name}' not found — installing...\")\n"
        "    subprocess.check_call(\n"
        "        [sys.executable, \"-m\", \"pip\", \"install\", name, \"--quiet\"],\n"
        "        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n"
        "    )\n"
        "    print(f\"  [SETUP] '{name}' installed.\\n\")\n"
        "\n"
        "\n"
        "_ensure_pkg(\"dearpygui\")\n"
        "\n"
        "import dearpygui.dearpygui as dpg  # noqa: E402\n"
        "\n"
        "# ── Project paths ─────────────────────────────────────────────────────────────\n"
        "CONNECTION_PY = ROOT / \"Main\" / \"connect\" / \"connection.py\"\n"
        "DECISION_PY   = ROOT / \"Main\" / \"Decision Engine\" / \"Helpers\" / \"root_principal.py\"\n"
        "HTML_FILE     = ROOT / \"Main\" / \"Oxsium-Framework.html\"\n"
        "\n"
        "# ── Palette ───────────────────────────────────────────────────────────────────\n"
        "C_BG_DEEP    = (10,  10,  10,  255)\n"
        "C_BG_BASE    = (17,  17,  17,  255)\n"
        "C_BG_PANEL   = (26,  26,  26,  255)\n"
        "C_BG_CARD    = (31,  31,  31,  255)\n"
        "C_BG_INPUT   = (20,  20,  20,  255)\n"
        "C_BORDER     = (42,  42,  42,  255)\n"
        "C_BORDER_HI  = (61,  61,  61,  255)\n"
        "C_ACCENT     = (204, 26,  26,  255)\n"
        "C_ACCENT_D   = (122, 15,  15,  255)\n"
        "C_ACCENT_G   = (204, 26,  26,  35 )\n"
        "C_GREEN      = (76,  175, 80,  255)\n"
        "C_GREEN_D    = (76,  175, 80,  40 )\n"
        "C_AMBER      = (158, 158, 100, 255)\n"
        "C_RED        = (204, 26,  26,  255)\n"
        "C_RED_D      = (204, 26,  26,  40 )\n"
        "C_TEXT_HI    = (245, 245, 245, 255)\n"
        "C_TEXT_PRI   = (212, 212, 212, 255)\n"
        "C_TEXT_SEC   = (122, 122, 122, 255)\n"
        "C_TEXT_DIM   = (68,  68,  68,  255)\n"
        "C_TRANSPARENT= (0,   0,   0,   0  )\n"
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
        "# ── Service model ─────────────────────────────────────────────────────────────\n"
        "class Service:\n"
        "    MAX_LOGS = 500\n"
        "\n"
        "    def __init__(self, key: str, name: str, script: Path, default_port: int):\n"
        "        self.key          = key\n"
        "        self.name         = name\n"
        "        self.script       = script\n"
        "        self.default_port = default_port\n"
        "        self._port        = default_port\n"
        "        self.proc: subprocess.Popen | None = None\n"
        "        self.logs: list[str] = []\n"
        "        self.status       = \"stopped\"   # stopped | running | error\n"
        "        self._lock        = threading.Lock()\n"
        "\n"
        "    @property\n"
        "    def port(self) -> int:\n"
        "        return self._port\n"
        "\n"
        "    @port.setter\n"
        "    def port(self, v: int):\n"
        "        self._port = int(v)\n"
        "\n"
        "    def _log(self, line: str):\n"
        "        ts = time.strftime(\"%H:%M:%S\")\n"
        "        entry = f\"[{ts}]  {line}\"\n"
        "        with self._lock:\n"
        "            self.logs.append(entry)\n"
        "            if len(self.logs) > self.MAX_LOGS:\n"
        "                self.logs = self.logs[-400:]\n"
        "\n"
        "    def start(self, ip: str):\n"
        "        if self.proc and self.proc.poll() is None:\n"
        "            return\n"
        "        if not self.script.exists():\n"
        "            self.status = \"error\"\n"
        "            self._log(f\"ERROR: script not found → {self.script}\")\n"
        "            return\n"
        "\n"
        "        cmd = [str(PYTHON), str(self.script)]\n"
        "        if self.key == \"dec\":\n"
        "            cmd += [\"server\", \"--ip\", ip, \"--port\", str(self._port)]\n"
        "        else:\n"
        "            cmd += [\"--ip\", ip, \"--port\", str(self._port)]\n"
        "\n"
        "        self._log(f\"Starting: {' '.join(cmd)}\")\n"
        "        try:\n"
        "            self.proc = subprocess.Popen(\n"
        "                cmd,\n"
        "                cwd=str(ROOT),\n"
        "                env=get_venv_env(),\n"
        "                stdout=subprocess.PIPE,\n"
        "                stderr=subprocess.STDOUT,\n"
        "                stdin=subprocess.DEVNULL,\n"
        "                text=True, bufsize=1,\n"
        "                **_launch_kwargs(),\n"
        "            )\n"
        "            self.status = \"running\"\n"
        "            self._log(f\"PID {self.proc.pid}  —  {ip}:{self._port}\")\n"
        "            threading.Thread(target=self._tail,  daemon=True).start()\n"
        "            threading.Thread(target=self._watch, daemon=True).start()\n"
        "        except Exception as exc:\n"
        "            self.status = \"error\"\n"
        "            self._log(f\"LAUNCH ERROR: {exc}\")\n"
        "\n"
        "    def _tail(self):\n"
        "        try:\n"
        "            for line in self.proc.stdout:\n"
        "                self._log(line.rstrip())\n"
        "        except Exception:\n"
        "            pass\n"
        "\n"
        "    def _watch(self):\n"
        "        code = self.proc.wait()\n"
        "        if self.status == \"running\":\n"
        "            self.status = \"error\" if code != 0 else \"stopped\"\n"
        "            self._log(f\"Process exited — code {code}\")\n"
        "\n"
        "    def stop(self):\n"
        "        if self.proc and self.proc.poll() is None:\n"
        "            self._log(\"Stopping…\")\n"
        "            self.proc.terminate()\n"
        "            try:\n"
        "                self.proc.wait(timeout=5)\n"
        "            except subprocess.TimeoutExpired:\n"
        "                self.proc.kill()\n"
        "                self.proc.wait()\n"
        "            self._log(\"Stopped.\")\n"
        "        self.status = \"stopped\"\n"
        "        self.proc = None\n"
        "\n"
        "\n"
        "SERVICES = [\n"
        "    Service(\"conn\", \"CONNECTION  API\",\n"
        "            CONNECTION_PY, _load_port(CONNECTION_PY, \"PORT\", 5000)),\n"
        "    Service(\"dec\",  \"DECISION  ENGINE\",\n"
        "            DECISION_PY,   _load_port(DECISION_PY,   \"PORT\", 5100)),\n"
        "]\n"
        "\n"
        "\n"
        "# ── Theme builder ─────────────────────────────────────────────────────────────\n"
        "def _make_global_theme() -> int:\n"
        "    with dpg.theme() as t:\n"
        "        with dpg.theme_component(dpg.mvAll):\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_WindowBg,        C_BG_DEEP)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ChildBg,         C_BG_BASE)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_PopupBg,         C_BG_PANEL)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Border,          C_BORDER)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,         C_BG_INPUT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered,  C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive,   C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_TitleBg,         C_BG_BASE)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive,   C_BG_PANEL)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_MenuBarBg,       C_BG_BASE)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarBg,     C_BG_DEEP)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrab,   C_BORDER_HI)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabHovered, C_ACCENT_D)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ScrollbarGrabActive,  C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_CheckMark,       C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_SliderGrab,      C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_SliderGrabActive,C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Button,          C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered,   C_BG_PANEL)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive,    C_ACCENT_D)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Header,          C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered,   C_BG_PANEL)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_HeaderActive,    C_ACCENT_D)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Separator,       C_BORDER)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_SeparatorHovered,C_ACCENT_D)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_SeparatorActive, C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ResizeGrip,       C_TRANSPARENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripHovered, C_ACCENT_D)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ResizeGripActive,  C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Tab,             C_BG_BASE)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_TabHovered,      C_BG_PANEL)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_TabActive,       C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Text,            C_TEXT_PRI)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_TextDisabled,    C_TEXT_DIM)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_PlotLines,       C_ACCENT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_PlotHistogram,   C_ACCENT)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_WindowRounding,   0.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,    3.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_ChildRounding,    3.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_GrabRounding,     2.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_WindowBorderSize, 1.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_ChildBorderSize,  1.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize,  0.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_WindowPadding,    16, 12)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,     10,  6)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing,       8,  6)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_ItemInnerSpacing,  6,  4)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_ScrollbarSize,     8.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_IndentSpacing,    16.0)\n"
        "    return t\n"
        "\n"
        "\n"
        "def _btn_theme(bg: tuple, bg_hov: tuple, bg_act: tuple, text: tuple) -> int:\n"
        "    with dpg.theme() as t:\n"
        "        with dpg.theme_component(dpg.mvButton):\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Button,        bg)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, bg_hov)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_ButtonActive,  bg_act)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Text,          text)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 3.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,  12, 5)\n"
        "    return t\n"
        "\n"
        "\n"
        "def _log_theme() -> int:\n"
        "    with dpg.theme() as t:\n"
        "        with dpg.theme_component(dpg.mvInputText):\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,        C_BG_DEEP)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, C_BG_DEEP)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive,  C_BG_DEEP)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Text,           C_TEXT_SEC)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Border,         C_BORDER)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,  0.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,   8, 6)\n"
        "    return t\n"
        "\n"
        "\n"
        "def _input_theme() -> int:\n"
        "    with dpg.theme() as t:\n"
        "        with dpg.theme_component(dpg.mvInputText):\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,        C_BG_INPUT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive,  C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Text,           C_TEXT_HI)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Border,         C_BORDER_HI)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,  3.0)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,   8, 5)\n"
        "        with dpg.theme_component(dpg.mvInputInt):\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBg,        C_BG_INPUT)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive,  C_BG_CARD)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Text,           C_TEXT_HI)\n"
        "            dpg.add_theme_color(dpg.mvThemeCol_Border,         C_BORDER_HI)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding,  3.0, category=dpg.mvThemeCat_Core)\n"
        "            dpg.add_theme_style(dpg.mvStyleVar_FramePadding,   8, 5, category=dpg.mvThemeCat_Core)\n"
        "    return t\n"
        "\n"
        "\n"
        "# ── UI state ──────────────────────────────────────────────────────────────────\n"
        "# tag dicts updated in build_ui, read in render_loop\n"
        "_log_tags:     dict[str, str] = {}   # key -> dpg tag of log input_text\n"
        "_status_tags:  dict[str, str] = {}   # key -> dpg tag of status text\n"
        "_dot_tags:     dict[str, str] = {}   # key -> dpg tag of dot text\n"
        "_log_snapshots: dict[str, int] = {}  # key -> last log count (dirty check)\n"
        "\n"
        "\n"
        "# ── UI builder ────────────────────────────────────────────────────────────────\n"
        "def build_ui():\n"
        "    theme_start  = _btn_theme(C_BG_CARD,  (20, 60, 20, 255), (30, 100, 30, 255), C_GREEN)\n"
        "    theme_stop   = _btn_theme(C_BG_CARD,  (60, 10, 10, 255), (100, 15, 15, 255), C_RED)\n"
        "    theme_clear  = _btn_theme(C_BG_DEEP,  C_BG_BASE,          C_BG_PANEL,         C_TEXT_SEC)\n"
        "    theme_all_go = _btn_theme(C_ACCENT_D, (160, 20, 20, 255), C_ACCENT,           C_TEXT_HI)\n"
        "    theme_all_st = _btn_theme(C_BG_PANEL, C_BG_CARD,          C_BG_CARD,          C_TEXT_SEC)\n"
        "    theme_log    = _log_theme()\n"
        "    theme_input  = _input_theme()\n"
        "\n"
        "    with dpg.window(tag=\"main_win\", no_title_bar=True, no_move=True,\n"
        "                    no_resize=True, no_scrollbar=True, no_collapse=True):\n"
        "\n"
        "        # ── TOP BAR ───────────────────────────────────────────────────────\n"
        "        with dpg.group(horizontal=True):\n"
        "            dpg.add_text(\"◆\", color=C_ACCENT)\n"
        "            dpg.add_text(\"OXSIUM FRAMEWORK\", color=C_TEXT_HI)\n"
        "            dpg.add_text(\"  |  SERVICE LAUNCHER\", color=C_TEXT_DIM)\n"
        "            dpg.add_text(\n"
        "                f\"  Python: {PYTHON.name}  \"\n"
        "                f\"Venv: {'✓' if VENV_PYTHON.exists() else '✗'}\",\n"
        "                color=C_TEXT_DIM,\n"
        "            )\n"
        "\n"
        "        dpg.add_spacer(height=4)\n"
        "        dpg.add_separator()\n"
        "        dpg.add_spacer(height=8)\n"
        "\n"
        "        # ── GLOBAL CONTROLS ───────────────────────────────────────────────\n"
        "        with dpg.child_window(height=52, border=True, tag=\"ctrl_bar\"):\n"
        "            with dpg.group(horizontal=True):\n"
        "                dpg.add_spacer(width=4)\n"
        "                dpg.add_text(\"GLOBAL IP\", color=C_TEXT_SEC)\n"
        "                dpg.add_spacer(width=6)\n"
        "                dpg.add_input_text(\n"
        "                    tag=\"global_ip\", default_value=\"0.0.0.0\",\n"
        "                    width=140, hint=\"IP address\",\n"
        "                )\n"
        "                dpg.bind_item_theme(\"global_ip\", theme_input)\n"
        "                dpg.add_spacer(width=16)\n"
        "\n"
        "                def _start_all():\n"
        "                    ip = dpg.get_value(\"global_ip\")\n"
        "                    for svc in SERVICES:\n"
        "                        svc.start(ip)\n"
        "\n"
        "                def _stop_all():\n"
        "                    for svc in SERVICES:\n"
        "                        svc.stop()\n"
        "\n"
        "                b1 = dpg.add_button(label=\"  ▶  START ALL  \", callback=_start_all, height=30)\n"
        "                dpg.bind_item_theme(b1, theme_all_go)\n"
        "                dpg.add_spacer(width=6)\n"
        "                b2 = dpg.add_button(label=\"  ■  STOP ALL  \", callback=_stop_all, height=30)\n"
        "                dpg.bind_item_theme(b2, theme_all_st)\n"
        "\n"
        "        dpg.add_spacer(height=10)\n"
        "\n"
        "        # ── SERVICE CARDS (side by side) ──────────────────────────────────\n"
        "        with dpg.group(horizontal=True, tag=\"cards_row\"):\n"
        "            for svc in SERVICES:\n"
        "                _build_card(svc, theme_start, theme_stop, theme_clear,\n"
        "                            theme_log, theme_input)\n"
        "                dpg.add_spacer(width=12)\n"
        "\n"
        "        dpg.add_spacer(height=8)\n"
        "        dpg.add_separator()\n"
        "        dpg.add_spacer(height=4)\n"
        "\n"
        "        # ── STATUS BAR ────────────────────────────────────────────────────\n"
        "        with dpg.group(horizontal=True):\n"
        "            dpg.add_spacer(width=4)\n"
        "            conn_ok = CONNECTION_PY.exists()\n"
        "            dec_ok  = DECISION_PY.exists()\n"
        "            dpg.add_text(\"Connection Script:\", color=C_TEXT_DIM)\n"
        "            dpg.add_text(\"✓ found\" if conn_ok else \"✗ missing\",\n"
        "                         color=C_GREEN if conn_ok else C_RED)\n"
        "            dpg.add_spacer(width=20)\n"
        "            dpg.add_text(\"Decision Script:\", color=C_TEXT_DIM)\n"
        "            dpg.add_text(\"✓ found\" if dec_ok else \"✗ missing\",\n"
        "                         color=C_GREEN if dec_ok else C_RED)\n"
        "            dpg.add_spacer(width=20)\n"
        "            dpg.add_text(\"Framework HTML:\", color=C_TEXT_DIM)\n"
        "            html_ok = HTML_FILE.exists()\n"
        "            dpg.add_text(\"✓ found\" if html_ok else \"✗ missing\",\n"
        "                         color=C_GREEN if html_ok else C_AMBER)\n"
        "\n"
        "\n"
        "def _build_card(svc: Service, t_start, t_stop, t_clear, t_log, t_input):\n"
        "    \"\"\"Build one service card. Tags derived from svc.key.\"\"\"\n"
        "    k = svc.key\n"
        "\n"
        "    # We'll set actual width in resize callback; use 0 for now\n"
        "    with dpg.child_window(tag=f\"card_{k}\", border=True,\n"
        "                          width=0, height=0, no_scrollbar=True):\n"
        "\n"
        "        # ── card header ───────────────────────────────────────────────\n"
        "        with dpg.group(horizontal=True):\n"
        "            dot = dpg.add_text(\"●\", color=C_TEXT_SEC)\n"
        "            _dot_tags[k] = dot\n"
        "            dpg.add_spacer(width=6)\n"
        "            dpg.add_text(svc.name, color=C_TEXT_HI)\n"
        "            dpg.add_spacer(width=10)\n"
        "            st = dpg.add_text(\"STOPPED\", color=C_TEXT_SEC)\n"
        "            _status_tags[k] = st\n"
        "\n"
        "        dpg.add_spacer(height=6)\n"
        "        dpg.add_separator()\n"
        "        dpg.add_spacer(height=8)\n"
        "\n"
        "        # ── config row ────────────────────────────────────────────────\n"
        "        with dpg.group(horizontal=True):\n"
        "            dpg.add_text(\"PORT\", color=C_TEXT_SEC)\n"
        "            dpg.add_spacer(width=8)\n"
        "            port_tag = f\"port_{k}\"\n"
        "            dpg.add_input_int(\n"
        "                tag=port_tag, default_value=svc.default_port,\n"
        "                min_value=1, max_value=65535, min_clamped=True,\n"
        "                max_clamped=True, width=110, step=0, step_fast=0,\n"
        "            )\n"
        "            dpg.bind_item_theme(port_tag, t_input)\n"
        "            dpg.add_spacer(width=16)\n"
        "            dpg.add_text(\"IP → global\", color=C_TEXT_DIM)\n"
        "\n"
        "        dpg.add_spacer(height=8)\n"
        "        dpg.add_separator()\n"
        "        dpg.add_spacer(height=6)\n"
        "\n"
        "        # ── log label ─────────────────────────────────────────────────\n"
        "        with dpg.group(horizontal=True):\n"
        "            dpg.add_text(\"OUTPUT LOG\", color=C_TEXT_DIM)\n"
        "            dpg.add_spacer(width=8)\n"
        "            dpg.add_text(\"—\", color=C_BORDER_HI)\n"
        "            dpg.add_spacer(width=8)\n"
        "            cnt = dpg.add_text(\"0 lines\", color=C_TEXT_DIM)\n"
        "            _log_snapshots[k] = 0\n"
        "            # store count tag too\n"
        "            _status_tags[f\"{k}_cnt\"] = cnt\n"
        "\n"
        "        dpg.add_spacer(height=4)\n"
        "\n"
        "        # ── log area ─────────────────────────────────────────────────\n"
        "        log_tag = f\"log_{k}\"\n"
        "        dpg.add_input_text(\n"
        "            tag=log_tag, multiline=True, readonly=True,\n"
        "            default_value=\"\", width=-1, height=-52,\n"
        "            tab_input=False,\n"
        "        )\n"
        "        dpg.bind_item_theme(log_tag, t_log)\n"
        "        _log_tags[k] = log_tag\n"
        "\n"
        "        dpg.add_spacer(height=6)\n"
        "        dpg.add_separator()\n"
        "        dpg.add_spacer(height=6)\n"
        "\n"
        "        # ── footer buttons ────────────────────────────────────────────\n"
        "        def make_start(s=svc, pk=port_tag):\n"
        "            def _cb():\n"
        "                s.port = dpg.get_value(pk)\n"
        "                s.start(dpg.get_value(\"global_ip\"))\n"
        "            return _cb\n"
        "\n"
        "        def make_stop(s=svc):\n"
        "            def _cb(): s.stop()\n"
        "            return _cb\n"
        "\n"
        "        def make_clear(s=svc, lk=log_tag, ck=cnt):\n"
        "            def _cb():\n"
        "                s.logs.clear()\n"
        "                dpg.set_value(lk, \"\")\n"
        "                dpg.set_value(ck, \"0 lines\")\n"
        "            return _cb\n"
        "\n"
        "        with dpg.group(horizontal=True):\n"
        "            b1 = dpg.add_button(label=\"  ▶ START  \", callback=make_start(), height=28)\n"
        "            dpg.bind_item_theme(b1, t_start)\n"
        "            dpg.add_spacer(width=6)\n"
        "            b2 = dpg.add_button(label=\"  ■ STOP  \", callback=make_stop(), height=28)\n"
        "            dpg.bind_item_theme(b2, t_stop)\n"
        "            dpg.add_spacer(width=6)\n"
        "            b3 = dpg.add_button(label=\"CLEAR\", callback=make_clear(), height=28)\n"
        "            dpg.bind_item_theme(b3, t_clear)\n"
        "\n"
        "\n"
        "# ── Resize handler ────────────────────────────────────────────────────────────\n"
        "def _resize_layout():\n"
        "    vw = dpg.get_viewport_client_width()\n"
        "    vh = dpg.get_viewport_client_height()\n"
        "    dpg.set_item_width(\"main_win\",  vw)\n"
        "    dpg.set_item_height(\"main_win\", vh)\n"
        "\n"
        "    card_w = max(340, (vw - 60) // len(SERVICES))\n"
        "    # topbar ~28 + sep ~10 + ctrl_bar 52+sp 20 + statusbar ~30 + margins ~40\n"
        "    card_h = max(300, vh - 200)\n"
        "\n"
        "    for svc in SERVICES:\n"
        "        if dpg.does_item_exist(f\"card_{svc.key}\"):\n"
        "            dpg.set_item_width(f\"card_{svc.key}\",  card_w)\n"
        "            dpg.set_item_height(f\"card_{svc.key}\", card_h)\n"
        "\n"
        "\n"
        "# ── Render loop updates ───────────────────────────────────────────────────────\n"
        "_STATUS_COLOR = {\n"
        "    \"running\": C_GREEN,\n"
        "    \"error\":   C_RED,\n"
        "    \"stopped\": C_TEXT_SEC,\n"
        "}\n"
        "_STATUS_LABEL = {\n"
        "    \"running\": \"RUNNING\",\n"
        "    \"error\":   \"ERROR\",\n"
        "    \"stopped\": \"STOPPED\",\n"
        "}\n"
        "\n"
        "def _update_ui():\n"
        "    for svc in SERVICES:\n"
        "        k = svc.key\n"
        "        st = svc.status\n"
        "\n"
        "        # dot + status label\n"
        "        if dpg.does_item_exist(_dot_tags.get(k, \"\")):\n"
        "            col = _STATUS_COLOR.get(st, C_TEXT_SEC)\n"
        "            dpg.configure_item(_dot_tags[k],  color=col)\n"
        "            dpg.configure_item(_status_tags[k],\n"
        "                               default_value=_STATUS_LABEL.get(st, st.upper()),\n"
        "                               color=col)\n"
        "\n"
        "        # logs — only refresh when new lines arrived\n"
        "        with svc._lock:\n"
        "            n = len(svc.logs)\n"
        "        if n != _log_snapshots.get(k, -1):\n"
        "            _log_snapshots[k] = n\n"
        "            with svc._lock:\n"
        "                text = \"\\n\".join(svc.logs[-300:])\n"
        "            if dpg.does_item_exist(_log_tags.get(k, \"\")):\n"
        "                dpg.set_value(_log_tags[k], text)\n"
        "            cnt_tag = _status_tags.get(f\"{k}_cnt\")\n"
        "            if cnt_tag and dpg.does_item_exist(cnt_tag):\n"
        "                dpg.set_value(cnt_tag, f\"{n} lines\")\n"
        "\n"
        "\n"
        "# ── Entry point ───────────────────────────────────────────────────────────────\n"
        "def main():\n"
        "    dpg.create_context()\n"
        "    dpg.bind_theme(_make_global_theme())\n"
        "\n"
        "    build_ui()\n"
        "\n"
        "    dpg.create_viewport(\n"
        "        title=\"Oxsium Framework — Service Launcher\",\n"
        "        width=1140, height=720,\n"
        "        min_width=800, min_height=500,\n"
        "        clear_color=list(C_BG_DEEP),\n"
        "    )\n"
        "    dpg.setup_dearpygui()\n"
        "    dpg.show_viewport()\n"
        "    dpg.set_primary_window(\"main_win\", True)\n"
        "\n"
        "    _resize_layout()\n"
        "\n"
        "    while dpg.is_dearpygui_running():\n"
        "        _resize_layout()\n"
        "        _update_ui()\n"
        "        dpg.render_dearpygui_frame()\n"
        "\n"
        "    # clean shutdown\n"
        "    for svc in SERVICES:\n"
        "        svc.stop()\n"
        "    dpg.destroy_context()\n"
        "\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    main()\n"
        "\n"
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
    bullet(ansi::DIM() + "=>  Dear PyGui native desktop launcher — GPU-rendered window" + ansi::RST());
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