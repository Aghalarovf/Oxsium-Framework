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
    std::cout << "    " << ansi::CYAN()   << "python setup_connect.py"
              << ansi::RST() << ansi::DIM() << "   =>  start the connection layer\n" << ansi::RST();
    std::cout << "    " << ansi::CYAN()   << "python setup_decision.py"
              << ansi::RST() << ansi::DIM() << "  =>  start the Flask decision server\n" << ansi::RST();
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
        rc = run_direct(interp_path, "-m venv "" + venv_dir.string() + """);
    } else {
        /* Fallback: interpreter is just "python" or "py -3" — use system() */
        const std::string cmd = interp + " -m venv "" + venv_dir.string() + """;
        bullet(ansi::DIM() + cmd + ansi::RST());
        rc = run(cmd);
    }
#else
    const std::string cmd = interp + " -m venv "" + venv_dir.string() + """;
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
    std::string interp = quote(venv_python(root));
    if (!fs::exists(venv_python(root))) interp = python_command(root);
    if (interp.empty()) return false;

    info("Upgrading pip, setuptools and wheel ...");
    std::cout << "\n";
    if (run(interp + " -m pip install --upgrade pip setuptools wheel") != 0) {
        std::cout << "\n";
        err("Failed to upgrade pip.");
        return false;
    }
    std::cout << "\n";
    info("Installing packages from requirements.txt ...");
    std::cout << "\n";
    if (run(interp + " -m pip install -r " + quote(req)) != 0) {
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

static std::string launcher_template(const std::string& target_relative,
                                     const std::string& extra_args) {
    return
        "from __future__ import annotations\n\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n\n\n"
        "ROOT = Path(__file__).resolve().parent\n"
        "VENV_PYTHON = (\n"
        "    ROOT / \"oxsium\"\n"
        "    / (\"Scripts\" if os.name == \"nt\" else \"bin\")\n"
        "    / (\"python.exe\" if os.name == \"nt\" else \"python\")\n"
        ")\n"
        "PYTHON = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)\n"
        "TARGET = ROOT / \"" + target_relative + "\"\n\n\n"
        "def main() -> int:\n"
        "    if not TARGET.exists():\n"
        "        print(f\"Target not found: {TARGET}\")\n"
        "        return 1\n"
        "    return subprocess.call([str(PYTHON), str(TARGET)] + " + extra_args + ", cwd=str(ROOT))\n\n\n"
        "if __name__ == \"__main__\":\n"
        "    raise SystemExit(main())\n";
}

static bool create_launchers(const fs::path& root) {
    bool ok1 = write_file(
        root / "setup_connect.py",
        launcher_template("Main/connect/connection.py", "[]")
    );
    bool ok2 = write_file(
        root / "setup_decision.py",
        launcher_template("Main/Decision Engine/Helpers/root_principal.py", "[\"server\"]")
    );
    if (!ok1 || !ok2) {
        err("Failed to write launcher scripts.");
        return false;
    }
    ok("setup_connect.py  created");
    bullet(ansi::DIM() + "=>  Main/connect/connection.py" + ansi::RST());
    ok("setup_decision.py created");
    bullet(ansi::DIM() + "=>  Main/Decision Engine/Helpers/root_principal.py  (Flask server)" + ansi::RST());
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
   Entry point
   ══════════════════════════════════════════════════════════════════════════ */

int main() {
    ansi::init();
    print_banner();

    /* Use current_path() as the reliable root — argv[0] can be a bare name
       like "setup.exe" with no directory component when launched from the
       same folder, which makes fs::absolute resolve relative to CWD anyway;
       using current_path() directly avoids the ambiguity and any 8.3 short-
       path issue on older Windows builds. */
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