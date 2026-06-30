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
              << ansi::RST() << ansi::DIM() << "   =>  start all services (connection + decision + web)\n" << ansi::RST();
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
static bool command_ok(const std::string& cmd) {
#ifdef _WIN32
    return run(cmd + " >nul 2>&1") == 0;
#else
    return run(cmd + " >/dev/null 2>&1") == 0;
#endif
}

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

static bool python_exists()      { return command_ok("python3 --version") || command_ok("python --version"); }
static bool py_launcher_exists() {
#ifdef _WIN32
    return command_ok("py -3 --version");
#else
    return false;
#endif
}

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
#ifdef _WIN32
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
#else
    /* On Linux/macOS prefer python3, fall back to python */
    if (command_ok("python3 --version")) return fs::path("python3");
    if (command_ok("python --version"))  return fs::path("python");
    return {};
#endif
}

/* ── Python installer ─────────────────────────────────────────────────── */

/*
 * Method 1 — apt (Debian/Ubuntu)
 */
static bool install_via_apt() {
    if (!command_ok("apt-get --version")) return false;
    info("Installing Python 3 via " + ansi::CYAN() + "apt-get" + ansi::RST() + " ...");
    std::cout << "\n";
    int rc = run("sudo apt-get install -y python3 python3-pip python3-venv");
    std::cout << "\n";
    if (rc != 0) {
        warn("apt-get install failed (exit code " + std::to_string(rc) + "). Trying fallback ...");
        return false;
    }
    ok("Python 3 installed via apt-get.");
    return true;
}

/*
 * Method 2 — dnf (Fedora/RHEL/Rocky)
 */
static bool install_via_dnf() {
    if (!command_ok("dnf --version")) return false;
    info("Installing Python 3 via " + ansi::CYAN() + "dnf" + ansi::RST() + " ...");
    std::cout << "\n";
    int rc = run("sudo dnf install -y python3 python3-pip");
    std::cout << "\n";
    if (rc != 0) {
        warn("dnf install failed (exit code " + std::to_string(rc) + "). Trying fallback ...");
        return false;
    }
    ok("Python 3 installed via dnf.");
    return true;
}

/*
 * Method 3 — brew (macOS / Linuxbrew)
 */
static bool install_via_brew() {
    if (!command_ok("brew --version")) return false;
    info("Installing Python 3 via " + ansi::CYAN() + "brew" + ansi::RST() + " ...");
    std::cout << "\n";
    int rc = run("brew install python3");
    std::cout << "\n";
    if (rc != 0) {
        warn("brew install failed (exit code " + std::to_string(rc) + ").");
        return false;
    }
    ok("Python 3 installed via brew.");
    return true;
}

static bool install_python() {
    warn("Python was not found on this system.");
    std::cout << "\n  " << ansi::BOLD()
              << "Would you like to install Python 3 automatically? "
              << ansi::CYAN() << "[Y/N]" << ansi::RST() << ": ";

    std::string answer;
    std::getline(std::cin, answer);

    while (!answer.empty() && std::isspace((unsigned char)answer.front())) answer.erase(answer.begin());
    while (!answer.empty() && std::isspace((unsigned char)answer.back()))  answer.pop_back();
    for (auto& ch : answer) ch = static_cast<char>(std::tolower((unsigned char)ch));

    if (answer != "y" && answer != "yes") {
        std::cout << "\n";
        err("Setup aborted — Python is required to continue.");
        bullet("Install manually: " + ansi::CYAN() + "sudo apt-get install python3 python3-venv python3-pip" + ansi::RST());
        std::cout << "\n";
        return false;
    }

    /* Try each method in order — stop at the first success */
    if (install_via_apt()) return true;
    if (install_via_dnf()) return true;
    if (install_via_brew()) return true;

    /* All methods failed */
    err("All automatic installation methods failed.");
    bullet("Please install manually: " + ansi::CYAN() + "sudo apt-get install python3 python3-venv python3-pip" + ansi::RST());
    std::cout << "\n";
    return false;
}

static bool ensure_python() {
    if (python_exists() || py_launcher_exists()) {
        ok("Python detected on this system.");
        return true;
    }
    if (!install_python()) return false;

    bool found = python_exists() || !find_python_exe().empty();
    if (!found) {
        warn("Python installed but not yet visible in PATH.");
        bullet("Open a new terminal window and re-run setup.");
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
        if (inst == fs::path("python3") || inst == fs::path("python") || inst == fs::path("py -3"))
            return inst.string();
        return quote(inst);
    }
#ifdef _WIN32
    if (python_exists())      return "python";
    if (py_launcher_exists()) return "py -3";
#else
    if (command_ok("python3 --version")) return "python3";
    if (python_exists())                 return "python";
#endif
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

    /* 2 ── path contains problematic characters ──────────────────── */
    {
        const std::string p = venv_dir.string();

#ifdef _WIN32
        bool trailing_bs   = (!p.empty() && p.back() == '\\');
        bool bad_chars     = (p.find('(')  != std::string::npos ||
                              p.find(')')  != std::string::npos ||
                              p.find('!')  != std::string::npos ||
                              p.find('^')  != std::string::npos ||
                              p.find('&')  != std::string::npos ||
                              p.find('%')  != std::string::npos);
        bool embedded_quote = (p.find('"') != std::string::npos);

        if (trailing_bs || bad_chars || embedded_quote) {
            err("Destination path contains characters that break cmd.exe quoting:");
            if (trailing_bs)    bullet("Trailing backslash before closing quote  →  \\\"");
            if (bad_chars)      bullet("Shell-special character  ( ) ! ^ & %  in path");
            if (embedded_quote) bullet("Embedded double-quote in path name");
            bullet("Path : " + ansi::PATH_CLR() + p + ansi::RST());
            bullet("Fix  : move the project to a path without these characters.");
        } else {
            ok("Destination path looks safe.");
        }
        if (p.find(' ') != std::string::npos) {
            warn("Destination path contains spaces — this can cause issues.");
        }
#else
        bool embedded_quote = (p.find('"') != std::string::npos);
        if (embedded_quote) {
            err("Destination path contains a double-quote character — this will break shell quoting.");
            bullet("Path : " + ansi::PATH_CLR() + p + ansi::RST());
        } else {
            ok("Destination path looks safe.");
        }
#endif
    }

    /* 3 ── target directory already exists but is broken ─────────── */
    if (fs::exists(venv_dir)) {
        bool has_pyvenv_cfg = fs::exists(venv_dir / "pyvenv.cfg");
        if (!has_pyvenv_cfg) {
            warn("Directory already exists but has no pyvenv.cfg — it may be");
            bullet("a leftover from a previous failed attempt.");
#ifdef _WIN32
            bullet("Delete it and re-run:  rmdir /s /q \"" + venv_dir.string() + "\"");
#else
            bullet("Delete it and re-run:  rm -rf \"" + venv_dir.string() + "\"");
#endif
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
        bullet("Uncommon code — run the command manually in a terminal to see");
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
        && interp_path != fs::path("python3")
        && interp_path != fs::path("python")
        && interp_path != fs::path("py -3")) {
        interp = quote(interp_path);        // full path, always works
    } else if (!interp_path.empty()) {
        interp = interp_path.string();      // "python3" / "python" / "py -3"
    } else if (py_launcher_exists()) {
        interp = "py -3";
        interp_path = fs::path("py -3");
    } else if (python_exists()) {
#ifdef _WIN32
        interp = "python";
        interp_path = fs::path("python");
#else
        interp = "python3";
        interp_path = fs::path("python3");
#endif
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
        if (interp_path.empty()) {
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
        /* If interp_path is a bare name (python3/python), use it directly */
        std::string interp_str = interp_path.string();
        bool is_bare = (interp_str == "python3" || interp_str == "python");
        std::string cmd = (is_bare ? interp_str : ("\"" + interp_str + "\"")) + " " + args;
        return run(cmd);
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

static bool ensure_graph_engine_executable(const fs::path& root) {
#ifdef _WIN32
    (void)root;
    return true;
#else
    const fs::path graph_engine = root / "Main" / "Decision Engine" / "Engine" / "graph_engine";
    if (!fs::exists(graph_engine)) {
        warn("Decision Engine graph_engine not found: " + graph_engine.string());
        return false;
    }

    std::error_code ec;
    fs::permissions(
        graph_engine,
        fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
        fs::perm_options::add,
        ec
    );

    if (ec) {
        warn("Failed to set executable permission on graph_engine: " + ec.message());
        return false;
    }

    ok("graph_engine marked as executable.");
    bullet(ansi::PATH_CLR() + graph_engine.string() + ansi::RST());
    return true;
#endif
}

static std::string start_py_template() {
    return
        "from __future__ import annotations\n"
        "\n"
        "import sys\n"
        "\n"
        "from PyQt6.QtGui     import QColor, QPalette\n"
        "from PyQt6.QtWidgets import QApplication\n"
        "\n"
        "from core.config    import C, QSS\n"
        "from ui.main_window import MainWin\n"
        "\n"
        "\n"
        "def main() -> None:\n"
        "    app = QApplication(sys.argv)\n"
        "    app.setApplicationName(\"Oxsium Framework\")\n"
        "    app.setStyleSheet(QSS)\n"
        "\n"
        "    pal = QPalette()\n"
        "    pal.setColor(QPalette.ColorRole.Window,          QColor(C.BASE))\n"
        "    pal.setColor(QPalette.ColorRole.WindowText,      QColor(C.T0))\n"
        "    pal.setColor(QPalette.ColorRole.Base,            QColor(C.SURF0))\n"
        "    pal.setColor(QPalette.ColorRole.AlternateBase,   QColor(C.SURF1))\n"
        "    pal.setColor(QPalette.ColorRole.Text,            QColor(C.T0))\n"
        "    pal.setColor(QPalette.ColorRole.Button,          QColor(C.SURF1))\n"
        "    pal.setColor(QPalette.ColorRole.ButtonText,      QColor(C.T0))\n"
        "    pal.setColor(QPalette.ColorRole.Highlight,       QColor(C.BLUE_B))\n"
        "    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(C.T0))\n"
        "    app.setPalette(pal)\n"
        "\n"
        "    w = MainWin()\n"
        "    w.show()\n"
        "    sys.exit(app.exec())\n"
        "\n"
        "\n"
        "if __name__ == \"__main__\":\n"
        "    main()";
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
    bullet(ansi::DIM() + "=>  Unified launcher for connection & decision services" + ansi::RST());
    return true;
}


int main() {
    ansi::init();
    print_banner();

    const fs::path exe_path = fs::current_path() / "setup";

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

    step_header(5, "Decision Engine Permissions");
    ensure_graph_engine_executable(root);

    print_success(root);
    return 0;
}