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
                 "--accept-package-agreements --accept-source-agreements");
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
 *   PrependPath=1  — adds python.exe to PATH automatically
 *   InstallAllUsers=0 — per-user install (no admin needed)
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
        "  -ArgumentList '/quiet','InstallAllUsers=0','PrependPath=1','Include_test=0' "
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
                 "/quiet InstallAllUsers=0 PrependPath=1 Include_test=0");
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
    } else if (python_exists()) {
        interp = "python";
    } else {
        err("No Python interpreter found \u2014 cannot create virtual environment.");
        return false;
    }

    /* Quote the venv destination so spaces in the project root are safe. */
    const fs::path   venv_dir    = root / "oxsium";
    const std::string venv_quoted = quote(venv_dir);

    info("Creating virtual environment " + ansi::CYAN() + "oxsium" + ansi::RST() + " ...");
    bullet(ansi::DIM() + interp + " -m venv " + venv_quoted + ansi::RST());

    /* system() already goes through the Windows shell; avoid adding an
       extra cmd /c layer because it can break quoted executable paths.   */
    const std::string cmd = interp + " -m venv " + venv_quoted;
    if (run(cmd) != 0) {
        err("Failed to create virtual environment.");
        bullet("Command was: " + cmd);
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