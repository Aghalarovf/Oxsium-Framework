#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

static std::string quote(const fs::path& path) {
    return '"' + path.string() + '"';
}

static int run(const std::string& command) {
    return std::system(command.c_str());
}

static bool command_ok(const std::string& command) {
    return run(command + " >nul 2>&1") == 0;
}

static fs::path locate_root(const fs::path& start) {
    fs::path current = start;
    while (!current.empty()) {
        if (fs::exists(current / "Main" / "requirements.txt")) {
            return current;
        }
        fs::path parent = current.parent_path();
        if (parent == current) {
            break;
        }
        current = parent;
    }
    return start;
}

static bool python_exists() {
    return command_ok("python --version");
}

static bool py_launcher_exists() {
    return command_ok("py -3 --version");
}

static fs::path find_python_exe() {
    const char* localAppData = std::getenv("LOCALAPPDATA");
    const char* programFiles = std::getenv("ProgramFiles");
    const char* programFilesX86 = std::getenv("ProgramFiles(x86)");

    auto probe = [](const fs::path& candidate) {
        return fs::exists(candidate) ? candidate : fs::path();
    };

    if (localAppData) {
        fs::path base = fs::path(localAppData) / "Programs" / "Python";
        if (fs::exists(base)) {
            for (const auto& entry : fs::directory_iterator(base)) {
                fs::path candidate = entry.path() / "python.exe";
                if (fs::exists(candidate)) {
                    return candidate;
                }
            }
        }
    }

    auto scan_program_files = [&](const char* root_dir) -> fs::path {
        if (!root_dir) {
            return {};
        }
        fs::path base(root_dir);
        if (!fs::exists(base)) {
            return {};
        }
        for (const auto& entry : fs::directory_iterator(base)) {
            if (!entry.is_directory()) {
                continue;
            }
            fs::path candidate = entry.path() / "python.exe";
            if (fs::exists(candidate)) {
                return candidate;
            }
            if (entry.path().filename().string().find("Python") != std::string::npos) {
                for (const auto& sub : fs::recursive_directory_iterator(entry.path())) {
                    if (sub.is_regular_file() && sub.path().filename() == "python.exe") {
                        return sub.path();
                    }
                }
            }
        }
        return {};
    };

    fs::path found = scan_program_files(programFiles);
    if (!found.empty()) {
        return found;
    }

    found = scan_program_files(programFilesX86);
    if (!found.empty()) {
        return found;
    }

    if (python_exists()) {
        return fs::path("python");
    }

    if (py_launcher_exists()) {
        return fs::path("py -3");
    }

    return {};
}

static bool install_python() {
    std::cout << "Python tapilmadi. Indi yüklənsin? [Y/N]: ";
    std::string answer;
    std::getline(std::cin, answer);

    for (auto& ch : answer) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (answer != "y" && answer != "yes") {
        std::cout << "Quraşdırma uğursuz oldu: Python olmadığı üçün proses dayandırıldı.\n";
        return false;
    }

    if (!command_ok("winget --version")) {
        std::cout << "winget tapılmadı. Python-u manual yükləmək lazımdır.\n";
        return false;
    }

    std::cout << "Python yüklənir...\n";
    int code = run("winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements");
    if (code != 0) {
        std::cout << "Python quraşdırıla bilmədi.\n";
        return false;
    }

    return true;
}

static bool ensure_python() {
    if (python_exists() || py_launcher_exists()) {
        return true;
    }

    if (!install_python()) {
        return false;
    }

    return python_exists() || py_launcher_exists() || !find_python_exe().empty();
}

static fs::path venv_python(const fs::path& root) {
#ifdef _WIN32
    return root / "oxsium" / "Scripts" / "python.exe";
#else
    return root / "oxsium" / "bin" / "python";
#endif
}

static std::string python_command(const fs::path& root) {
    fs::path candidate = venv_python(root);
    if (fs::exists(candidate)) {
        return quote(candidate);
    }

    fs::path installed = find_python_exe();
    if (!installed.empty()) {
        if (installed == fs::path("python") || installed == fs::path("py -3")) {
            return installed.string();
        }
        return quote(installed);
    }

    if (python_exists()) {
        return "python";
    }

    if (py_launcher_exists()) {
        return "py -3";
    }

    return {};
}

static bool create_virtual_environment(const fs::path& root) {
    fs::path venv_dir = root / "oxsium";
    if (fs::exists(venv_python(root))) {
        return true;
    }

    std::string interpreter = python_command(root);
    if (interpreter.empty()) {
        return false;
    }

    return run(interpreter + " -m venv " + quote(venv_dir)) == 0;
}

static bool install_requirements(const fs::path& root) {
    std::string interpreter = python_command(root);
    if (interpreter.empty()) {
        return false;
    }

    fs::path requirements = root / "Main" / "requirements.txt";
    fs::path venv_dir = root / "oxsium";
    if (!fs::exists(requirements)) {
        std::cout << "requirements.txt tapılmadı: " << requirements.string() << "\n";
        return false;
    }

    std::string venv_interpreter = quote(venv_python(root));
    if (!fs::exists(venv_python(root))) {
        venv_interpreter = interpreter;
    }

    int upgrade_code = run(venv_interpreter + " -m pip install --upgrade pip setuptools wheel");
    if (upgrade_code != 0) {
        return false;
    }

    return run(venv_interpreter + " -m pip install -r " + quote(requirements)) == 0;
}

static bool write_file(const fs::path& file_path, const std::string& content) {
    std::ofstream stream(file_path, std::ios::binary);
    if (!stream) {
        return false;
    }
    stream << content;
    return static_cast<bool>(stream);
}

static std::string launcher_template(const std::string& target_relative, bool is_decision) {
    std::string args = is_decision ? "[\"server\"]" : "[]";
    return
        "from __future__ import annotations\n\n"
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n\n\n"
        "ROOT = Path(__file__).resolve().parent\n"
        "VENV_PYTHON = ROOT / \"oxsium\" / (\"Scripts\" if os.name == \"nt\" else \"bin\") / (\"python.exe\" if os.name == \"nt\" else \"python\")\n"
        "PYTHON = VENV_PYTHON if VENV_PYTHON.exists() else Path(sys.executable)\n"
        "TARGET = ROOT / \"" + target_relative + "\"\n\n\n"
        "def main() -> int:\n"
        "    if not TARGET.exists():\n"
        "        print(f\"Target file not found: {TARGET}\")\n"
        "        return 1\n"
        "    return subprocess.call([str(PYTHON), str(TARGET)] + " + args + ", cwd=str(ROOT))\n\n\n"
        "if __name__ == \"__main__\":\n"
        "    raise SystemExit(main())\n";
}

static bool create_launchers(const fs::path& root) {
    const std::string connect_target = "Main/connect/connection.py";
    const std::string decision_target = "Main/Decision Engine/Helpers/root_principal.py";

    if (!write_file(root / "setup_connect.py", launcher_template(connect_target, false))) {
        return false;
    }

    if (!write_file(root / "setup_decision.py", launcher_template(decision_target, true))) {
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    const fs::path exe_path = argc > 0 ? fs::absolute(argv[0]) : fs::current_path();
    const fs::path root = locate_root(exe_path.parent_path());

    if (!ensure_python()) {
        return 1;
    }

    if (!create_virtual_environment(root)) {
        std::cout << "Virtual environment yaradıla bilmədi.\n";
        return 1;
    }

    if (!install_requirements(root)) {
        std::cout << "Lazımi kitabxanalar yüklənə bilmədi.\n";
        return 1;
    }

    if (!create_launchers(root)) {
        std::cout << "setup_connect.py və ya setup_decision.py yaradılmadı.\n";
        return 1;
    }

    std::cout << "Quraşdırma tamamlandı.\n";
    std::cout << "Virtual environment: " << (root / "oxsium").string() << "\n";
    std::cout << "setup_connect.py yaradıldı.\n";
    std::cout << "setup_decision.py yaradıldı.\n";
    return 0;
}