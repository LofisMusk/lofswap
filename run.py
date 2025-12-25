import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
from tkinter import Tk, Text, Entry, StringVar, Button, END, DISABLED, NORMAL, filedialog, messagebox


class InstallerGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("Lofswap Installer")
        self.root.geometry("640x360")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=0)
        self.root.grid_rowconfigure(2, weight=1)

        self.output_var = StringVar()

        self.output_entry = Entry(self.root, textvariable=self.output_var, width=60)
        self.output_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        browse_btn = Button(self.root, text="Browse...", command=self.choose_output_dir)
        browse_btn.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        install_btn = Button(self.root, text="Build and Install", command=self.start_install)
        install_btn.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.log_box = Text(self.root, height=15, width=80, state=DISABLED)
        self.log_box.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def choose_output_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.output_var.set(directory)

    def log(self, message):
        self.log_box.config(state=NORMAL)
        self.log_box.insert(END, f"{message}\n")
        self.log_box.see(END)
        self.log_box.config(state=DISABLED)

    def start_install(self):
        output_dir = self.output_var.get().strip()
        if not output_dir:
            messagebox.showerror("Missing output directory", "Please select an output directory.")
            return

        thread = threading.Thread(target=self.install_flow, args=(Path(output_dir),), daemon=True)
        thread.start()

    def install_flow(self, output_dir: Path):
        try:
            self.log(f"Output directory: {output_dir}")
            ensure_dir(output_dir)

            if not is_rust_installed():
                self.log("Rust not found. Installing latest toolchain...")
                install_rust()
                if not is_rust_installed():
                    raise RuntimeError("Rust installation failed or cargo not found on PATH.")
                self.log("Rust installed successfully.")

            add_cargo_bin_to_path()
            self.log("Building workspace...")
            executables = build_and_collect_executables(output_dir, logger=self.log)

            if not executables:
                raise RuntimeError("No executables were produced by the build.")

            self.log("Build complete. Executables:")
            for exe in executables:
                self.log(f" - {exe}")
            messagebox.showinfo("Success", "Build and installation completed.")
        except Exception as exc:
            self.log(f"Error: {exc}")
            messagebox.showerror("Installer error", str(exc))


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def is_rust_installed():
    try:
        subprocess.run(["rustc", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["cargo", "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def add_cargo_bin_to_path():
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.exists():
        os.environ["PATH"] = f"{cargo_bin}{os.pathsep}{os.environ.get('PATH', '')}"


def install_rust():
    system = platform.system().lower()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        if system == "windows":
            installer = tmp_path / "rustup-init.exe"
            url = "https://win.rustup.rs/x86_64"
            urllib.request.urlretrieve(url, installer)
            subprocess.run([str(installer), "-y"], check=True)
        else:
            installer = tmp_path / "rustup-init.sh"
            url = "https://sh.rustup.rs"
            urllib.request.urlretrieve(url, installer)
            installer.chmod(installer.stat().st_mode | stat.S_IEXEC)
            subprocess.run([str(installer), "-y"], check=True)


def log_stream(text: str, logger):
    if not text:
        return
    for line in text.splitlines():
        logger(line)


def build_and_collect_executables(output_dir: Path, logger=print):
    executables = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        target_dir = tmp_path / "target"
        artifact_dir = tmp_path / "artifacts"

        build_command = [
            "cargo",
            "build",
            "-r",
            "--workspace",
            "--target-dir",
            str(target_dir),
        ]

        result = subprocess.run(
            build_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        log_stream(result.stdout, logger)
        if result.returncode != 0:
            log_stream(result.stderr, logger)
            raise RuntimeError(f"cargo build failed with exit code {result.returncode}")

        release_dirs = [
            target_dir / "release",
            artifact_dir,
        ]

        ensure_dir(output_dir)
        for folder in release_dirs:
            if not folder.exists():
                continue
            for item in folder.iterdir():
                if item.is_file() and is_executable_file(item):
                    destination = output_dir / item.name
                    shutil.copy2(item, destination)
                    executables.append(destination)
        return executables


def is_executable_file(path: Path):
    if path.suffix.lower() == ".exe":
        return True
    return os.access(path, os.X_OK) and not path.suffix


def main():
    gui = InstallerGUI()
    gui.root.mainloop()


if __name__ == "__main__":
    main()
