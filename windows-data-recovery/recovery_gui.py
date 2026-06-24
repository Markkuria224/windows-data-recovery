import contextlib
import io
import queue
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from recovery_mvp import scan_source, select_signatures


class GuiTextWriter(io.TextIOBase):
    def __init__(self, output_queue: queue.Queue[str]) -> None:
        self.output_queue = output_queue

    def write(self, text: str) -> int:
        if text:
            self.output_queue.put(text)
        return len(text)

    def flush(self) -> None:
        return None


class RecoveryGui(tk.Tk):
    FILE_TYPES = ["jpeg", "png", "pdf", "gif", "zip-office"]

    def __init__(self) -> None:
        super().__init__()
        self.title("Windows Data Recovery MVP")
        self.geometry("820x620")
        self.resizable(True, True)

        self.output_queue: queue.Queue[str] = queue.Queue()
        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.max_file_mb_var = tk.StringVar(value="256")
        self.max_candidates_var = tk.StringVar(value="0")
        self.min_bytes_var = tk.StringVar(value="0")
        self.all_types_var = tk.BooleanVar(value=True)
        self.type_vars = {name: tk.BooleanVar(value=True) for name in self.FILE_TYPES}

        self._build_ui()
        self._poll_queue()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Source path:").grid(row=0, column=0, sticky="w")
        source_entry = ttk.Entry(frame, textvariable=self.source_var, width=70)
        source_entry.grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Button(frame, text="Browse...", command=self._browse_source).grid(row=0, column=2, padx=4)

        ttk.Label(frame, text="Output folder:").grid(row=1, column=0, sticky="w")
        output_entry = ttk.Entry(frame, textvariable=self.output_var, width=70)
        output_entry.grid(row=1, column=1, sticky="ew", pady=2)
        ttk.Button(frame, text="Browse...", command=self._browse_output).grid(row=1, column=2, padx=4)

        type_frame = ttk.LabelFrame(frame, text="File types")
        type_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=8)

        ttk.Checkbutton(
            type_frame,
            text="All types",
            variable=self.all_types_var,
            command=self._on_all_types_changed,
        ).grid(row=0, column=0, sticky="w", padx=4, pady=2)

        self.type_checkbuttons = {}
        for index, name in enumerate(self.FILE_TYPES, start=1):
            row = (index - 1) // 3 + 1
            col = (index - 1) % 3
            cb = ttk.Checkbutton(
                type_frame,
                text=name,
                variable=self.type_vars[name],
                command=self._on_type_checkbox_changed,
            )
            cb.grid(row=row, column=col, sticky="w", padx=4, pady=2)
            self.type_checkbuttons[name] = cb

        options_frame = ttk.Frame(frame)
        options_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=8)

        ttk.Label(options_frame, text="Max file size (MB):").grid(row=0, column=0, sticky="w")
        ttk.Entry(options_frame, textvariable=self.max_file_mb_var, width=10).grid(row=0, column=1, padx=4)

        ttk.Label(options_frame, text="Max candidates:").grid(row=0, column=2, sticky="w")
        ttk.Entry(options_frame, textvariable=self.max_candidates_var, width=10).grid(row=0, column=3, padx=4)

        ttk.Label(options_frame, text="Min bytes:").grid(row=0, column=4, sticky="w")
        ttk.Entry(options_frame, textvariable=self.min_bytes_var, width=10).grid(row=0, column=5, padx=4)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=4)

        self.start_button = ttk.Button(button_frame, text="Start Scan", command=self._start_scan)
        self.start_button.grid(row=0, column=0, sticky="w")
        ttk.Button(button_frame, text="Clear Log", command=self._clear_log).grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(frame, text="Live scan output:").grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))
        log_frame = ttk.Frame(frame)
        log_frame.grid(row=6, column=0, columnspan=3, sticky="nsew")
        frame.rowconfigure(6, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap="word", state="disabled", height=18)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        note = r"Note: scanning live devices such as \\.\E: requires Administrator privileges."
        ttk.Label(frame, text=note, foreground="gray").grid(row=7, column=0, columnspan=3, sticky="w", pady=(6, 0))

    def _browse_source(self) -> None:
        path = filedialog.askopenfilename(title="Select source file or disk image", filetypes=[("All files", "*")])
        if path:
            self.source_var.set(path)

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(title="Select output folder")
        if path:
            self.output_var.set(path)

    def _on_all_types_changed(self) -> None:
        if self.all_types_var.get():
            for var in self.type_vars.values():
                var.set(True)
        self._update_type_checkstates()

    def _on_type_checkbox_changed(self) -> None:
        if all(var.get() for var in self.type_vars.values()):
            self.all_types_var.set(True)
        else:
            self.all_types_var.set(False)
        self._update_type_checkstates()

    def _update_type_checkstates(self) -> None:
        state = "disabled" if self.all_types_var.get() else "normal"
        for name in self.FILE_TYPES:
            cb = self.type_checkbuttons.get(name)
            if cb is not None:
                cb.configure(state=state)

    def _start_scan(self) -> None:
        source = self.source_var.get().strip()
        output = self.output_var.get().strip()
        if not source:
            self._append_log("Error: source path is required.\n")
            return
        if not output:
            self._append_log("Error: output folder is required.\n")
            return

        try:
            max_file_mb = int(self.max_file_mb_var.get())
            max_candidates = int(self.max_candidates_var.get())
            min_bytes = int(self.min_bytes_var.get())
        except ValueError:
            self._append_log("Error: numeric values must be valid integers.\n")
            return

        if max_file_mb < 1:
            self._append_log("Error: max file size must be at least 1 MB.\n")
            return
        if max_candidates < 0 or min_bytes < 0:
            self._append_log("Error: max candidates and min bytes cannot be negative.\n")
            return

        selected_types = self._selected_types()
        if not selected_types:
            self._append_log("Error: select at least one file type or All types.\n")
            return

        self._append_log("Starting scan...\n")
        self._set_controls_state("disabled")
        threading.Thread(
            target=self._run_scan,
            args=(source, output, max_file_mb, max_candidates, selected_types, min_bytes),
            daemon=True,
        ).start()

    def _selected_types(self) -> list[str]:
        if self.all_types_var.get():
            return ["all"]
        return [name for name, var in self.type_vars.items() if var.get()]

    def _run_scan(self, source: str, output: str, max_file_mb: int, max_candidates: int, file_types: list[str], min_bytes: int) -> None:
        try:
            signatures = select_signatures(",".join(file_types))
            if not signatures:
                raise ValueError("No valid file types selected.")

            writer = GuiTextWriter(self.output_queue)
            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                result = scan_source(source, Path(output), max_file_mb * 1024 * 1024, max_candidates, signatures, min_bytes)
            self.output_queue.put(f"Scan finished with exit code {result}.\n")
        except Exception as exc:
            self.output_queue.put(f"Error: {exc}\n")
            self.output_queue.put(traceback.format_exc())
        finally:
            self.output_queue.put("__scan_complete__")

    def _poll_queue(self) -> None:
        while True:
            try:
                message = self.output_queue.get_nowait()
            except queue.Empty:
                break
            if message == "__scan_complete__":
                self._set_controls_state("normal")
                continue
            self._append_log(message)
        self.after(100, self._poll_queue)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _set_controls_state(self, state: str) -> None:
        for widget in (self.start_button,):
            widget.configure(state=state)
        if state == "normal":
            self._update_type_checkstates()
        else:
            for name in self.FILE_TYPES:
                cb = self.type_checkbuttons.get(name)
                if cb is not None:
                    cb.configure(state="disabled")


def main() -> None:
    app = RecoveryGui()
    app.mainloop()


if __name__ == "__main__":
    main()
