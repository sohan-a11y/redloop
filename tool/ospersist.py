import shutil
import subprocess

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _task_name(engagement: str) -> str:
    return f"RECOIL-{engagement}"

def _run_key_name(engagement: str) -> str:
    return f"RECOIL-{engagement}"

def _shell(cmd: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", f"{type(exc).__name__}:{exc}"


def schtasks_available() -> bool:
    return shutil.which("schtasks") is not None


def create_task(engagement: str, quiet: bool = False) -> str:
    name = _task_name(engagement)
    cmd = [
        shutil.which("schtasks"),
        "/create", "/tn", name, "/tr", f"echo RECOIL-heartbeat-{engagement}",
        "/sc", "MINUTE", "/mo", "5", "/f",
    ]
    rc, out, err = _shell(cmd)
    return "ok" if rc == 0 else f"fail:{err}"


def task_liveness(engagement: str) -> bool:
    name = _task_name(engagement)
    rc, out, err = _shell([shutil.which("schtasks"), "/query", "/tn", name, "/fo", "LIST"])
    return rc == 0 and name.lower() in out.lower()


def delete_task(engagement: str) -> bool:
    name = _task_name(engagement)
    rc, out, err = _shell([shutil.which("schtasks"), "/delete", "/tn", name, "/f"])
    return rc == 0


def write_run_key(engagement: str) -> str:
    name = _run_key_name(engagement)
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, f"echo RECOIL-run-{engagement}")
        return "ok"
    except Exception as exc:
        return f"fail:{exc}"


def run_key_liveness(engagement: str) -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as k:
            winreg.QueryValueEx(k, _run_key_name(engagement))
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def delete_run_key(engagement: str) -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, _run_key_name(engagement))
        return True
    except Exception:
        return False


class Persister:
    def __init__(self, engagement: str, disarmed: bool = False, max_heal: int = 2, no_registry: bool = False) -> None:
        self.engagement = engagement
        self.disarmed = disarmed
        self.max_heal = max_heal
        self.no_registry = no_registry
        self.heal_count = 0

    def arm(self) -> dict:
        state = {"task": "off", "run_key": "off"}
        if self.disarmed:
            return state
        if schtasks_available():
            state["task"] = create_task(self.engagement)
        if not self.no_registry:
            state["run_key"] = write_run_key(self.engagement)
        return state

    def liveness(self) -> dict:
        task = schtasks_available() and task_liveness(self.engagement)
        run = None if self.no_registry else run_key_liveness(self.engagement)
        return {"task": task, "run_key": run}

    def heal(self) -> bool:
        if self.disarmed or self.heal_count >= self.max_heal:
            return False
        live = self.liveness()
        need_task = schtasks_available() and not live.get("task")
        need_run = (not self.no_registry) and not live.get("run_key")
        rearmed = 0
        if need_task:
            self.heal_count += 1
            create_task(self.engagement)
            rearmed += 1
        if need_run:
            self.heal_count += 1
            write_run_key(self.engagement)
            rearmed += 1
        return rearmed > 0

    def disarm(self) -> bool:
        self.disarmed = True
        return True

    def remove(self) -> dict:
        task = schtasks_available() and delete_task(self.engagement)
        if self.no_registry:
            run = True
        else:
            run = delete_run_key(self.engagement)
        return {"task": task, "run_key": run}