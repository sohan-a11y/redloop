from dataclasses import dataclass


@dataclass
class AxisBaseline:
    length: int
    status: int
    timing_mean: float
    noise: float


def axis_scores(probe, base: AxisBaseline) -> dict:
    len_d = abs(probe.len_delta)
    status_signal = 1 if probe.status != base.status else 0
    t_d = abs(probe.ms - base.timing_mean)
    return {
        "length": len_d / max(base.noise, 1.0),
        "status": status_signal,
        "timing": t_d / max(base.noise * 4, 1.0),
    }


def gate(p, ctrl_p, base: AxisBaseline, ctrl_base: AxisBaseline, axes_needed: int = 2) -> bool:
    pa = axis_scores(p, base)
    ca = axis_scores(ctrl_p, ctrl_base)
    strong = 0
    for k in ("length", "status", "timing"):
        if pa[k] > 1.5 and ca[k] <= pa[k] * 0.4:
            strong += 1
    return strong >= axes_needed


def budget_refund(spent_by_axis: dict, caps: dict) -> int:
    refund = 0
    for axis, spent in spent_by_axis.items():
        cap = caps.get(axis, 1 << 30)
        if spent < cap * 0.5:
            refund += 1
    return refund


def halt_check(spent_by_axis: dict, caps: dict) -> bool:
    for axis, spent in spent_by_axis.items():
        if spent >= caps.get(axis, 1 << 30):
            return True
    return False