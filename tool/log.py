import inspect
import os



def set_debug():
    os.environ["EXP_DEBUG"] = "true"

def set_no_debug():
    os.environ["EXP_DEBUG"] = ""


def debug_log(msg: str, tag: str = "") -> None:
    if os.environ.get("EXP_DEBUG", "").lower() in ("1", "true", "yes"):
        caller_frame = inspect.stack()[1]
        caller_file = caller_frame.filename
        caller_func = caller_frame.function  # 自动获取调用者函数名
        module_name = os.path.splitext(os.path.basename(caller_file))[0]

        # tag 未传入时，自动用调用者函数名
        resolved_tag = tag if tag else caller_func

        log = f"[{module_name}][{resolved_tag}] {msg}"
        print(log)